"""`janus map`: the second face (docs/design.md §6a; the contract the Map page and the alert file read is
docs/plans/2026-11-09-map-page.md §3). One run asks `tailscale status --json` which devices exist and which are online,
probes every door doors.json lists on the online ones (a TCP connect; a GET of a serve door's health path; a Taildrop
door is open while its device is online) and writes only what changed: map.json, one doors-log line per change, and
the alert file while a door that should be open is closed. A door is called closed only after two failed probes in a
row; the count for the first one lives in run.json in the runtime directory (memory, not disk). Tailnet addresses are
read fresh from Tailscale on every run and are never written anywhere."""
import contextlib
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from janus import config, identity, log, seen, version

TIMEOUT = 2                  # seconds for one probe (design §6a)
GRACE = 0.5                  # a probe still running this long after TIMEOUT is counted as timed out
STATUS_TIMEOUT = 10          # seconds for `tailscale status --json`
ALERTS = "~/.local/state/argus-ui/alerts"     # or $ARGUS_ALERTS (argus-ui docs/alerts.md)
JOB = "janus-map"            # the task the alert belongs to: the unit's name without ".service"
WAITING = "; waiting for a second probe"
NOT_PROBED = {"asleep": "device asleep, not probed", "absent": "device not on the tailnet, not probed"}
ROOM_SAYS = {"online": "Tailscale says online", "asleep": "Tailscale says offline", "absent": "not in tailscale status"}
WORDS = {"open": "open", "closed": "closed", "asleep": "asleep", "unknown": "not probed yet", "online": "online",
         "absent": "not on the tailnet"}
COUNTS = ("open", "closed", "unexpected", "asleep", "unknown")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
STAMP = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:\d\d)$")


class Failed(Exception):
    """The run could not be made (Tailscale down, doors.json broken, nowhere to write): exit 2. When it is raised
    before the probes, nothing was written and the previous map stays."""


class Broken(Failed):
    """map.json is there but is not a version 1 map."""


def map_path(env=None):
    return seen.state_dir(env) / "map.json"


def run_path(env=None):
    """run.json: $XDG_RUNTIME_DIR/janus/ (memory), or beside map.json where there is no runtime directory."""
    runtime = (env if env is not None else os.environ).get("XDG_RUNTIME_DIR")
    return (Path(runtime) / "janus" if runtime else seen.state_dir(env)) / "run.json"


def alert_path(env=None):
    return Path(os.path.expanduser((env if env is not None else os.environ).get("ARGUS_ALERTS") or ALERTS)) / "janus.json"


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def write_json(path, doc):
    """Atomically: a .tmp file beside it, then a rename, so a reader never sees half a file (argus-ui docs/alerts.md)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_map(env=None):
    """The map as last written, or None when there is none yet. Raises Broken for a file that is not a map."""
    path = map_path(env)
    if not path.exists():
        return None
    doc = read_json(path)
    ok = (isinstance(doc, dict) and doc.get("version") == 1 and isinstance(doc.get("rooms"), list)
          and all(isinstance(r, dict) and isinstance(r.get("doors"), list) and all(isinstance(d, dict) for d in r["doors"])
                  for r in doc["rooms"]))
    if not ok:
        raise Broken("%s is not a version 1 map" % config.short(path))
    return doc


@contextlib.contextmanager
def locked(env=None):
    """One run at a time: the timer, Probe now and a run by hand all read and rewrite map.json. An flock on a file
    beside run.json, held for the run. Where there is no flock (not Linux), runs are not serialised."""
    try:
        import fcntl
    except ImportError:
        yield
        return
    path = run_path(env).with_name("map.lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def when(stamp):
    """Tailscale's LastSeen as local ISO time to the second; None for a missing one and for Go's zero time (year 1),
    which is what an online device carries."""
    m = STAMP.match(stamp) if isinstance(stamp, str) else None
    if not m or int(m.group(1)) < 1970:
        return None
    tz = m.group(7)
    off = timezone.utc if tz == "Z" else timezone((1 if tz[0] == "+" else -1) * timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6])))
    try:
        return datetime(*(int(g) for g in m.groups()[:6]), tzinfo=off).astimezone().isoformat(timespec="seconds")
    except (ValueError, OverflowError, OSError):
        return None


class Node:
    """One device as `tailscale status --json` shows it. `label` is the first label of its MagicDNS name (unique in a
    tailnet, lower case); `host` is the name the device gives itself, which may hold capitals and spaces and may differ
    from the label. `ip` is its IPv4 tailnet address: a service bound to IPv4 refuses the IPv6 one."""
    def __init__(self, raw, is_self=False):
        self.is_self = is_self
        self.host = str(raw.get("HostName") or "").strip()
        self.dns = str(raw.get("DNSName") or "").strip().rstrip(".")
        self.label = self.dns.split(".")[0]
        self.name = self.label or self.host
        self.os = raw.get("OS") if isinstance(raw.get("OS"), str) and raw.get("OS") else None
        self.online = is_self or raw.get("Online") is True
        ips = raw.get("TailscaleIPs") if isinstance(raw.get("TailscaleIPs"), list) else []
        self.ip = next((i for i in ips if isinstance(i, str) and IPV4.match(i)), None)
        self.last_seen = None if self.online else when(raw.get("LastSeen"))     # an online device's would change every run


def status(env=None):
    """`tailscale status --json` -> (this machine, the other devices). Raises Failed when Tailscale gives no usable
    answer or is not running: a map drawn from that would call every room absent."""
    env = dict(env if env is not None else os.environ)
    try:
        r = subprocess.run([identity.tailscale(env), "status", "--json"], capture_output=True, text=True,
                           timeout=STATUS_TIMEOUT, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Failed("tailscale status could not run (%s)" % e)
    if r.returncode != 0:
        raise Failed("tailscale status gave no answer (%s)" % ((r.stderr or r.stdout).strip()[:200] or "exit %d" % r.returncode))
    try:
        doc = json.loads(r.stdout)
    except ValueError:
        raise Failed("tailscale status answered with something that is not JSON")
    peers = doc.get("Peer") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or not isinstance(doc.get("Self"), dict) or not isinstance(peers or {}, dict):
        raise Failed("tailscale status answered with something that is not a status")
    if doc.get("BackendState") not in (None, "Running"):
        raise Failed("Tailscale is not running on this machine (it says %s)" % doc.get("BackendState"))
    me = Node(doc["Self"], is_self=True)
    if not me.name:
        raise Failed("tailscale status names no device of its own")
    others = [Node(p) for p in (peers or {}).values() if isinstance(p, dict)]
    return me, [n for n in others if n.name]


def rooms_of(cfg, me, peers):
    """The rooms in the page's order (plan §3.2): the server, then the doors.json devices in file order, then the
    tailnet devices doors.json doesn't list, by name. Each room is (name, Device or None, Node or None). A doors.json
    name means the device whose MagicDNS label it is, or else the one whose HostName it is, ignoring case; a device
    is one room."""
    free, found = [me] + sorted(peers, key=lambda n: n.name.lower()), {}
    for attr in ("label", "host"):
        for key in cfg.devices:
            hit = None if key in found else next((n for n in free if getattr(n, attr).lower() == key.lower()), None)
            if hit is not None:
                found[key] = hit
                free.remove(hit)
    rooms = [(key, dev, found.get(key)) for key, dev in cfg.devices.items()] + [(n.name, None, n) for n in free]
    return sorted(rooms, key=lambda r: not (r[2] is not None and r[2].is_self))      # a stable sort: only the server moves


def connect(ip, port):
    """One TCP connect -> (answered, the probe text)."""
    if not ip:
        return False, "no tailnet address to connect to"
    t0 = time.monotonic()
    try:
        socket.create_connection((ip, port), timeout=TIMEOUT).close()
    except (socket.timeout, TimeoutError):
        return False, "connect timeout %d s" % TIMEOUT
    except ConnectionRefusedError:
        return False, "connect refused"
    except OSError as e:
        return False, "connect failed (%s)" % (e.strerror or type(e).__name__)
    return True, "connected in %d ms" % round((time.monotonic() - t0) * 1000)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A health path that redirects did not answer 2xx; following it could end on another machine."""
    def redirect_request(self, *args, **kwargs):
        return None


def health(base, path):
    """One GET of a serve door's health path -> (answered 2xx, the probe text). The normal TLS check, no proxy, no
    redirects. The texts never quote the address."""
    if not base:
        return False, "no MagicDNS name to ask"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect,
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(urllib.request.Request(base + path, headers={"User-Agent": "janus-map/" + version()}),
                         timeout=TIMEOUT) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
        e.close()
    except (OSError, http.client.HTTPException, ValueError) as e:
        why = e.reason if isinstance(e, urllib.error.URLError) else e
        if isinstance(why, (socket.timeout, TimeoutError)):
            return False, "health timeout %d s" % TIMEOUT
        if isinstance(why, ssl.SSLError):
            return False, "health TLS check failed"
        if isinstance(why, ConnectionRefusedError):
            return False, "health connect refused"
        return False, "health did not answer"
    return 200 <= code < 300, "health answered %d" % code


def serve_base(node, env=None):
    """Where a serve door is asked: its device's own MagicDNS name over HTTPS, the way another device reaches it.
    $JANUS_SERVE_URL replaces it (the tests point it at a local listener)."""
    over = (env if env is not None else os.environ).get("JANUS_SERVE_URL")
    return (over or ("https://" + node.dns if node.dns else "")).rstrip("/")


def probe_all(jobs):
    """Run every probe at once -> { id: (answered, text) }. jobs: [(id, function, text if it never comes back)].
    Each probe has its own TIMEOUT; one still running GRACE after that (a name lookup that hangs) is left behind in
    its daemon thread and counted as timed out, so a run with every door silent still ends in under 3 s."""
    answers = {}

    def work(key, fn):
        try:
            answers[key] = fn()
        except Exception as e:      # a probe must never take the run down: the door did not answer
            answers[key] = (False, "probe failed (%s)" % type(e).__name__)

    threads = [threading.Thread(target=work, args=(key, fn), daemon=True) for key, fn, _ in jobs]
    for t in threads:
        t.start()
    end = time.monotonic() + TIMEOUT + GRACE
    for t in threads:
        t.join(max(0.0, end - time.monotonic()))
    return {key: answers.get(key, (False, late)) for key, _, late in jobs}


def counts(rooms):
    """Doors per state; each door is in exactly one count (a door closed unexpectedly is not also in `closed`)."""
    c = dict.fromkeys(COUNTS, 0)
    for r in rooms:
        for d in r["doors"]:
            c["unexpected" if d["unexpected"] else d["state"]] += 1
    return c


def _named(names, what):
    """Rooms in the status line: named while there are one or two, counted when there are more."""
    return "%s %s" % (config.join(names) if len(names) <= 2 else "%d rooms" % len(names), what)


def _time(iso):
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError):
        return 0.0


def line(rooms, c):
    """The status line: the same text on the page, in Home's status and in `janus map --json` (plan §3.4)."""
    if not sum(c.values()):
        return "No doors in doors.json"
    parts = []
    if c["open"]:
        parts.append(config.plural(c["open"], "door") + " open")
    if c["unexpected"]:
        parts.append("%d closed unexpectedly" % c["unexpected"])
    if c["closed"]:
        parts.append("%d closed" % c["closed"])
    asleep = [r["device"] for r in rooms if r["state"] == "asleep"]
    if asleep:
        parts.append(_named(asleep, "asleep"))
    if c["unknown"]:
        parts.append("%d not probed yet" % c["unknown"])
    if not parts:       # every door belongs to a device the tailnet doesn't know
        parts.append(_named([r["device"] for r in rooms if r["state"] == "absent" and r["doors"]], "not on the tailnet"))
    return " \u00b7 ".join(parts)


def alert_for(doc):
    """What alerts/janus.json should hold for this map (argus-ui docs/alerts.md), or None when no door is closed
    unexpectedly. The names are the owner's own, as the page shows them: the file never leaves the server."""
    ids = doc["alert"]["doors"]
    if not ids:
        return None
    doors = [(r["device"], d) for r in doc["rooms"] for d in r["doors"] if d["id"] in ids]
    if len(doors) == 1:
        device, d = doors[0]
        message = "%s's %s door closed unexpectedly (%s). Open the Map for its history." % (device, d["name"], d["probe"])
    else:
        message = "%d doors closed unexpectedly. Open the Map for their history." % len(doors)
    return {"job": JOB, "level": "alert", "since": doc["alert"]["since"], "link": "map", "message": message}


def sync_alert(doc, env=None):
    """Write alerts/janus.json when it should say something else than it does; remove it when no door needs it."""
    path, want = alert_path(env), alert_for(doc)
    if want is None:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    elif read_json(path) != want:
        write_json(path, want)
    return want


def run(env=None):
    """One run of the map -> (the map, the changes as doors-log lines). Raises Failed; when Tailscale or doors.json
    cannot be read, that is before anything is written."""
    env = dict(env if env is not None else os.environ)
    started = time.monotonic()
    try:
        cfg = config.load_doors()
    except config.ConfigError as e:
        raise Failed("%s. %s" % (e, " ".join(e.config.errors[:3])))
    me, peers = status(env)
    try:
        with locked(env):
            return _run(cfg, me, peers, env, started)
    except OSError as e:
        raise Failed("could not write what the run found (%s)" % e)


def _run(cfg, me, peers, env, started):
    try:
        old = read_map(env)
    except Broken as e:
        print("janus map: %s; drawing it again from nothing." % e, file=sys.stderr)
        old = None
    was_rooms = {r.get("device"): r for r in old["rooms"]} if old else {}
    was_doors = {d.get("id"): d for r in old["rooms"] for d in r["doors"]} if old else {}
    waited = (read_json(run_path(env)) or {}).get("pending")
    waited = waited if isinstance(waited, dict) else {}
    now = log.now().isoformat(timespec="seconds")
    rooms = rooms_of(cfg, me, peers)

    jobs, answers = [], {}
    for name, dev, node in rooms:
        if dev is None or node is None or not node.online:
            continue                        # an asleep room is never probed
        for door in dev.doors.values():
            did = "%s/%s" % (name, door.name)
            if door.taildrop:               # a Taildrop can't be test-sent: open while its device is online
                answers[did] = (True, "device online (Taildrop)")
            elif door.serve:
                jobs.append((did, lambda b=serve_base(node, env), p=door.health: health(b, p), "health timeout %d s" % TIMEOUT))
            else:
                jobs.append((did, lambda i=node.ip, p=door.port: connect(i, p), "connect timeout %d s" % TIMEOUT))
    answers.update(probe_all(jobs))

    out, changes, pending = [], [], {}
    for name, dev, node in rooms:
        state = "absent" if node is None else "online" if node.online else "asleep"
        was_state = (was_rooms.get(name) or {}).get("state")
        room = {"device": name, "self": bool(node and node.is_self), "os": node.os if node else None, "state": state,
                "expect": dev.expect if dev else None, "last_seen": node.last_seen if node else None,
                "note": dev.note if dev else None, "uses": list(dev.uses) if dev else [], "doors": []}
        if state != was_state:
            changes.append({"t": now, "device": name, "door": None, "room": True, "from": was_state, "to": state,
                            "expected": state == "online" or room["expect"] != "always", "probe": ROOM_SAYS[state]})
        for door in (dev.doors.values() if dev else ()):
            did = "%s/%s" % (name, door.name)
            expect = door.expect or dev.expect
            prev = was_doors.get(did) or {}
            was = prev.get("state")
            if state != "online":           # Tailscale's word, not a probe: at once
                new, text = "asleep", NOT_PROBED[state]
            else:
                ok, text = answers[did]
                base = was if was in ("open", "closed") and was_state == "online" else "unknown"
                if ok:                      # a connect that succeeded can't be a dropped packet: at once
                    new = "open"
                elif base == "closed":
                    new = "closed"
                else:                       # to closed only after two failed probes in a row
                    w = waited.get(did)
                    n = (w.get("n") if isinstance(w, dict) and isinstance(w.get("n"), int) else 0) + 1
                    if n >= 2:
                        new = "closed"
                    else:
                        new = base
                        pending[did] = {"n": n, "probe": text, "t": now}
                        text += WAITING
            unexpected = new == "closed" and expect in ("always", "when-online")
            entry = {"id": did, "name": door.name, "how": "taildrop" if door.taildrop else "serve" if door.serve else "connect",
                     "port": door.port, "health": door.health if door.serve else None, "state": new,
                     "unexpected": unexpected, "expect": expect, "since": prev.get("since"), "probe": prev.get("probe"),
                     "agents": list(door.agents), "clients": list(door.clients), "note": door.note}
            if new != was:
                entry["since"], entry["probe"] = now, text
            elif new == "asleep" and state != was_state:
                entry["probe"] = text       # asleep before, not on the tailnet now (or the other way round)
            if new != was or unexpected != (prev.get("unexpected") is True):    # the second: doors.json expects something else now
                changes.append({"t": now, "device": name, "door": door.name, "from": was, "to": new,
                                "expected": not unexpected, "probe": entry["probe"]})
            room["doors"].append(entry)
        out.append(room)

    c = counts(out)
    alarm = [d for r in out for d in r["doors"] if d["unexpected"]]
    doc = {"version": 1, "changed": now, "line": line(out, c), "counts": c, "rooms": out,
           "alert": {"doors": [d["id"] for d in alarm], "since": min((d["since"] for d in alarm), key=_time, default=None), "acked": []}}
    if old is not None and {**old, "changed": None} == {**doc, "changed": None}:
        doc["changed"] = old.get("changed")         # nothing changed: nothing is written
    else:
        write_json(map_path(env), doc)
    for change in changes:
        log.write("doors", change, env)
    sync_alert(doc, env)
    write_json(run_path(env), {"version": 1, "t": now, "ms": round((time.monotonic() - started) * 1000),
                               "probed": len(jobs), "changes": len(changes), "pending": pending})
    return doc, changes


def sentence(change):
    """One change in plain words, for `janus map` at a terminal and in the journal."""
    to = "closed unexpectedly" if change["to"] == "closed" and not change["expected"] else WORDS.get(change["to"], change["to"])
    who = change["device"] if change["door"] is None else "%s's %s door" % (change["device"], change["door"])
    if change["from"] is None:
        return "%s: %s (%s)" % (who, to, change["probe"])
    return "%s: %s, now %s (%s)" % (who, WORDS.get(change["from"], change["from"]), to, change["probe"])


def main(args):
    """janus map [--once] [--json]: one run. Exit 0 when the run completed (a closed door is not a failure), 2 when it
    could not be made: then the previous map stays."""
    try:
        doc, changes = run()
    except Failed as e:
        print("janus map: %s" % e, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(doc))
    else:
        print(doc["line"].encode(sys.stdout.encoding or "utf-8", "replace").decode(sys.stdout.encoding or "utf-8"))
        for change in changes:
            print("  " + sentence(change))
    return 0
