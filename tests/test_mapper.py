"""`janus map` (docs/design.md §6a, issue #11; the contract in docs/plans/2026-11-09-map-page.md §3): the fake tailscale
says which devices exist and which are online, and local listeners stand in for the doors. Every test has its own
temporary realm (doors.json, a tailnet folder for the fake, and the three places a run writes to), so nothing on this
machine is read or written. Every device answers at the loopback address; the names are invented."""
import contextlib
import errno
import http.server
import io
import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import janus
from janus import mapper
from tests.helpers import DOORS_EXAMPLE, ROOT, Realm, snapshot

try:
    import fcntl
except ImportError:         # not Linux: runs are not serialised there (mapper.locked)
    fcntl = None

DOT = " · "
ZERO = "0001-01-01T00:00:00Z"                   # Go's zero time: what an online device carries as LastSeen
SEEN = "2026-11-08T08:00:00.123456789Z"         # an asleep device's LastSeen, with Go's nine decimals
SEEN_LOCAL = datetime(2026, 11, 8, 8, 0, tzinfo=timezone.utc).astimezone().isoformat(timespec="seconds")
T0 = datetime(2026, 11, 9, 21, 0, tzinfo=timezone(timedelta(hours=-7)))
ROOM_KEYS = ["device", "doors", "expect", "last_seen", "note", "os", "self", "state", "uses"]
DOOR_KEYS = ["agents", "clients", "expect", "health", "how", "id", "name", "note", "port", "probe", "since", "state",
             "unexpected"]


def stamp(n):
    """The time of run n (the runs are five minutes apart), as the map and the log write it."""
    return (T0 + timedelta(minutes=5 * n)).isoformat(timespec="seconds")


def device(name, online=True, os="linux", host=None, seen=None, ip="127.0.0.1"):
    """One device the way `tailscale status --json` lists it. The IPv6 address comes first here to prove that Janus
    picks the IPv4 one."""
    return {"ID": "n-" + name, "HostName": host or name, "DNSName": name + ".example.ts.net.", "OS": os, "Online": online,
            "TailscaleIPs": ["2001:db8::1"] + ([ip] if ip else []), "LastSeen": seen or (ZERO if online else SEEN)}


class Port:
    """A TCP port on this machine that answers a connect or refuses it. Nothing is accepted (the backlog takes the
    connects), so it needs no thread."""
    def __init__(self, listening=True):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        if listening:
            self.sock.listen(128)

    def shut(self):
        """Stop answering. The port stays taken (bound, not listening), so a connect is refused."""
        self.sock.close()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))

    def open(self):
        self.sock.listen(128)

    def close(self):
        self.sock.close()


class Health:
    """A local web server standing in for a `tailscale serve` door: it answers every GET with one status code."""
    def __init__(self, code=200, location=None):
        outer = self
        self.code, self.location, self.paths, self.agents = code, location, [], []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.paths.append(self.path)
                outer.agents.append(self.headers.get("User-Agent"))
                self.send_response(outer.code)
                if outer.location:
                    self.send_header("Location", outer.location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


class Raw:
    """A local TCP server that reads what arrives, sends fixed bytes (or nothing) and hangs up."""
    def __init__(self, answer=b""):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                if answer:
                    self.request.sendall(answer)

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


class MapCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.realm = Realm(tmp.name)
        self.addCleanup(self.realm.stop)
        self.fake = self.tmp / "tailnet"
        self.fake.mkdir()
        self.state, self.alerts, self.runtime = self.tmp / "state", self.tmp / "alerts", self.tmp / "runtime"
        env = mock.patch.dict(os.environ, {"USERPROFILE": str(self.realm.home), "JANUS_FAKE_TAILNET": str(self.fake),
                                           "JANUS_STATE": str(self.state), "ARGUS_ALERTS": str(self.alerts),
                                           "XDG_RUNTIME_DIR": str(self.runtime)})
        env.start()
        self.addCleanup(env.stop)
        for name in ("JANUS_SERVE_URL", "JANUS_FAKE_STATUS"):
            os.environ.pop(name, None)
        self.runs, self.changes = 0, []

    # the stand-ins -------------------------------------------------------------------------------------------------
    def port(self, listening=True):
        p = Port(listening)
        self.addCleanup(p.close)
        return p

    def health(self, code=200, location=None):
        h = Health(code, location)
        self.addCleanup(h.close)
        return h

    def raw(self, answer=b""):
        r = Raw(answer)
        self.addCleanup(r.close)
        return r

    def silent(self, *ports):
        """From now on a connect to one of these ports times out (at once, not after two seconds)."""
        real, numbers = socket.create_connection, [p.port for p in ports]

        def fake(address, *args, **kwargs):
            if address[1] in numbers:
                raise socket.timeout("timed out")
            return real(address, *args, **kwargs)

        p = mock.patch("socket.create_connection", fake)
        p.start()
        self.addCleanup(p.stop)

    def tailnet_is(self, *peers, me=None, backend="Running"):
        doc = {"Version": "1.80.0", "BackendState": backend, "Self": me or device("homeserver"),
               "Peer": {"nodekey-%d" % i: p for i, p in enumerate(peers)}}
        (self.fake / "status.json").write_text(json.dumps(doc), encoding="utf-8")

    def doors_are(self, devices):
        self.realm.doors.write_text(json.dumps({"version": 1, "devices": devices}), encoding="utf-8")

    def world(self, desktop=True, laptop=False):
        """A small realm with five doors. The server (always): jellyfin, and sunshine (sometimes). The desktop
        (when-online): Taildrop and apollo. The laptop (sometimes, asleep): Taildrop. A phone and a tablet without
        doors; the tablet is not on the tailnet, and `guestbook` is on the tailnet but not in doors.json."""
        self.jellyfin, self.sunshine, self.apollo = self.port(), self.port(), self.port()
        self.devices = {
            "{{SERVER}}": {"expect": "always", "doors": {
                "jellyfin": {"port": self.jellyfin.port, "agents": ["hermes-jellyfin"], "clients": ["{{PHONE}}", "tv"]},
                "sunshine": {"port": self.sunshine.port, "expect": "sometimes", "note": "only while someone plays"}}},
            "{{PC}}": {"expect": "when-online", "note": "a VPN takes it off the tailnet", "doors": {
                "taildrop": {"taildrop": True, "agents": ["hermes"]},
                "apollo": {"port": self.apollo.port, "clients": ["{{SERVER}}"]}}},
            "laptop": {"expect": "sometimes", "doors": {"taildrop": {"taildrop": True}}},
            "{{PHONE}}": {"expect": "sometimes", "doors": {}, "uses": ["jellyfin"]},
            "tablet": {"expect": "sometimes", "doors": {}, "note": "not on the tailnet yet"}}
        self.doors_are(self.devices)
        self.online(desktop, laptop)

    def online(self, desktop=True, laptop=False):
        self.tailnet_is(device("phone", os="android"), device("laptop", online=laptop),
                        device("guestbook", os="macOS"), device("desktop", online=desktop, os="windows"))

    # a run and what it left ----------------------------------------------------------------------------------------
    def run_map(self, at=None):
        """One run of the map, five minutes after the one before (or at `at`) -> the map it returns."""
        at = at or T0 + timedelta(minutes=5 * self.runs)
        self.runs += 1
        with mock.patch("janus.log.now", return_value=at):
            doc, self.changes = mapper.run()
        return doc

    def map(self):
        return json.loads((self.state / "map.json").read_text(encoding="utf-8"))

    def run_json(self):
        return json.loads((self.runtime / "janus" / "run.json").read_text(encoding="utf-8"))

    def log(self):
        lines = []
        for f in sorted((self.state / "log").glob("doors-*.jsonl")):
            lines += [json.loads(text) for text in f.read_text(encoding="utf-8").splitlines()]
        return lines

    def alert(self):
        path = self.alerts / "janus.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def room(self, doc, name):
        return next(r for r in doc["rooms"] if r["device"] == name)

    def door(self, doc, did):
        return next(d for r in doc["rooms"] for d in r["doors"] if d["id"] == did)

    def says(self, doc, did):
        """A door in four words: its state, whether that is unexpected, since when, and the probe text."""
        d = self.door(doc, did)
        return d["state"], d["unexpected"], d["since"], d["probe"]

    def age(self):
        """Make every written file an hour old, so a rewrite would show in its mtime whatever the clock's grain."""
        old = time.time() - 3600
        for folder in (self.state, self.alerts):
            for p in folder.rglob("*"):
                if p.is_file():
                    os.utime(p, (old, old))


class MapRunTest(MapCase):
    def test_the_first_run_draws_every_room_and_every_door(self):
        self.world()
        doc = self.run_map()
        self.assertEqual(doc, self.map())
        self.assertEqual(sorted(doc), ["alert", "changed", "counts", "line", "rooms", "version"])
        self.assertEqual((doc["version"], doc["changed"]), (1, stamp(0)))
        self.assertEqual(doc["line"], "4 doors open" + DOT + "laptop asleep")
        self.assertEqual(doc["counts"], {"open": 4, "closed": 0, "unexpected": 0, "asleep": 1, "unknown": 0})
        self.assertEqual(doc["alert"], {"doors": [], "since": None, "acked": []})
        self.assertIsNone(self.alert())
        # the server first, then doors.json in file order, then the tailnet's other devices
        self.assertEqual([(r["device"], r["self"], r["state"], r["expect"], r["os"]) for r in doc["rooms"]],
                         [("homeserver", True, "online", "always", "linux"),
                          ("desktop", False, "online", "when-online", "windows"),
                          ("laptop", False, "asleep", "sometimes", "linux"),
                          ("phone", False, "online", "sometimes", "android"),
                          ("tablet", False, "absent", "sometimes", None),
                          ("guestbook", False, "online", None, "macOS")])
        for room in doc["rooms"]:
            self.assertEqual(sorted(room), ROOM_KEYS)
            for door in room["doors"]:
                self.assertEqual(sorted(door), DOOR_KEYS)
        self.assertEqual([(r["last_seen"], r["note"], r["uses"]) for r in doc["rooms"]],
                         [(None, None, []), (None, "a VPN takes it off the tailnet", []), (SEEN_LOCAL, None, []),
                          (None, None, ["jellyfin"]), (None, "not on the tailnet yet", []), (None, None, [])])
        self.assertEqual([d["id"] for r in doc["rooms"] for d in r["doors"]],
                         ["homeserver/jellyfin", "homeserver/sunshine", "desktop/taildrop", "desktop/apollo",
                          "laptop/taildrop"])
        jellyfin = self.door(doc, "homeserver/jellyfin")
        self.assertRegex(jellyfin.pop("probe"), r"^connected in \d+ ms$")
        self.assertEqual(jellyfin, {"id": "homeserver/jellyfin", "name": "jellyfin", "how": "connect",
                                    "port": self.jellyfin.port, "health": None, "state": "open", "unexpected": False,
                                    "expect": "always", "since": stamp(0), "agents": ["hermes-jellyfin"],
                                    "clients": ["phone", "tv"], "note": None})
        sunshine = self.door(doc, "homeserver/sunshine")
        self.assertEqual((sunshine["expect"], sunshine["note"], sunshine["state"]),
                         ("sometimes", "only while someone plays", "open"))
        self.assertEqual(self.door(doc, "desktop/taildrop"),
                         {"id": "desktop/taildrop", "name": "taildrop", "how": "taildrop", "port": None, "health": None,
                          "state": "open", "unexpected": False, "expect": "when-online", "since": stamp(0),
                          "probe": "device online (Taildrop)", "agents": ["hermes"], "clients": [], "note": None})
        self.assertEqual(self.door(doc, "desktop/apollo")["clients"], ["homeserver"])
        self.assertEqual(self.says(doc, "laptop/taildrop"), ("asleep", False, stamp(0), "device asleep, not probed"))

    def test_the_first_run_logs_every_room_and_every_door_once(self):
        self.world()
        self.run_map()
        log = self.log()
        self.assertEqual(log, self.changes)
        self.assertEqual(len(log), 11)
        self.assertEqual([line["device"] for line in log if line.get("room")],
                         ["homeserver", "desktop", "laptop", "phone", "tablet", "guestbook"])
        self.assertEqual([line["device"] + "/" + line["door"] for line in log if line["door"]],
                         ["homeserver/jellyfin", "homeserver/sunshine", "desktop/taildrop", "desktop/apollo",
                          "laptop/taildrop"])
        self.assertIn({"t": stamp(0), "device": "laptop", "door": None, "room": True, "from": None, "to": "asleep",
                       "expected": True, "probe": "Tailscale says offline"}, log)
        self.assertIn({"t": stamp(0), "device": "tablet", "door": None, "room": True, "from": None, "to": "absent",
                       "expected": True, "probe": "not in tailscale status"}, log)
        self.assertIn({"t": stamp(0), "device": "guestbook", "door": None, "room": True, "from": None, "to": "online",
                       "expected": True, "probe": "Tailscale says online"}, log)
        self.assertIn({"t": stamp(0), "device": "desktop", "door": "taildrop", "from": None, "to": "open",
                       "expected": True, "probe": "device online (Taildrop)"}, log)
        self.assertIn({"t": stamp(0), "device": "laptop", "door": "taildrop", "from": None, "to": "asleep",
                       "expected": True, "probe": "device asleep, not probed"}, log)
        self.assertEqual([p.name for p in (self.state / "log").iterdir()], ["doors-2026-11.jsonl"])

    def test_run_json_is_written_on_every_run_in_the_runtime_directory(self):
        self.world()
        self.run_map()
        run = self.run_json()
        self.assertIsInstance(run.pop("ms"), int)
        self.assertEqual(run, {"version": 1, "t": stamp(0), "probed": 3, "changes": 11, "pending": {}})
        self.run_map()
        run = self.run_json()
        self.assertEqual((run["t"], run["probed"], run["changes"]), (stamp(1), 3, 0))
        self.assertFalse((self.state / "run.json").exists())

    def test_without_a_runtime_directory_run_json_sits_beside_the_map(self):
        self.world()
        del os.environ["XDG_RUNTIME_DIR"]
        self.run_map()
        self.assertEqual(json.loads((self.state / "run.json").read_text(encoding="utf-8"))["t"], stamp(0))
        self.assertFalse(self.runtime.exists())
        self.assertEqual(mapper.run_path({"JANUS_STATE": str(self.state)}), self.state / "run.json")
        self.assertEqual(mapper.run_path({"JANUS_STATE": str(self.state), "XDG_RUNTIME_DIR": str(self.runtime)}),
                         self.runtime / "janus" / "run.json")

    def test_where_the_files_live_by_default(self):
        self.assertEqual(mapper.map_path({}), self.realm.home / ".local" / "share" / "janus" / "map.json")
        self.assertEqual(mapper.alert_path({}), self.realm.home / ".local" / "state" / "argus-ui" / "alerts" / "janus.json")
        self.assertEqual(mapper.alert_path(), self.alerts / "janus.json")
        self.assertEqual(mapper.map_path(), self.state / "map.json")

    def test_no_tailnet_address_or_tailnet_name_is_written_anywhere(self):
        self.world()
        self.jellyfin.shut()
        for _ in range(3):
            self.run_map()
        self.assertIsNotNone(self.alert())
        written = [p for folder in (self.state, self.alerts, self.runtime) for p in folder.rglob("*") if p.is_file()]
        self.assertEqual(sorted(p.name for p in written), ["doors-2026-11.jsonl", "janus.json", "map.json", "map.lock", "run.json"]
                         if fcntl else ["doors-2026-11.jsonl", "janus.json", "map.json", "run.json"])
        for p in written:
            text = p.read_text(encoding="utf-8")
            for private in ("127.0.0.1", "2001:db8", "ts.net", "nodekey", "n-homeserver"):
                self.assertNotIn(private, text, p.name)

    # matching (plan §3.2) ------------------------------------------------------------------------------------------
    def test_a_doors_json_name_means_the_magicdns_label_first_and_else_the_host_name(self):
        rooms = {"expect": "sometimes", "doors": {}}
        self.doors_are({"homeserver": rooms, "studio": rooms, "tower": rooms})
        self.tailnet_is(device("den", os="macOS", host="studio"),               # its HostName is another one's label
                        device("tower-1", os="linux", host="TOWER"),            # matched by HostName, ignoring case
                        device("studio", os="windows", host="Living Room PC"),  # matched by its label
                        {"HostName": "Guest Tablet", "OS": "android", "Online": True},     # no MagicDNS name at all
                        me=device("homeserver", host="Home Server"))
        doc = self.run_map()
        self.assertEqual([(r["device"], r["os"], r["expect"]) for r in doc["rooms"]],
                         [("homeserver", "linux", "sometimes"), ("studio", "windows", "sometimes"),
                          ("tower", "linux", "sometimes"), ("den", "macOS", None), ("Guest Tablet", "android", None)])

    def test_the_server_comes_first_wherever_doors_json_lists_it(self):
        self.doors_are({"desktop": {"expect": "sometimes", "doors": {}}, "homeserver": {"expect": "always", "doors": {}}})
        self.tailnet_is(device("desktop"), device("attic"))
        self.assertEqual([r["device"] for r in self.run_map()["rooms"]], ["homeserver", "desktop", "attic"])

    def test_a_server_that_doors_json_does_not_list_is_still_the_first_room(self):
        self.doors_are({"desktop": {"expect": "sometimes", "doors": {}}})
        self.tailnet_is(device("desktop"), device("attic"))
        doc = self.run_map()
        self.assertEqual([(r["device"], r["self"], r["expect"], r["doors"]) for r in doc["rooms"]],
                         [("homeserver", True, None, []), ("desktop", False, "sometimes", []), ("attic", False, None, [])])
        self.assertEqual(doc["line"], "No doors in doors.json")

    # asleep and absent ---------------------------------------------------------------------------------------------
    def test_an_asleep_room_is_never_probed(self):
        self.world(desktop=False)               # apollo's port answers: a probe would find it open
        with mock.patch.object(mapper, "connect", wraps=mapper.connect) as connect:
            doc = self.run_map()
        self.assertEqual(sorted(c.args[1] for c in connect.call_args_list), sorted([self.jellyfin.port, self.sunshine.port]))
        self.assertEqual(self.run_json()["probed"], 2)
        self.assertEqual(self.says(doc, "desktop/apollo"), ("asleep", False, stamp(0), "device asleep, not probed"))
        self.assertEqual(self.says(doc, "desktop/taildrop"), ("asleep", False, stamp(0), "device asleep, not probed"))
        self.assertEqual(self.room(doc, "desktop")["last_seen"], SEEN_LOCAL)
        self.assertEqual(doc["counts"], {"open": 2, "closed": 0, "unexpected": 0, "asleep": 3, "unknown": 0})
        self.assertEqual(doc["line"], "2 doors open" + DOT + "desktop and laptop asleep")

    def test_a_device_the_tailnet_does_not_know_is_absent_and_its_doors_are_not_probed(self):
        kiosk = self.port()
        self.doors_are({"homeserver": {"expect": "always", "doors": {}},
                        "tablet": {"expect": "always", "doors": {"kiosk": {"port": kiosk.port}}}})
        self.tailnet_is()
        with mock.patch.object(mapper, "connect", wraps=mapper.connect) as connect:
            doc = self.run_map()
        connect.assert_not_called()
        room = self.room(doc, "tablet")
        self.assertEqual((room["state"], room["os"], room["last_seen"]), ("absent", None, None))
        self.assertEqual(self.says(doc, "tablet/kiosk"), ("asleep", False, stamp(0), "device not on the tailnet, not probed"))
        self.assertEqual(doc["counts"], {"open": 0, "closed": 0, "unexpected": 0, "asleep": 1, "unknown": 0})
        self.assertEqual(doc["line"], "tablet not on the tailnet")
        self.assertIn({"t": stamp(0), "device": "tablet", "door": None, "room": True, "from": None, "to": "absent",
                       "expected": False, "probe": "not in tailscale status"}, self.log())
        self.assertIsNone(self.alert())

    def test_a_room_that_falls_asleep_takes_its_doors_with_it_at_once(self):
        self.world()
        self.run_map()
        self.online(desktop=False)
        doc = self.run_map()
        self.assertEqual(self.says(doc, "desktop/apollo"), ("asleep", False, stamp(1), "device asleep, not probed"))
        self.assertEqual(self.says(doc, "desktop/taildrop"), ("asleep", False, stamp(1), "device asleep, not probed"))
        self.assertEqual(self.changes, [
            {"t": stamp(1), "device": "desktop", "door": None, "room": True, "from": "online", "to": "asleep",
             "expected": True, "probe": "Tailscale says offline"},
            {"t": stamp(1), "device": "desktop", "door": "taildrop", "from": "open", "to": "asleep", "expected": True,
             "probe": "device asleep, not probed"},
            {"t": stamp(1), "device": "desktop", "door": "apollo", "from": "open", "to": "asleep", "expected": True,
             "probe": "device asleep, not probed"}])
        self.assertEqual(self.log()[-3:], self.changes)
        self.assertEqual(self.room(doc, "desktop")["last_seen"], SEEN_LOCAL)

    def test_an_asleep_device_that_leaves_the_tailnet_keeps_its_doors_asleep_with_the_new_reason(self):
        self.world(desktop=False)
        self.run_map()
        self.tailnet_is(device("phone", os="android"), device("laptop", online=False), device("guestbook", os="macOS"))
        doc = self.run_map()
        self.assertEqual(self.room(doc, "desktop")["state"], "absent")
        self.assertEqual(self.says(doc, "desktop/apollo"), ("asleep", False, stamp(0), "device not on the tailnet, not probed"))
        self.assertEqual(self.changes, [{"t": stamp(1), "device": "desktop", "door": None, "room": True, "from": "asleep",
                                         "to": "absent", "expected": True, "probe": "not in tailscale status"}])

    def test_a_room_that_wakes_has_its_doors_probed_in_the_same_run(self):
        self.world(desktop=False)
        self.apollo.shut()
        self.run_map()
        self.online(desktop=True)
        doc = self.run_map()
        self.assertEqual((self.room(doc, "desktop")["state"], self.room(doc, "desktop")["last_seen"]), ("online", None))
        self.assertEqual(self.says(doc, "desktop/taildrop"), ("open", False, stamp(1), "device online (Taildrop)"))
        self.assertEqual(self.says(doc, "desktop/apollo"),
                         ("unknown", False, stamp(1), "connect refused; waiting for a second probe"))
        self.assertEqual(doc["line"], "3 doors open" + DOT + "laptop asleep" + DOT + "1 not probed yet")
        self.assertEqual(doc["counts"], {"open": 3, "closed": 0, "unexpected": 0, "asleep": 1, "unknown": 1})
        self.assertEqual(self.run_json()["pending"], {"desktop/apollo": {"n": 1, "probe": "connect refused", "t": stamp(1)}})
        self.assertEqual(self.changes, [
            {"t": stamp(1), "device": "desktop", "door": None, "room": True, "from": "asleep", "to": "online",
             "expected": True, "probe": "Tailscale says online"},
            {"t": stamp(1), "device": "desktop", "door": "taildrop", "from": "asleep", "to": "open", "expected": True,
             "probe": "device online (Taildrop)"},
            {"t": stamp(1), "device": "desktop", "door": "apollo", "from": "asleep", "to": "unknown", "expected": True,
             "probe": "connect refused; waiting for a second probe"}])
        self.assertIsNone(self.alert())
        doc = self.run_map()                    # the second failed probe: an awake desktop's apollo should answer
        self.assertEqual(self.says(doc, "desktop/apollo"), ("closed", True, stamp(2), "connect refused"))
        self.assertEqual(self.alert()["message"],
                         "desktop's apollo door closed unexpectedly (connect refused). Open the Map for its history.")

    def test_a_woken_rooms_answering_door_is_open_at_once(self):
        self.world(desktop=False)
        self.run_map()
        self.online(desktop=True)
        doc = self.run_map()
        state, unexpected, since, probe = self.says(doc, "desktop/apollo")
        self.assertEqual((state, unexpected, since), ("open", False, stamp(1)))
        self.assertRegex(probe, r"^connected in \d+ ms$")
        self.assertEqual(doc["line"], "4 doors open" + DOT + "laptop asleep")
        self.assertEqual(self.run_json()["pending"], {})

    # the two-probe rule (plan §3.3) --------------------------------------------------------------------------------
    def test_one_failed_probe_changes_nothing_and_the_second_closes_the_door(self):
        self.world()
        first = self.run_map()
        self.sunshine.shut()
        self.age()
        before = snapshot(self.state), snapshot(self.alerts)
        self.assertEqual(self.run_map(), first)
        self.assertEqual(self.changes, [])
        self.assertEqual((snapshot(self.state), snapshot(self.alerts)), before)       # one miss: nothing on disk moved
        self.assertEqual(self.run_json()["pending"], {"homeserver/sunshine": {"n": 1, "probe": "connect refused", "t": stamp(1)}})
        self.assertNotIn("pending", (self.state / "map.json").read_text(encoding="utf-8"))
        doc = self.run_map()
        self.assertEqual(self.says(doc, "homeserver/sunshine"), ("closed", False, stamp(2), "connect refused"))
        self.assertEqual(doc["changed"], stamp(2))
        self.assertEqual(doc["line"], "3 doors open" + DOT + "1 closed" + DOT + "laptop asleep")
        self.assertEqual(doc["counts"], {"open": 3, "closed": 1, "unexpected": 0, "asleep": 1, "unknown": 0})
        self.assertEqual(self.log()[11:], [{"t": stamp(2), "device": "homeserver", "door": "sunshine", "from": "open",
                                            "to": "closed", "expected": True, "probe": "connect refused"}])
        self.assertEqual(self.run_json()["pending"], {})
        self.assertIsNone(self.alert())         # a `sometimes` door may be closed
        self.assertEqual(doc, self.map())

    def test_an_answer_between_two_misses_starts_the_count_again(self):
        self.world()
        self.run_map()
        self.sunshine.shut()
        self.run_map()
        self.sunshine.open()
        self.run_map()
        self.assertEqual(self.run_json()["pending"], {})
        self.sunshine.shut()
        doc = self.run_map()
        self.assertEqual(self.door(doc, "homeserver/sunshine")["state"], "open")
        self.assertEqual(self.run_json()["pending"]["homeserver/sunshine"]["n"], 1)
        self.assertEqual(len(self.log()), 11)
        self.assertEqual(self.door(self.run_map(), "homeserver/sunshine")["state"], "closed")

    def test_on_the_first_run_a_silent_door_is_not_probed_yet_and_an_answer_opens_it_at_once(self):
        self.world()
        self.jellyfin.shut()
        doc = self.run_map()
        self.assertEqual(self.says(doc, "homeserver/jellyfin"),
                         ("unknown", False, stamp(0), "connect refused; waiting for a second probe"))
        self.assertEqual(doc["line"], "3 doors open" + DOT + "laptop asleep" + DOT + "1 not probed yet")
        self.assertIsNone(self.alert())
        self.jellyfin.open()
        doc = self.run_map()
        state, unexpected, since, probe = self.says(doc, "homeserver/jellyfin")
        self.assertEqual((state, unexpected, since), ("open", False, stamp(1)))
        self.assertEqual(self.changes, [{"t": stamp(1), "device": "homeserver", "door": "jellyfin", "from": "unknown",
                                         "to": "open", "expected": True, "probe": probe}])
        self.assertEqual(self.run_json()["pending"], {})

    def test_a_closed_first_answer_needs_two_probes(self):
        self.world()
        self.sunshine.shut()
        self.assertEqual(self.door(self.run_map(), "homeserver/sunshine")["state"], "unknown")
        doc = self.run_map()
        self.assertEqual(self.says(doc, "homeserver/sunshine"), ("closed", False, stamp(1), "connect refused"))
        self.assertEqual(self.changes, [{"t": stamp(1), "device": "homeserver", "door": "sunshine", "from": "unknown",
                                         "to": "closed", "expected": True, "probe": "connect refused"}])
        doc = self.run_map()                    # closed stays closed without a new count
        self.assertEqual((self.changes, self.run_json()["pending"], doc["changed"]), ([], {}, stamp(1)))

    def test_a_door_not_probed_yet_stays_so_when_the_count_was_lost(self):
        self.world()
        self.sunshine.shut()
        self.run_map()
        (self.runtime / "janus" / "run.json").write_text("{", encoding="utf-8")      # a reboot empties the runtime directory
        doc = self.run_map()
        self.assertEqual(self.says(doc, "homeserver/sunshine"),
                         ("unknown", False, stamp(0), "connect refused; waiting for a second probe"))
        self.assertEqual(self.changes, [])
        self.assertEqual(self.door(self.run_map(), "homeserver/sunshine")["state"], "closed")

    # closed unexpectedly: the alert file (plan §3.6) ---------------------------------------------------------------
    def test_a_door_that_should_be_open_closes_unexpectedly_and_the_alert_file_says_so(self):
        self.world()
        self.run_map()
        self.silent(self.jellyfin)
        self.run_map()
        self.assertIsNone(self.alert())         # one miss never alarms
        doc = self.run_map()
        self.assertEqual(self.says(doc, "homeserver/jellyfin"), ("closed", True, stamp(2), "connect timeout 2 s"))
        self.assertEqual(doc["alert"], {"doors": ["homeserver/jellyfin"], "since": stamp(2), "acked": []})
        self.assertEqual(doc["line"], "3 doors open" + DOT + "1 closed unexpectedly" + DOT + "laptop asleep")
        self.assertEqual(doc["counts"], {"open": 3, "closed": 0, "unexpected": 1, "asleep": 1, "unknown": 0})
        self.assertEqual(self.alert(), {
            "job": "janus-map", "level": "alert", "since": stamp(2), "link": "map",
            "message": "homeserver's jellyfin door closed unexpectedly (connect timeout 2 s). Open the Map for its history."})
        self.assertEqual(self.log()[-1], {"t": stamp(2), "device": "homeserver", "door": "jellyfin", "from": "open",
                                          "to": "closed", "expected": False, "probe": "connect timeout 2 s"})
        self.assertEqual(list(self.tmp.rglob("*.tmp")), [])
        self.assertEqual([p.name for p in self.alerts.iterdir()], ["janus.json"])

    def test_a_reopened_door_clears_the_alert_file_in_the_same_run(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.run_map()
        self.run_map()
        self.assertIsNotNone(self.alert())
        self.jellyfin.open()
        doc = self.run_map()
        state, unexpected, since, probe = self.says(doc, "homeserver/jellyfin")
        self.assertEqual((state, unexpected, since), ("open", False, stamp(3)))
        self.assertIsNone(self.alert())
        self.assertEqual(list(self.alerts.iterdir()), [])
        self.assertEqual(doc["alert"], {"doors": [], "since": None, "acked": []})
        self.assertEqual(self.changes, [{"t": stamp(3), "device": "homeserver", "door": "jellyfin", "from": "closed",
                                         "to": "open", "expected": True, "probe": probe}])
        self.assertEqual(doc["line"], "4 doors open" + DOT + "laptop asleep")

    def test_a_when_online_door_alarms_only_while_its_room_is_online(self):
        self.world()
        self.run_map()
        self.apollo.shut()
        self.run_map()
        doc = self.run_map()
        self.assertEqual(self.says(doc, "desktop/apollo"), ("closed", True, stamp(2), "connect refused"))
        self.assertEqual(self.alert()["message"],
                         "desktop's apollo door closed unexpectedly (connect refused). Open the Map for its history.")
        self.online(desktop=False)
        doc = self.run_map()
        self.assertEqual(self.says(doc, "desktop/apollo"), ("asleep", False, stamp(3), "device asleep, not probed"))
        self.assertIsNone(self.alert())
        self.assertEqual(doc["line"], "2 doors open" + DOT + "desktop and laptop asleep")

    def test_several_doors_closed_unexpectedly_make_one_file_counted_from_the_earliest(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.run_map()
        self.run_map()
        self.apollo.shut()
        self.run_map()
        doc = self.run_map()
        self.assertEqual(doc["alert"], {"doors": ["homeserver/jellyfin", "desktop/apollo"], "since": stamp(2), "acked": []})
        self.assertEqual(self.alert(), {"job": "janus-map", "level": "alert", "since": stamp(2), "link": "map",
                                        "message": "2 doors closed unexpectedly: homeserver's jellyfin, desktop's apollo. "
                                                   "Open the Map for their history."})
        self.assertEqual([p.name for p in self.alerts.iterdir()], ["janus.json"])
        self.assertEqual(doc["line"], "2 doors open" + DOT + "2 closed unexpectedly" + DOT + "laptop asleep")
        self.jellyfin.open()
        self.run_map()
        self.assertEqual(self.alert(), {
            "job": "janus-map", "level": "alert", "since": stamp(4), "link": "map",
            "message": "desktop's apollo door closed unexpectedly (connect refused). Open the Map for its history."})

    def test_the_alert_counts_from_the_earliest_close_by_the_clock_not_by_the_text(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.run_map()
        self.run_map()                          # jellyfin closed at 21:10 -07:00
        self.apollo.shut()
        back = datetime(2026, 11, 9, 20, 15, tzinfo=timezone(timedelta(hours=-8)))    # the clocks went back an hour
        self.run_map(at=back)
        doc = self.run_map(at=back + timedelta(minutes=5))
        self.assertEqual(self.door(doc, "desktop/apollo")["since"], "2026-11-09T20:20:00-08:00")
        self.assertEqual(doc["alert"]["since"], stamp(2))
        self.assertEqual(self.alert()["since"], stamp(2))

    def test_the_alert_file_is_one_argus_ui_accepts(self):
        self.world()
        self.jellyfin.shut()
        self.run_map()
        self.run_map()
        alert = self.alert()                    # argus-ui docs/alerts.md
        self.assertEqual(sorted(alert), ["job", "level", "link", "message", "since"])
        self.assertRegex(alert["job"], r"^[a-z][a-z0-9-]{0,80}$")
        self.assertTrue(alert["job"].startswith("janus-"))
        self.assertEqual((alert["level"], alert["link"]), ("alert", "map"))
        self.assertLessEqual(len(alert["message"]), 300)
        self.assertNotIn("\n", alert["message"])
        self.assertEqual(datetime.fromisoformat(alert["since"]), T0 + timedelta(minutes=5))
        self.assertTrue((ROOT / "units" / (alert["job"] + ".service")).is_file())     # the job is the unit that ran

    # nothing changed: nothing written ------------------------------------------------------------------------------
    def test_a_run_with_no_change_writes_nothing(self):
        self.world()
        self.jellyfin.shut()
        self.sunshine.shut()
        for _ in range(2):
            self.run_map()
        self.assertIsNotNone(self.alert())
        self.age()
        before = snapshot(self.state), snapshot(self.alerts)
        doc = self.run_map()
        self.assertEqual((snapshot(self.state), snapshot(self.alerts)), before)       # map.json, the log, the alert file
        self.assertEqual((doc["changed"], self.changes), (stamp(1), []))
        self.assertEqual(doc, self.map())
        self.assertEqual((self.run_json()["t"], self.run_json()["changes"]), (stamp(2), 0))

    def test_the_counts_add_up_to_the_doors_and_an_unexpected_door_is_never_also_closed(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.sunshine.shut()
        self.run_map()
        doc = self.run_map()
        self.assertEqual(doc["counts"], {"open": 2, "closed": 1, "unexpected": 1, "asleep": 1, "unknown": 0})
        self.assertEqual(sum(doc["counts"].values()), 5)
        self.assertEqual(sum(doc["counts"].values()), sum(len(r["doors"]) for r in doc["rooms"]))
        self.assertEqual(doc["line"], "2 doors open" + DOT + "1 closed unexpectedly" + DOT + "1 closed" + DOT + "laptop asleep")

    # doors.json changes between runs -------------------------------------------------------------------------------
    def test_a_closed_door_that_doors_json_now_expects_open_becomes_unexpected(self):
        self.world()
        self.run_map()
        self.sunshine.shut()
        self.run_map()
        self.run_map()
        self.assertIsNone(self.alert())
        del self.devices["{{SERVER}}"]["doors"]["sunshine"]["expect"]       # now it inherits the server's `always`
        self.doors_are(self.devices)
        doc = self.run_map()
        self.assertEqual(self.says(doc, "homeserver/sunshine"), ("closed", True, stamp(2), "connect refused"))
        self.assertEqual(self.door(doc, "homeserver/sunshine")["expect"], "always")
        self.assertEqual(self.changes, [{"t": stamp(3), "device": "homeserver", "door": "sunshine", "from": "closed",
                                         "to": "closed", "expected": False, "probe": "connect refused"}])
        self.assertEqual(self.alert()["since"], stamp(2))
        self.devices["{{SERVER}}"]["doors"]["sunshine"]["expect"] = "sometimes"
        self.doors_are(self.devices)
        doc = self.run_map()
        self.assertEqual(self.says(doc, "homeserver/sunshine"), ("closed", False, stamp(2), "connect refused"))
        self.assertEqual(self.changes[0]["expected"], True)
        self.assertIsNone(self.alert())

    def test_a_door_taken_out_of_doors_json_leaves_the_map_and_the_alert(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.run_map()
        self.run_map()
        self.assertIsNotNone(self.alert())
        del self.devices["{{SERVER}}"]["doors"]["jellyfin"]
        self.doors_are(self.devices)
        doc = self.run_map()
        self.assertEqual([d["id"] for d in self.room(doc, "homeserver")["doors"]], ["homeserver/sunshine"])
        self.assertEqual((sum(doc["counts"].values()), doc["changed"], self.changes), (4, stamp(3), []))
        self.assertEqual(doc, self.map())
        self.assertIsNone(self.alert())

    def test_a_map_file_that_is_not_a_map_is_drawn_again(self):
        self.world()
        self.run_map()
        for broken in ("{", "[]", json.dumps({"version": 2, "rooms": []}), json.dumps({"version": 1, "rooms": [{"doors": 5}]})):
            (self.state / "map.json").write_text(broken, encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                doc = self.run_map()
            self.assertIn("map.json is not a version 1 map; drawing it again from nothing.", err.getvalue())
            self.assertTrue(err.getvalue().startswith("janus map: "))
            self.assertEqual(doc, self.map())
            self.assertEqual(doc["line"], "4 doors open" + DOT + "laptop asleep")
            self.assertEqual(self.door(doc, "homeserver/jellyfin")["since"], stamp(self.runs - 1))

    # serve doors ---------------------------------------------------------------------------------------------------
    def test_a_serve_door_is_asked_for_its_health_path(self):
        health = self.health(200)
        self.doors_are({"homeserver": {"expect": "always", "doors": {
            "elaia": {"serve": True, "health": "/argus/api/health", "agents": ["argus"]}}}})
        self.tailnet_is()
        with mock.patch.dict(os.environ, {"JANUS_SERVE_URL": health.url}):
            doc = self.run_map()
            door = self.door(doc, "homeserver/elaia")
            self.assertEqual((door["how"], door["port"], door["health"], door["state"], door["probe"]),
                             ("serve", None, "/argus/api/health", "open", "health answered 200"))
            self.assertEqual(health.paths, ["/argus/api/health"])
            self.assertEqual(health.agents, ["janus-map/" + janus.version()])
            health.code = 502
            self.run_map()
            doc = self.run_map()
        self.assertEqual(self.says(doc, "homeserver/elaia"), ("closed", True, stamp(2), "health answered 502"))
        self.assertEqual(self.alert()["message"],
                         "homeserver's elaia door closed unexpectedly (health answered 502). Open the Map for its history.")

    def test_a_serve_door_is_asked_at_its_devices_own_magicdns_name(self):
        self.doors_are({"homeserver": {"expect": "always", "doors": {"elaia": {"serve": True, "health": "/argus/api/health"}}}})
        self.tailnet_is()
        with mock.patch.object(mapper, "health", return_value=(True, "health answered 200")) as health:
            self.run_map()
        health.assert_called_once_with("https://homeserver.example.ts.net", "/argus/api/health")
        node = mapper.Node(device("homeserver"), is_self=True)
        self.assertEqual(mapper.serve_base(node, {}), "https://homeserver.example.ts.net")
        self.assertEqual(mapper.serve_base(node, {"JANUS_SERVE_URL": "http://127.0.0.1:1/"}), "http://127.0.0.1:1")
        self.assertEqual(mapper.serve_base(mapper.Node({"HostName": "Guest Tablet"}), {}), "")


class StatusTest(unittest.TestCase):
    """What Janus reads out of one device of `tailscale status --json`."""
    def test_last_seen_becomes_local_time_and_the_zero_time_is_none(self):
        for nothing in (ZERO, None, "", "yesterday", 5, "2026-13-45T08:00:00Z", "1969-12-31T23:59:59Z"):
            self.assertIsNone(mapper.when(nothing), nothing)
        for same in ("2026-11-08T08:00:00Z", SEEN, "2026-11-08T10:00:00+02:00", "2026-11-08T01:00:00.5-07:00"):
            self.assertEqual(mapper.when(same), SEEN_LOCAL, same)

    def test_a_node(self):
        n = mapper.Node(device("desktop", host="Living Room PC", online=False))
        self.assertEqual((n.host, n.dns, n.label, n.name), ("Living Room PC", "desktop.example.ts.net", "desktop", "desktop"))
        self.assertEqual((n.os, n.online, n.ip, n.last_seen, n.is_self), ("linux", False, "127.0.0.1", SEEN_LOCAL, False))
        n = mapper.Node(device("desktop", seen=SEEN))
        self.assertEqual((n.online, n.last_seen), (True, None))         # an online device's would change every run
        n = mapper.Node({"HostName": " Guest Tablet ", "TailscaleIPs": ["2001:db8::2"], "Online": False}, is_self=True)
        self.assertEqual((n.name, n.label, n.os, n.ip, n.online), ("Guest Tablet", "", None, None, True))
        self.assertEqual(mapper.Node({}).name, "")


def drawn(*rooms):
    """Rooms as the map holds them, from (name, room state, a state per door); "unexpected" is a closed door that
    should be open."""
    return [{"device": name, "state": state,
             "doors": [{"state": "closed" if d == "unexpected" else d, "unexpected": d == "unexpected"} for d in doors]}
            for name, state, *doors in rooms]


class LineTest(unittest.TestCase):
    """The status line (plan §3.4): the same text on the page, on Home and in `janus map --json`."""
    def line(self, *rooms):
        rooms = drawn(*rooms)
        return mapper.line(rooms, mapper.counts(rooms))

    def test_each_part(self):
        for rooms, text in (
                ((), "No doors in doors.json"),
                ((("homeserver", "online"), ("phone", "asleep")), "No doors in doors.json"),
                ((("homeserver", "online", "open"),), "1 door open"),
                ((("homeserver", "online", "open", "open"),), "2 doors open"),
                ((("homeserver", "online", "unexpected"),), "1 closed unexpectedly"),
                ((("homeserver", "online", "unexpected", "unexpected"),), "2 closed unexpectedly"),
                ((("homeserver", "online", "closed"),), "1 closed"),
                ((("homeserver", "online", "unknown", "unknown"),), "2 not probed yet"),
                ((("desktop", "asleep", "asleep", "asleep"),), "desktop asleep"),
                ((("desktop", "asleep", "asleep"), ("laptop", "asleep", "asleep")), "desktop and laptop asleep"),
                ((("desktop", "asleep", "asleep"), ("laptop", "asleep", "asleep"), ("phone", "asleep")), "3 rooms asleep"),
                ((("tablet", "absent", "asleep"),), "tablet not on the tailnet"),
                ((("tablet", "absent", "asleep"), ("kiosk", "absent", "asleep"), ("attic", "absent", "asleep")),
                 "3 rooms not on the tailnet")):
            self.assertEqual(self.line(*rooms), text)

    def test_the_parts_in_their_order(self):
        rooms = (("homeserver", "online", "open", "open", "open", "open", "open", "open", "unexpected", "closed"),
                 ("desktop", "asleep", "asleep", "asleep", "asleep"))
        self.assertEqual(self.line(*rooms), "6 doors open · 1 closed unexpectedly · 1 closed · desktop asleep")
        self.assertEqual(mapper.counts(drawn(*rooms)), {"open": 6, "closed": 1, "unexpected": 1, "asleep": 3, "unknown": 0})
        self.assertEqual(self.line(("homeserver", "online", "open", "unknown"), ("desktop", "asleep", "asleep"), ("tablet", "absent")),
                         "1 door open · desktop asleep · 1 not probed yet")

    def test_an_asleep_room_without_doors_is_named_too(self):
        self.assertEqual(self.line(("homeserver", "online", "open"), ("phone", "asleep")), "1 door open · phone asleep")

    def test_a_change_in_plain_words(self):
        for change, text in (
                ({"device": "homeserver", "door": "jellyfin", "from": "open", "to": "closed", "expected": False,
                  "probe": "connect timeout 2 s"},
                 "homeserver's jellyfin door: open, now closed unexpectedly (connect timeout 2 s)"),
                ({"device": "homeserver", "door": "sunshine", "from": "unknown", "to": "closed", "expected": True,
                  "probe": "connect refused"}, "homeserver's sunshine door: not probed yet, now closed (connect refused)"),
                ({"device": "homeserver", "door": "jellyfin", "from": None, "to": "open", "expected": True,
                  "probe": "connected in 3 ms"}, "homeserver's jellyfin door: open (connected in 3 ms)"),
                ({"device": "desktop", "door": "apollo", "from": "asleep", "to": "unknown", "expected": True,
                  "probe": "connect refused; waiting for a second probe"},
                 "desktop's apollo door: asleep, now not probed yet (connect refused; waiting for a second probe)"),
                ({"device": "laptop", "door": None, "room": True, "from": "online", "to": "asleep", "expected": True,
                  "probe": "Tailscale says offline"}, "laptop: online, now asleep (Tailscale says offline)"),
                ({"device": "tablet", "door": None, "room": True, "from": None, "to": "absent", "expected": True,
                  "probe": "not in tailscale status"}, "tablet: not on the tailnet (not in tailscale status)")):
            self.assertEqual(mapper.sentence(change), text)


class ProbeTextTest(MapCase):
    """Every probe text. None of them quotes an address or a name."""
    def test_connect(self):
        ok, text = mapper.connect("127.0.0.1", self.port().port)
        self.assertTrue(ok)
        self.assertRegex(text, r"^connected in \d+ ms$")
        self.assertEqual(mapper.connect("127.0.0.1", self.port(listening=False).port), (False, "connect refused"))
        self.assertEqual(mapper.connect(None, 80), (False, "no tailnet address to connect to"))

    def test_connect_that_fails_otherwise(self):
        for error, text in ((socket.timeout("timed out"), "connect timeout 2 s"),
                            (TimeoutError(errno.ETIMEDOUT, "Connection timed out"), "connect timeout 2 s"),
                            (ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"), "connect refused"),
                            (OSError(errno.ENETUNREACH, "Network is unreachable"), "connect failed (Network is unreachable)"),
                            (OSError(), "connect failed (OSError)")):
            with mock.patch("socket.create_connection", side_effect=error) as create:
                self.assertEqual(mapper.connect("192.0.2.10", 8096), (False, text))
            create.assert_called_once_with(("192.0.2.10", 8096), timeout=2)

    def test_health_answers(self):
        for code, ok in ((200, True), (204, True), (404, False), (500, False), (502, False)):
            health = self.health(code)
            self.assertEqual(mapper.health(health.url, "/argus/api/health"), (ok, "health answered %d" % code))
            self.assertEqual(health.paths, ["/argus/api/health"])

    def test_health_does_not_follow_a_redirect(self):
        elsewhere = self.health(200)
        health = self.health(302, location=elsewhere.url + "/login")
        self.assertEqual(mapper.health(health.url, "/argus/api/health"), (False, "health answered 302"))
        self.assertEqual(elsewhere.paths, [])

    def test_health_that_gets_no_answer(self):
        self.assertEqual(mapper.health("", "/argus/api/health"), (False, "no MagicDNS name to ask"))
        refused = "http://127.0.0.1:%d" % self.port(listening=False).port
        self.assertEqual(mapper.health(refused, "/argus/api/health"), (False, "health connect refused"))
        hangup = "http://127.0.0.1:%d" % self.raw().port
        self.assertEqual(mapper.health(hangup, "/argus/api/health"), (False, "health did not answer"))
        plain = "https://127.0.0.1:%d" % self.raw(b"HTTP/1.1 400 Bad Request\r\n\r\n").port      # no TLS behind it
        self.assertEqual(mapper.health(plain, "/argus/api/health"), (False, "health TLS check failed"))

    def test_health_that_times_out(self):
        mute = "http://127.0.0.1:%d" % self.port().port         # it takes the connect and never answers
        t0 = time.monotonic()
        self.assertEqual(mapper.health(mute, "/argus/api/health"), (False, "health timeout 2 s"))
        self.assertLess(time.monotonic() - t0, 2.5)

    def test_a_probe_that_breaks_or_never_comes_back_does_not_take_the_run_down(self):
        gate = threading.Event()
        self.addCleanup(gate.set)
        with mock.patch.object(mapper, "TIMEOUT", 0.2), mock.patch.object(mapper, "GRACE", 0.1):
            t0 = time.monotonic()
            got = mapper.probe_all([("a", lambda: (True, "connected in 1 ms"), "late a"),
                                    ("b", lambda: 1 // 0, "late b"),
                                    ("c", lambda: (gate.wait(30), "never used"), "connect timeout 2 s")])
            took = time.monotonic() - t0
        self.assertEqual(got, {"a": (True, "connected in 1 ms"), "b": (False, "probe failed (ZeroDivisionError)"),
                               "c": (False, "connect timeout 2 s")})
        self.assertLess(took, 2)
        self.assertEqual(mapper.probe_all([]), {})

    def test_a_device_without_an_ipv4_address_has_doors_that_wait_and_then_close(self):
        door = self.port()
        self.doors_are({"homeserver": {"expect": "always", "doors": {}},
                        "desktop": {"expect": "sometimes", "doors": {"apollo": {"port": door.port}}}})
        self.tailnet_is(device("desktop", ip=None))
        self.assertEqual(self.says(self.run_map(), "desktop/apollo"),
                         ("unknown", False, stamp(0), "no tailnet address to connect to; waiting for a second probe"))
        self.assertEqual(self.says(self.run_map(), "desktop/apollo"),
                         ("closed", False, stamp(1), "no tailnet address to connect to"))


class MapFailsTest(MapCase):
    """A run that cannot be made is exit 2 (mapper.Failed): nothing is written and the previous map stays."""
    def refused(self, *words):
        before = snapshot(self.tmp)
        with self.assertRaises(mapper.Failed) as e:
            mapper.run()
        for word in words:
            self.assertIn(word, str(e.exception))
        self.assertEqual(snapshot(self.tmp), before)            # not one file or folder more, none touched
        return str(e.exception)

    def test_tailscale_is_not_installed(self):
        self.world()
        with mock.patch.dict(os.environ, {"JANUS_TAILSCALE": str(self.tmp / "no-tailscale")}):
            self.refused("tailscale status could not run (")
        self.assertFalse(self.state.exists() or self.alerts.exists() or self.runtime.exists())

    def test_tailscale_is_down(self):
        self.world()
        with mock.patch.dict(os.environ, {"JANUS_FAKE_STATUS": "fail"}):
            self.refused("tailscale status gave no answer (failed to connect to local tailscaled")
        self.assertFalse(self.state.exists() or self.alerts.exists() or self.runtime.exists())

    def test_tailscale_answers_with_something_else(self):
        self.world()
        with mock.patch.dict(os.environ, {"JANUS_FAKE_STATUS": "garbage"}):
            self.refused("tailscale status answered with something that is not JSON")
        for not_a_status in ([1, 2], {"Peer": {}}, {"Self": "homeserver"}, {"Self": device("homeserver"), "Peer": [1]}):
            (self.fake / "status.json").write_text(json.dumps(not_a_status), encoding="utf-8")
            self.refused("tailscale status answered with something that is not a status")
        (self.fake / "status.json").write_text(json.dumps({"Self": {"Online": True}, "Peer": {}}), encoding="utf-8")
        self.refused("tailscale status names no device of its own")

    def test_tailscale_is_stopped_or_logged_out(self):
        self.world()
        for backend in ("Stopped", "NeedsLogin"):
            self.tailnet_is(device("desktop"), backend=backend)
            self.refused("Tailscale is not running on this machine (it says %s)" % backend)

    def test_doors_json_is_broken_missing_or_wrong(self):
        self.world()
        self.realm.doors.write_text("{ not json", encoding="utf-8")
        self.refused("doors.json: 1 error; run `janus check-config`.", "not valid JSON")
        self.doors_are({"homeserver": {"expect": "always", "doors": {"both": {"port": 80, "taildrop": True}}}})
        self.refused("doors.json: 1 error; run `janus check-config`.", 'needs exactly one of "port", "serve": true or "taildrop": true')
        self.doors_are({"homeserver": {"expect": "now and then", "doors": {}}, "desktop": {"doors": 5}})
        self.refused("doors.json: 2 errors; run `janus check-config`.", '"expect" must be one of')
        os.replace(self.realm.doors, self.realm.doors.with_name("doors.json.away"))
        self.refused("doors.json: 1 error; run `janus check-config`.", "cannot read it")

    def test_the_previous_map_and_alert_stay_when_a_run_fails(self):
        self.world()
        self.jellyfin.shut()
        self.run_map()
        self.run_map()
        kept = (self.state / "map.json").read_bytes(), (self.alerts / "janus.json").read_bytes()
        self.realm.doors.write_text("{ not json", encoding="utf-8")
        self.refused("doors.json")
        self.doors_are(self.devices)
        with mock.patch.dict(os.environ, {"JANUS_FAKE_STATUS": "fail"}):
            self.refused("tailscale status gave no answer")
        self.assertEqual(((self.state / "map.json").read_bytes(), (self.alerts / "janus.json").read_bytes()), kept)

    def test_a_mistake_in_routes_json_does_not_stop_the_map(self):
        self.world()
        self.realm.routes.write_text("{ not json", encoding="utf-8")
        self.assertEqual(self.run_map()["line"], "4 doors open" + DOT + "laptop asleep")
        os.replace(self.realm.routes, self.realm.routes.with_name("routes.json.away"))
        self.assertEqual(self.run_map()["line"], "4 doors open" + DOT + "laptop asleep")

    def test_a_place_that_cannot_be_written_is_a_failure(self):
        self.world()
        self.state.write_text("a file where the folder should be", encoding="utf-8")
        with self.assertRaises(mapper.Failed) as e:
            mapper.run()
        self.assertIn("could not write what the run found (", str(e.exception))


class MapCliTest(MapCase):
    """`janus map [--once] [--json]` as the timer and the page call it."""
    def test_map_prints_the_line_and_what_changed_and_a_closed_door_is_exit_0(self):
        self.world()
        self.sunshine.shut()
        r = self.realm.cli("map")
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        lines = r.stdout.splitlines()
        for part in ("3 doors open", "laptop asleep", "1 not probed yet"):
            self.assertIn(part, lines[0])
        self.assertEqual(len(lines), 12)
        self.assertIn("  laptop: asleep (Tailscale says offline)", lines)
        self.assertIn("  homeserver's sunshine door: not probed yet (connect refused; waiting for a second probe)", lines)
        r = self.realm.cli("map")
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(r.stdout.splitlines()[1:], ["  homeserver's sunshine door: not probed yet, now closed (connect refused)"])
        self.assertIn("1 closed", r.stdout.splitlines()[0])
        r = self.realm.cli("map")
        self.assertEqual((r.returncode, len(r.stdout.splitlines())), (0, 1))

    def test_map_json_prints_the_map(self):
        self.world()
        for args in (("map", "--json"), ("map", "--once", "--json"), ("map", "--once")):
            r = self.realm.cli(*args)
            self.assertEqual((r.returncode, r.stderr), (0, ""), args)
            if "--json" in args:
                self.assertEqual(json.loads(r.stdout), self.map())
                self.assertEqual(len(r.stdout.splitlines()), 1)
        self.assertEqual(self.map()["line"], "4 doors open" + DOT + "laptop asleep")

    def test_a_run_that_cannot_be_made_is_exit_2_and_writes_nothing(self):
        self.world()
        before = snapshot(self.tmp)
        r = self.realm.cli("map", "--json", JANUS_FAKE_STATUS="fail")
        self.assertEqual((r.returncode, r.stdout), (2, ""))
        self.assertTrue(r.stderr.startswith("janus map: tailscale status gave no answer (failed to connect"), r.stderr)
        self.assertEqual(snapshot(self.tmp), before)
        self.realm.doors.write_text("{ not json", encoding="utf-8")
        before = snapshot(self.tmp)
        r = self.realm.cli("map")
        self.assertEqual((r.returncode, r.stdout), (2, ""))
        self.assertTrue(r.stderr.startswith("janus map: "), r.stderr)
        self.assertIn("doors.json: 1 error; run `janus check-config`.", r.stderr)
        self.assertEqual(len(r.stderr.splitlines()), 1)
        self.assertEqual(snapshot(self.tmp), before)

    def test_help_names_both_flags(self):
        r = self.realm.cli("map", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--json", r.stdout)
        self.assertIn("--once", r.stdout)

    @unittest.skipUnless(fcntl, "runs are serialised with flock, which this platform doesn't have")
    def test_two_runs_never_overlap(self):
        self.world()
        with mapper.locked():
            p = subprocess.Popen([sys.executable, "-m", "janus", "map"], cwd=ROOT, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
            self.addCleanup(p.kill)
            with self.assertRaises(subprocess.TimeoutExpired):
                p.wait(1.5)                     # it waits for the run that holds the lock
            self.assertFalse((self.state / "map.json").exists())
        out, err = p.communicate(timeout=30)
        self.assertEqual((p.returncode, err), (0, ""))
        self.assertTrue((self.state / "map.json").exists())


class MapSpeedTest(MapCase):
    """#11's done-means: a full run against the example doors.json finishes under 1 s with every door answering and
    under 3 s with every door timing out. The example's four devices are all online here."""
    def setUp(self):
        super().setUp()
        self.realm.doors.write_text(DOORS_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
        self.tailnet_is(device("desktop", os="windows"), device("laptop"), device("phone", os="android"))

    def test_every_door_answering_takes_under_a_second(self):
        health, door = self.health(200), self.port()
        real = socket.create_connection

        def answering(address, *args, **kwargs):        # every port of the example is the one local listener
            return real(address if address[1] == health.server.server_address[1] else ("127.0.0.1", door.port), *args, **kwargs)

        with mock.patch.dict(os.environ, {"JANUS_SERVE_URL": health.url}), mock.patch("socket.create_connection", answering):
            t0 = time.monotonic()
            doc, _ = mapper.run()
            took = time.monotonic() - t0
        self.assertEqual(doc["line"], "13 doors open")
        self.assertEqual(doc["counts"], {"open": 13, "closed": 0, "unexpected": 0, "asleep": 0, "unknown": 0})
        self.assertEqual(self.run_json()["probed"], 10)
        self.assertLess(took, 1.0)

    def test_every_door_timing_out_takes_under_three_seconds(self):
        def silent(address, *args, **kwargs):
            time.sleep(kwargs.get("timeout") or 2)
            raise socket.timeout("timed out")

        mute = "http://127.0.0.1:%d" % self.port().port
        with mock.patch.dict(os.environ, {"JANUS_SERVE_URL": mute}), mock.patch("socket.create_connection", silent):
            t0 = time.monotonic()
            doc, _ = mapper.run()
            took = time.monotonic() - t0
            self.assertEqual(doc["line"], "3 doors open" + DOT + "10 not probed yet")
            self.assertEqual({d["probe"] for r in doc["rooms"] for d in r["doors"] if d["state"] == "unknown"},
                             {"connect timeout 2 s; waiting for a second probe", "health timeout 2 s; waiting for a second probe"})
            self.assertGreaterEqual(took, 2.0)
            self.assertLess(took, 3.0)
            doc, _ = mapper.run()
        self.assertEqual(doc["line"], "3 doors open" + DOT + "6 closed unexpectedly" + DOT + "4 closed")
        self.assertEqual(self.alert()["message"], "6 doors closed unexpectedly. Open the Map for their history.")


class UnitsTest(unittest.TestCase):
    """units/: the one-shot service, its timer and the limits drop-in (design §0, §6a). Nothing here installs them."""
    def unit(self, name):
        return (ROOT / "units" / name).read_text(encoding="utf-8").splitlines()

    def test_the_service_is_a_one_shot_that_runs_janus_map(self):
        lines = self.unit("janus-map.service")
        self.assertEqual(len([line for line in lines if line.startswith("Description=") and len(line) > 20]), 1)
        self.assertIn("Type=oneshot", lines)
        self.assertIn("ExecStart=%h/.local/bin/janus map", lines)
        self.assertIn("TimeoutStartSec=60", lines)      # a one-shot has no start timeout of its own: a hung run must not block the timer
        self.assertNotIn("[Install]", lines)            # the timer starts it; it is never enabled by itself

    def test_the_timer_runs_it_every_five_minutes(self):
        lines = self.unit("janus-map.timer")
        self.assertEqual(len([line for line in lines if line.startswith("Description=") and len(line) > 20]), 1)
        for line in ("OnUnitActiveSec=5min", "Persistent=false", "Unit=janus-map.service", "[Install]", "WantedBy=timers.target"):
            self.assertIn(line, lines)
        self.assertTrue([line for line in lines if line.startswith("OnBootSec=")])       # or it would never start

    def test_the_limits_drop_in(self):
        lines = self.unit("argus-limits.conf")
        for line in ("[Service]", "CPUQuota=25%", "MemoryMax=512M", "IOWeight=50", "Nice=10"):
            self.assertIn(line, lines)

    def test_the_alert_names_the_unit(self):
        self.assertTrue((ROOT / "units" / (mapper.JOB + ".service")).is_file())


if __name__ == "__main__":
    unittest.main()
