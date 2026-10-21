"""routes.json (who may send what, docs/design.md §2) and doors.json (what should be open, §6b). Load them, expand
`~` and {{PLACEHOLDERS}} from realm.json, validate them, and explain them in plain sentences (`janus check-config`).
Hermes's own routes.json is read only to warn about routes Hermes defines but Janus doesn't, because every arrival on
such a route would be quarantined."""
import fnmatch
import json
import os
import re
from pathlib import Path

from janus import kinds as kinds_module

ROUTES = "~/.config/janus/routes.json"        # or $JANUS_CONFIG (the name Hermes uses for the same file)
DOORS = "~/.config/janus/doors.json"          # or $JANUS_DOORS
HERMES_CONFIG = "~/.config/hermes/routes.json"  # or $HERMES_CONFIG
REALM = "~/.config/leafy/realm.json"          # or $LEAFY_REALM: the same file Mentor and Hermes read
REALM_DEFAULTS = {"SERVER": "homeserver", "PC": "desktop", "PHONE": "phone", "SSH": "server",
                  "HOME_PC": "C:\\Users\\you", "HOME_SERVER": "~", "REPO_URL": "https://github.com/you/argus-ui"}
PLACEHOLDER = re.compile(r"\{\{\s*(" + "|".join(REALM_DEFAULTS) + r")\s*\}\}")
ROUTE_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
ROUTE_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,30}\*$")      # torrent-*: covers torrent-movies ... torrent-games
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")        # senders, kinds, devices, doors

VIAS = ("ssh", "local", "taildrop", "elaia", "fetch")
SNIFFS = ("json", "bencode", "text", "image", "audio", "video", "document", "archive")
SHAPES = ("mentor-lesson-fields", "placeholders-known", "public-no-real-names", "magnet-uri", "deploy-request-fields",
          "archive-listing")
DESTINATIONS = ("private", "public")
EXPECTS = ("always", "when-online", "sometimes")
SENDER_KEYS = ("via", "key", "node", "users", "fetch")
KIND_KEYS = ("ext", "sniff", "max_bytes", "shape", "note")
ROUTE_KEYS = ("from", "kinds", "taildrop_kinds", "destination", "max_bytes", "same_as")
APPROVER_KEYS = ("users", "nodes", "max_age_s")
DEVICE_KEYS = ("expect", "doors", "note", "uses")
DOOR_KEYS = ("port", "serve", "health", "taildrop", "expect", "agents", "clients", "note")
MAX_AGE_DEFAULT = 120


def routes_path():
    return Path(os.path.expanduser(os.environ.get("JANUS_CONFIG") or ROUTES))


def doors_path():
    return Path(os.path.expanduser(os.environ.get("JANUS_DOORS") or DOORS))


def hermes_path():
    return Path(os.path.expanduser(os.environ.get("HERMES_CONFIG") or HERMES_CONFIG))


def realm_path():
    return Path(os.path.expanduser(os.environ.get("LEAFY_REALM") or REALM))


def realm(path=None):
    """The placeholder values: realm.json over the public defaults. A missing or broken file means the defaults."""
    try:
        with open(path or realm_path(), encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        doc = {}
    vals = dict(REALM_DEFAULTS)
    for k, v in (doc.items() if isinstance(doc, dict) else []):
        if str(k).upper() in vals and isinstance(v, (str, int, float)) and str(v).strip():
            vals[str(k).upper()] = str(v)
    return vals


def fill(text, vals, as_json=False):
    """Put the realm's values where {{SERVER}} etc. sit. as_json: text is JSON, so each value goes in escaped."""
    if "{{" not in text:
        return text
    return PLACEHOLDER.sub(lambda m: json.dumps(vals[m.group(1)])[1:-1] if as_json else vals[m.group(1)], text)


def short(path):
    """A path for people: the home folder shown as ~."""
    try:
        return "~/" + str(Path(path).relative_to(Path.home()))
    except ValueError:
        return str(path)


def size(n):
    """Bytes for people: 512 KB, 1 GB."""
    for unit, div in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= div:
            v = n / div
            return ("%d %s" if v == int(v) else "%.1f %s") % (v, unit)
    return "%d bytes" % n


def plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


class ConfigError(Exception):
    """A config file has errors; `janus check-config` lists them."""
    def __init__(self, config):
        n = len(config.errors)
        super().__init__("%s: %s; run `janus check-config`" % (config.what, plural(n, "error")))
        self.config = config


class Sender:
    """One named identity from `senders`: how it arrives (via) and what proves it."""
    def __init__(self, name, raw):
        self.name, self.raw = name, raw
        self.via = raw.get("via")
        self.key = raw.get("key", name) if self.via == "ssh" else None
        self.node = raw.get("node", name) if self.via == "ssh" else None
        self.users = list(raw.get("users", [])) if isinstance(raw.get("users"), list) else []
        self.fetch = raw.get("fetch", name[6:] if name.startswith("fetch:") else name) if self.via == "fetch" else None


class Kind:
    """One kind of file: its extensions, the content rule, the size cap and the shape rules."""
    def __init__(self, name, raw):
        self.name, self.raw = name, raw
        self.ext = [e.lower() for e in raw.get("ext", []) if isinstance(e, str)]
        self.sniff = raw.get("sniff")
        self.max_bytes = raw.get("max_bytes")
        self.shape = list(raw.get("shape", [])) if isinstance(raw.get("shape"), list) else []
        self.note = raw.get("note")


class Route:
    """One route after validation: which senders may send which kinds, and the caps."""
    def __init__(self, id, raw):
        self.id, self.raw = id, raw
        self.same_as = raw.get("same_as")
        self.senders = list(raw.get("from", [])) if isinstance(raw.get("from"), list) else []
        self.kinds = list(raw.get("kinds", [])) if isinstance(raw.get("kinds"), list) else []
        self.taildrop_kinds = raw.get("taildrop_kinds") if isinstance(raw.get("taildrop_kinds"), list) else None
        self.destination = raw.get("destination")
        self.max_bytes = raw.get("max_bytes")

    @property
    def pattern(self):
        return self.id.endswith("*")

    def kinds_for(self, via):
        """The kinds this route takes from a sender class: `taildrop_kinds` narrows the list for Taildrop."""
        if via == "taildrop" and self.taildrop_kinds is not None:
            return list(self.taildrop_kinds)
        return list(self.kinds)

    def sentence(self):
        """One plain sentence: who may send what on the route."""
        s = "%s: " % self.id
        if self.same_as:
            return s + "the same as %s." % self.same_as
        if not self.senders or not self.kinds:
            return s + "broken, see the errors."
        s += "%s may send %s" % (join(self.senders), join(self.kinds))
        if self.taildrop_kinds is not None:
            s += " (by Taildrop only %s)" % (join(self.taildrop_kinds) if self.taildrop_kinds else "nothing")
        if self.max_bytes:
            s += ", up to %s" % size(self.max_bytes)
        if self.destination:
            s += "; a %s destination" % self.destination
        return s + "."


class Door:
    """One door of a device: a port, a `tailscale serve` path, or Taildrop."""
    def __init__(self, device, name, raw):
        self.device, self.name, self.raw = device, name, raw
        self.port = raw.get("port")
        self.serve = raw.get("serve") is True
        self.health = raw.get("health")
        self.taildrop = raw.get("taildrop") is True
        self.expect = raw.get("expect")
        self.agents = list(raw.get("agents", [])) if isinstance(raw.get("agents"), list) else []
        self.clients = list(raw.get("clients", [])) if isinstance(raw.get("clients"), list) else []
        self.note = raw.get("note")

    def label(self):
        if self.taildrop:
            return "%s (Taildrop)" % self.name
        if self.serve:
            return "%s (serve %s)" % (self.name, self.health or "/")
        return "%s %s" % (self.name, self.port)


class Device:
    """One room of the map: a device, what to expect of it, and its doors."""
    def __init__(self, name, raw):
        self.name, self.raw = name, raw
        self.expect = raw.get("expect")
        self.doors = {}
        self.note = raw.get("note")
        self.uses = list(raw.get("uses", [])) if isinstance(raw.get("uses"), list) else []

    def sentence(self):
        doors = ", ".join(d.label() + (" (%s)" % d.expect if d.expect else "") for d in self.doors.values())
        return "%s (%s): %s." % (self.name, self.expect or "?", doors or "no doors")


def join(items):
    items = [str(i) for i in items]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


class Config:
    """A read routes.json (senders, kinds, routes, approvers) and doors.json (devices), plus the errors and warnings."""
    def __init__(self, path, doors=None):
        self.path, self.doors_path = path, doors
        self.senders, self.kinds, self.routes, self.approvers, self.devices = {}, {}, {}, {}, {}
        self.errors, self.warnings = [], []
        self.what = short(path)

    @property
    def ok(self):
        return not self.errors

    def explain(self):
        lines = [r.sentence() for r in self.routes.values()]
        lines += [d.sentence() for d in self.devices.values()]
        return lines

    def route(self, rid):
        """The route an arrival's route id means: an exact route, or the one a pattern (torrent-*) stands for."""
        r = self.routes.get(rid)
        if r is None:
            for p in self.routes.values():
                if p.pattern and fnmatch.fnmatchcase(rid, p.id):
                    r = p
                    break
        while r is not None and r.same_as:
            r = self.routes.get(r.same_as)
        return r

    def sender_by_key(self, key):
        """The ssh sender whose Hermes key name this is."""
        for s in self.senders.values():
            if s.via == "ssh" and s.key == key:
                return s
        return None

    def sender_by_fetch(self, job):
        for s in self.senders.values():
            if s.via == "fetch" and s.fetch == job:
                return s
        return None

    def senders_via(self, via):
        return [s for s in self.senders.values() if s.via == via]


def _read(path, cfg, vals, example):
    """A JSON object from a file with its placeholders filled, or None after recording the error."""
    err = cfg.errors.append
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        err("%s: cannot read it (%s). Copy examples/%s there and fill it in." % (short(path), e.strerror, example))
        return None
    try:
        doc = json.loads(fill(text, vals, as_json=True))
    except ValueError as e:
        err("%s: not valid JSON (%s). Look for a missing comma, quote or bracket near that line." % (short(path), e))
        return None
    if not isinstance(doc, dict):
        err("%s: the file must hold one JSON object, like examples/%s." % (short(path), example))
        return None
    if doc.get("version") != 1:
        err("%s: version must be 1 (the only version this Janus reads), not %r." % (short(path), doc.get("version")))
    return doc


def check(path=None, doors=None, hermes=None, vals=None):
    """Read and validate routes.json and doors.json without raising: the Config carries errors and warnings, in plain
    words. doors=False skips doors.json; hermes=False skips the Hermes warning."""
    cfg = Config(Path(path or routes_path()), None if doors is False else Path(doors or doors_path()))
    vals = vals or realm()
    doc = _read(cfg.path, cfg, vals, "routes.example.json")
    if doc is not None:
        _check_routes(cfg, doc)
    if cfg.doors_path is not None:
        ddoc = _read(cfg.doors_path, cfg, vals, "doors.example.json")
        if ddoc is not None:
            _check_doors(cfg, ddoc)
    if hermes is not False:
        _check_hermes(cfg, Path(hermes or hermes_path()))
    return cfg


def load(path=None, doors=False, hermes=False):
    """Read and validate the config for the commands that judge; raises ConfigError when it has errors."""
    cfg = check(path, doors=doors, hermes=hermes)
    if cfg.errors:
        raise ConfigError(cfg)
    return cfg


def _unknown(cfg, where, raw, allowed):
    for k in sorted(set(raw) - set(allowed)):
        cfg.warnings.append("%s: unknown setting %r is ignored (the settings are %s)." % (where, k, ", ".join(allowed)))


def _names(raw, key):
    v = raw.get(key)
    return isinstance(v, list) and v and all(isinstance(i, str) and i.strip() for i in v)


def _check_routes(cfg, doc):
    err, warn = cfg.errors.append, cfg.warnings.append
    senders = doc.get("senders")
    if not isinstance(senders, dict) or not senders:
        err('senders: must map at least one sender name to an identity, e.g. "{{PC}}": { "via": "ssh" }.')
        senders = {}
    for name, raw in senders.items():
        where = "senders.%s" % name
        if not NAME.match(str(name)):
            err("%s: a sender name is letters, digits, dots, dashes and colons, 64 characters at most." % where)
            continue
        if not isinstance(raw, dict):
            err('%s: must be an object with "via".' % where)
            continue
        _unknown(cfg, where, raw, SENDER_KEYS)
        s = Sender(name, raw)
        if s.via not in VIAS:
            err('%s: "via" must be one of %s, not %r.' % (where, ", ".join(VIAS), s.via))
            continue
        if s.via == "ssh" and not (isinstance(s.key, str) and s.key.strip() and isinstance(s.node, str) and s.node.strip()):
            err('%s: an ssh sender needs "key" (its Hermes key name) and "node" (its Tailscale name), as text.' % where)
            continue
        if s.via == "elaia" and not _names(raw, "users"):
            err('%s: an elaia sender needs "users", a list of tailnet logins allowed to send.' % where)
            continue
        if s.via == "fetch" and not (isinstance(s.fetch, str) and s.fetch.strip()):
            err('%s: a fetch sender needs "fetch", the Hermes fetch job name.' % where)
            continue
        cfg.senders[name] = s
    for via in ("ssh",):
        keys = {}
        for s in cfg.senders_via(via):
            if s.key in keys:
                err("senders.%s and senders.%s both use the ssh key %r; one key proves one device." % (keys[s.key], s.name, s.key))
            keys.setdefault(s.key, s.name)

    kinds = doc.get("kinds")
    if not isinstance(kinds, dict) or not kinds:
        err('kinds: must map at least one kind name to its rules, e.g. "image": { "ext": [".png"], "sniff": "image", '
            '"max_bytes": 52428800 }.')
        kinds = {}
    for name, raw in kinds.items():
        _check_kind(cfg, str(name), raw)

    routes = doc.get("routes")
    if not isinstance(routes, dict) or not routes:
        err('routes: must map at least one route id to a route, e.g. "lesson": { "from": ["{{PC}}"], "kinds": ["mentor-lesson"] }.')
        routes = {}
    for rid, raw in routes.items():
        _check_route(cfg, str(rid), raw, set(senders), set(kinds), set(routes))

    approvers = doc.get("approvers", {})
    if not isinstance(approvers, dict):
        err('approvers: must map approver names to { "users": [...], "nodes": [...], "max_age_s": 120 }.')
        approvers = {}
    for name, raw in approvers.items():
        where = "approvers.%s" % name
        if not isinstance(raw, dict):
            err('%s: must be an object with "users" and "nodes".' % where)
            continue
        _unknown(cfg, where, raw, APPROVER_KEYS)
        if not _names(raw, "users") or not _names(raw, "nodes"):
            err('%s: needs "users" (tailnet logins) and "nodes" (device names), each a non-empty list of text.' % where)
            continue
        age = raw.get("max_age_s", MAX_AGE_DEFAULT)
        if isinstance(age, bool) or not isinstance(age, int) or age <= 0:
            err('%s: "max_age_s" must be a whole number of seconds above 0, not %r.' % (where, age))
            continue
        cfg.approvers[name] = {"users": list(raw["users"]), "nodes": list(raw["nodes"]), "max_age_s": age}


def _check_kind(cfg, name, raw):
    err, warn = cfg.errors.append, cfg.warnings.append
    where = "kinds.%s" % name
    if not NAME.match(name):
        err("%s: a kind name is letters, digits, dots, dashes and colons, 64 characters at most." % where)
        return
    if not isinstance(raw, dict):
        err('%s: must be an object with "ext" and "max_bytes".' % where)
        return
    _unknown(cfg, where, raw, KIND_KEYS)
    k = Kind(name, raw)
    ext = raw.get("ext")
    if not isinstance(ext, list) or not ext or not all(isinstance(e, str) and e.startswith(".") and len(e) > 1
                                                         and not any(c.isspace() or c in "/\\" for c in e) for e in ext):
        err('%s: "ext" must be a non-empty list of file endings that start with a dot, such as [".png", ".jpg"].' % where)
        return
    for e in ext:
        refused = kinds_module.executable_extension(e)
        if refused:
            err("%s: %s is an executable or script ending, which Janus refuses on every route; no kind may list it. "
                "Remove it from the list." % (where, e))
            return
    if k.sniff is not None and k.sniff not in SNIFFS:
        err('%s: "sniff" must be one of %s, not %r.' % (where, ", ".join(SNIFFS), k.sniff))
        return
    if isinstance(k.max_bytes, bool) or not isinstance(k.max_bytes, int) or k.max_bytes <= 0:
        err('%s: "max_bytes" must be a whole number of bytes above 0, not %r.' % (where, k.max_bytes))
        return
    if "shape" in raw and (not isinstance(raw["shape"], list) or not all(s in SHAPES for s in raw["shape"])):
        err('%s: "shape" must be a list of shape rules from %s.' % (where, ", ".join(SHAPES)))
        return
    if "note" in raw and not isinstance(raw["note"], str):
        err('%s: "note" must be text.' % where)
        return
    cfg.kinds[name] = k


def _check_route(cfg, rid, raw, senders, kinds, routes):
    err, warn = cfg.errors.append, cfg.warnings.append
    where = "route %s" % rid
    if not (ROUTE_ID.match(rid) or ROUTE_PATTERN.match(rid)):
        err("%s: route ids are lowercase letters, digits and dashes, start with a letter and are 32 characters at "
            "most (e.g. torrent-movies); a pattern ends in * (torrent-*)." % where)
        return
    if not isinstance(raw, dict):
        err('%s: must be an object with "from" and "kinds", or "same_as".' % where)
        return
    _unknown(cfg, where, raw, ROUTE_KEYS)
    r = Route(rid, raw)
    if r.same_as is not None:
        target = routes - {rid}
        if r.same_as not in target:
            err('%s: "same_as" must name another route, not %r.' % (where, r.same_as))
            return
        if len(raw) > 1:
            warn('%s: with "same_as", the other settings are ignored; %s decides.' % (where, r.same_as))
        cfg.routes[rid] = r
        return
    if not _names(raw, "from"):
        err('%s: "from" must list at least one sender name from senders.' % where)
        return
    unknown = [s for s in r.senders if s not in senders]
    if unknown:
        err("%s: \"from\" names %s, which %s not defined under senders." % (where, join(unknown), "is" if len(unknown) == 1 else "are"))
        return
    if not _names(raw, "kinds"):
        err('%s: "kinds" must list at least one kind name from kinds.' % where)
        return
    unknown = [k for k in r.kinds if k not in kinds]
    if unknown:
        err("%s: \"kinds\" names %s, which %s not defined under kinds." % (where, join(unknown), "is" if len(unknown) == 1 else "are"))
        return
    if "taildrop_kinds" in raw:
        tk = raw["taildrop_kinds"]
        if not isinstance(tk, list) or not all(isinstance(k, str) for k in tk):
            err('%s: "taildrop_kinds" must be a list of kind names (a subset of "kinds").' % where)
            return
        extra = [k for k in tk if k not in r.kinds]
        if extra:
            err('%s: "taildrop_kinds" names %s, which the route\'s "kinds" don\'t include.' % (where, join(extra)))
            return
        if not any(cfg.senders[s].via == "taildrop" for s in r.senders if s in cfg.senders):
            warn('%s: "taildrop_kinds" is set but no taildrop sender is in "from", so it never applies.' % where)
    if "destination" in raw and raw["destination"] not in DESTINATIONS:
        err('%s: "destination" must be private or public, not %r.' % (where, raw["destination"]))
        return
    if "max_bytes" in raw and (isinstance(r.max_bytes, bool) or not isinstance(r.max_bytes, int) or r.max_bytes <= 0):
        err('%s: "max_bytes" must be a whole number of bytes above 0, not %r.' % (where, r.max_bytes))
        return
    cfg.routes[rid] = r


def _check_doors(cfg, doc):
    err, warn = cfg.errors.append, cfg.warnings.append
    devices = doc.get("devices")
    if not isinstance(devices, dict) or not devices:
        err('devices: must map at least one device name to { "expect": "always", "doors": { ... } }.')
        return
    for name, raw in devices.items():
        where = "devices.%s" % name
        if not NAME.match(str(name)):
            err("%s: a device name is letters, digits, dots, dashes and colons, 64 characters at most." % where)
            continue
        if not isinstance(raw, dict):
            err('%s: must be an object with "expect" and "doors".' % where)
            continue
        _unknown(cfg, where, raw, DEVICE_KEYS)
        d = Device(name, raw)
        if d.expect not in EXPECTS:
            err('%s: "expect" must be one of %s, not %r.' % (where, ", ".join(EXPECTS), d.expect))
            continue
        doors = raw.get("doors")
        if not isinstance(doors, dict):
            err('%s: "doors" must be an object (empty for a device with no doors).' % where)
            continue
        if "note" in raw and not isinstance(raw["note"], str):
            err('%s: "note" must be text.' % where)
            continue
        if "uses" in raw and not (isinstance(raw["uses"], list) and all(isinstance(u, str) for u in raw["uses"])):
            err('%s: "uses" must be a list of door names.' % where)
            continue
        ok = True
        for dname, draw in doors.items():
            door = _check_door(cfg, name, str(dname), draw)
            if door is None:
                ok = False
            else:
                d.doors[dname] = door
        if ok:
            cfg.devices[name] = d


def _check_door(cfg, device, name, raw):
    err = cfg.errors.append
    where = "devices.%s.doors.%s" % (device, name)
    if not NAME.match(name):
        err("%s: a door name is letters, digits, dots, dashes and colons, 64 characters at most." % where)
        return None
    if not isinstance(raw, dict):
        err('%s: must be an object with "port", "serve": true or "taildrop": true.' % where)
        return None
    _unknown(cfg, where, raw, DOOR_KEYS)
    door = Door(device, name, raw)
    ways = [w for w, on in (("port", door.port is not None), ("serve", door.serve), ("taildrop", door.taildrop)) if on]
    if len(ways) != 1:
        err('%s: needs exactly one of "port", "serve": true or "taildrop": true (found %s).' % (where, join(ways) or "none"))
        return None
    if door.port is not None and (isinstance(door.port, bool) or not isinstance(door.port, int) or not 1 <= door.port <= 65535):
        err('%s: "port" must be a whole number from 1 to 65535, not %r.' % (where, door.port))
        return None
    if door.serve and not (isinstance(door.health, str) and door.health.startswith("/")):
        err('%s: a serve door needs "health", the path to GET, starting with /.' % where)
        return None
    if door.expect is not None and door.expect not in EXPECTS:
        err('%s: "expect" must be one of %s, not %r.' % (where, ", ".join(EXPECTS), door.expect))
        return None
    for key in ("agents", "clients"):
        if key in raw and not (isinstance(raw[key], list) and all(isinstance(i, str) for i in raw[key])):
            err('%s: "%s" must be a list of names.' % (where, key))
            return None
    if "note" in raw and not isinstance(raw["note"], str):
        err('%s: "note" must be text.' % where)
        return None
    return door


def _check_hermes(cfg, path):
    """Warn about routes Hermes defines but Janus doesn't: every arrival on them would be quarantined."""
    if not path.is_file():
        return
    try:
        hroutes = json.loads(path.read_text(encoding="utf-8"))["routes"]
        if not isinstance(hroutes, dict):
            raise TypeError
    except (OSError, ValueError, KeyError, TypeError):
        cfg.warnings.append("%s: cannot read Hermes's routes from it, so Hermes's routes were not compared with Janus's."
                            % short(path))
        return
    missing = [rid for rid in hroutes if cfg.route(str(rid)) is None]
    if missing:
        one = len(missing) == 1
        cfg.warnings.append("Hermes's %s defines route%s %s, which Janus doesn't: every arrival on %s would be "
                            "quarantined. Add %s to %s." % (short(path), "" if one else "s", join(missing),
                                                            "it" if one else "them", "it" if one else "them", cfg.what))
