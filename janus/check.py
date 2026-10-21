"""janus check: the door, check by check (docs/design.md §3). Janus reads the arrival (meta.json and data) and never
writes inside it. The four checks (route, kind, shape, integrity) always all run, so one verdict lists every reason.
Exit 0 pass · 10 quarantine · 11 duplicate · 2 Janus failed (bad config, whois unavailable, I/O error: Hermes holds)."""
import json
import os
import time
from pathlib import Path

from janus import config, identity, kinds, shapes, version

EXIT = {"pass": 0, "quarantine": 10, "duplicate": 11, "fail": 2}
CHECKS = ("route", "kind", "shape", "integrity")
VIAS = ("ssh", "taildrop", "elaia", "fetch", "local")


class Failed(Exception):
    """Janus could not judge (exit 2): the arrival waits in Hermes's held/ and is tried again."""


class Verdict:
    """What `janus check` prints: the verdict, the per-check results, the reasons and the notes."""
    def __init__(self):
        self.checks = {c: "ok" for c in CHECKS}
        self.reasons, self.notes = [], []
        self.sha256 = self.kind = None
        self.duplicate = False
        self.started = time.monotonic()

    def fail(self, check, reason):
        """One check failed for one reason; the others still run."""
        self.checks[check] = "fail"
        self.reasons.append(reason)

    @property
    def verdict(self):
        if any(v == "fail" for v in self.checks.values()):
            return "quarantine"
        return "duplicate" if self.duplicate else "pass"

    def as_dict(self):
        return {"verdict": self.verdict, "janus": version(), "sha256": self.sha256, "kind": self.kind,
                "checks": dict(self.checks), "reasons": list(self.reasons), "notes": list(self.notes),
                "ms": int((time.monotonic() - self.started) * 1000)}


class Arrival:
    """One arrival folder from Hermes: its meta.json, read once, and the data path. Never written to."""
    def __init__(self, folder):
        self.folder = Path(folder)
        self.meta = self.read_meta()
        self.data = self.folder / "data"
        self.sender = self.meta.get("sender") if isinstance(self.meta.get("sender"), dict) else {}
        self.route_id = str(self.meta.get("route") or "")
        self.name = str(self.meta.get("name") or self.meta.get("id") or "the file")
        self.direction = str(self.meta.get("direction") or "in")

    def read_meta(self):
        try:
            with open(self.folder / "meta.json", encoding="utf-8") as f:
                meta = json.load(f)
        except OSError as e:
            raise Failed("cannot read %s (%s)" % (self.folder / "meta.json", e.strerror or e))
        except ValueError as e:
            raise Failed("%s is not JSON (%s)" % (self.folder / "meta.json", e))
        if not isinstance(meta, dict):
            raise Failed("%s does not hold a JSON object" % (self.folder / "meta.json"))
        return meta


class Context:
    """What the checks share: the arrival, the config, who looked up whois, and what check 1 found."""
    def __init__(self, arrival, cfg, env=None):
        self.arrival, self.cfg = arrival, cfg
        self.env = dict(env if env is not None else os.environ)
        self.whois = identity.Whois(self.env)
        self.route = self.sender = None        # set by check_route when the route and the sender resolve
        self.kind = None                       # set by check_kind when a kind matches
        self.via = arrival.sender.get("via")


# ---------- check 1: route and sender ----------

def who(ctx):
    """The sender for a sentence: the resolved sender's name, else what the arrival says."""
    if ctx.sender is not None:
        return ctx.sender.name
    s = ctx.arrival.sender
    return str(s.get("key") or s.get("fetch") or s.get("user") or s.get("via") or "the sender")


def resolve_sender(ctx):
    """Who sent it, by class, proven the way the class allows. Returns (Sender, reason): one of them is None."""
    cfg, s, via = ctx.cfg, ctx.arrival.sender, ctx.via
    if via not in VIAS:
        return None, ("The arrival's sender has no known way in (via %r); Hermes records ssh, taildrop, elaia, fetch or "
                      "local." % (via,))
    if via == "ssh":
        key = s.get("key")
        if not isinstance(key, str) or not key:
            return None, "The arrival names no ssh key, so Janus can't tell which device sent it."
        sender = cfg.sender_by_key(key)
        if sender is None:
            return None, "No sender in %s uses the ssh key named %s." % (cfg.what, key)
        ip = s.get("ip")
        if not isinstance(ip, str) or not ip.strip():
            return None, ("The arrival records no tailnet address for %s, so Tailscale can't confirm who sent it."
                          % sender.name)
        try:
            answer = ctx.whois(ip)
        except identity.Unavailable as e:
            raise Failed(str(e))
        if answer["node"] != sender.node:
            return None, "The ssh key says %s but Tailscale says %s." % (sender.name, answer["node"])
        return sender, None
    if via == "taildrop":
        senders = cfg.senders_via("taildrop")
        if not senders:
            return None, "No taildrop sender is defined in %s, so nothing can come in by Taildrop." % cfg.what
        return senders[0], None
    if via == "elaia":
        senders = cfg.senders_via("elaia")
        if not senders:
            return None, "No elaia sender is defined in %s, so nothing can come in from Elaia." % cfg.what
        user = s.get("user")
        if not isinstance(user, str) or not user:
            return None, "The arrival from Elaia names no tailnet login, so Janus can't tell who sent it."
        for sender in senders:
            if user in sender.users:
                return sender, None
        return None, "%s may not send through Elaia (the allowed logins are in %s)." % (user, cfg.what)
    if via == "fetch":
        job = s.get("fetch")
        if not isinstance(job, str) or not job:
            return None, "The arrival names no fetch job, so Janus can't tell which fetch brought it."
        sender = cfg.sender_by_fetch(job)
        if sender is None:
            return None, "No sender in %s is the fetch job named %s." % (cfg.what, job)
        return sender, None
    senders = cfg.senders_via("local")
    if not senders:
        return None, "No local sender (the server itself) is defined in %s." % cfg.what
    return senders[0], None


def check_route(ctx, v):
    """Check 1: the route exists, the sender is who Tailscale says, the direction fits, and the route allows the sender."""
    a, cfg = ctx.arrival, ctx.cfg
    route = cfg.route(a.route_id) if a.route_id else None
    if route is None:
        v.fail("route", "Janus knows no route named %s, so nothing can arrive on it; add it to %s if it should exist."
               % (a.route_id or "(none)", cfg.what))
    ctx.sender, reason = resolve_sender(ctx)
    if reason:
        v.fail("route", reason)
    if a.direction not in ("in", "out"):
        v.fail("route", "The arrival's direction is %r; Hermes records in or out." % (a.direction,))
    elif ctx.sender is not None:
        if a.direction == "out" and ctx.sender.via not in ("local", "elaia"):
            v.fail("route", "An outbound delivery must come from the server itself or from Elaia, not from %s by %s."
                   % (ctx.sender.name, ctx.sender.via))
        if a.direction == "in" and ctx.sender.via == "local":
            v.fail("route", "%s is the server itself, which can't be the sender of an incoming delivery." % ctx.sender.name)
    if route is not None and ctx.sender is not None and ctx.sender.name not in route.senders:
        v.fail("route", "%s may not send on the %s route (it takes files from %s)."
               % (ctx.sender.name, a.route_id, config.join(route.senders)))
    ctx.route = route


# ---------- check 2: kind ----------

def check_kind(ctx, v):
    """Check 2: executables refused first (in code), then the ending must be an allowed kind for the route (the Taildrop
    list for Taildrop) and the content must pass that kind's sniff. Sets v.kind and ctx.kind when a kind matches."""
    a, cfg = ctx.arrival, ctx.cfg
    name = a.name
    ctx.kind = None
    try:
        size = a.data.stat().st_size
        head = kinds.read_head(a.data)
    except OSError as e:
        raise Failed("cannot read %s (%s)" % (a.data, e.strerror or e))
    reason = kinds.refused_name(name) or kinds.refused_content(name, head)
    if reason:
        v.fail("kind", reason)
    route = ctx.route
    allowed = route.kinds_for(ctx.via) if route is not None else list(cfg.kinds)
    # the ending, judged against every kind the config knows, so the sentence can say what the route lacks
    all_exts = {e for k in cfg.kinds.values() for e in k.ext}
    ext = kinds.ext_of(name, all_exts)
    if ext is None:
        if not reason:
            v.fail("kind", "No kind in %s has files ending like %s, so it can't arrive on any route." % (cfg.what, name))
        return
    with_ext = [k for k in cfg.kinds.values() if ext in k.ext]
    candidates = [cfg.kinds[n] for n in allowed if n in cfg.kinds and ext in cfg.kinds[n].ext]   # in the route's order
    if not candidates:
        if route is not None and ctx.via == "taildrop" and any(k.name in route.kinds for k in with_ext):
            v.fail("kind", "%s is %s, which the %s route doesn't take by Taildrop (by Taildrop it takes only %s); send "
                   "it from a keyed device instead." % (name, an(with_ext[0].name), route.id, config.join(allowed) or "nothing"))
        elif route is not None:
            v.fail("kind", "%s is %s, which the %s route doesn't take (it takes %s)."
                   % (name, an(with_ext[0].name), route.id, config.join(allowed)))
        return
    for k in candidates:
        if k.sniff is None or kinds.sniff(k.sniff, a.data, name, ext, head, size):
            ctx.kind = k
            v.kind = k.name
            if k.note:
                v.notes.append("%s %s (%s)." % (k.name.replace("-", " "), k.note, ext))
            return
    k = candidates[0]
    ctx.kind = k
    v.kind = k.name
    v.fail("kind", "%s isn't %s inside." % (name, an(kinds.label(ext, k.sniff))))


def an(word):
    return ("an " if word[:1].lower() in "aeiou" else "a ") + word


# ---------- check 3: shape (size here; the shape rules come with issue #5) ----------

def check_size(ctx, v):
    """The size cap of the kind and of the route (design §3 check 3, first line)."""
    a = ctx.arrival
    size = a.data.stat().st_size
    if ctx.kind is not None and ctx.kind.max_bytes is not None and size > ctx.kind.max_bytes:
        v.fail("shape", "%s is %s, over the %s cap for %s files."
               % (a.name, config.size(size), config.size(ctx.kind.max_bytes), ctx.kind.name))
    if ctx.route is not None and ctx.route.max_bytes is not None and size > ctx.route.max_bytes:
        v.fail("shape", "%s is %s, over the %s cap of the %s route."
               % (a.name, config.size(size), config.size(ctx.route.max_bytes), ctx.route.id))


def check_shape(ctx, v):
    """Check 3, the rules: the kind's `shape` list, every rule in order (shapes.py; archive-listing comes with #7)."""
    if ctx.kind is None:
        return
    a = ctx.arrival
    for rule in ctx.kind.shape:
        fn = shapes.RULES.get(rule)
        if fn is None:
            raise Failed("the %s shape rule is not built yet (issue #7); the arrival waits" % rule)
        try:
            reasons = fn(a.name, a.data, ctx.route, ctx.env)
        except OSError as e:
            raise Failed("cannot read %s (%s)" % (a.data, e.strerror or e))
        for r in reasons:
            v.fail("shape", r)


# ---------- check 4 comes with issue #6 ----------

NOT_BUILT = {"integrity": 6}


def check_rest(ctx, v):
    """Until every check is built, a verdict can never be a pass: a quarantine stands, but anything else is "Janus
    failed" (exit 2) and Hermes holds the arrival."""
    for c in NOT_BUILT:
        if v.checks[c] == "ok":
            v.checks[c] = "not-built"
    if v.verdict != "quarantine":
        names = sorted(NOT_BUILT)
        raise Failed("the %s check%s not built yet (issue%s %s); the arrival waits"
                     % (config.join(names), " is" if len(names) == 1 else "s are", "" if len(names) == 1 else "s",
                        ", ".join("#%d" % NOT_BUILT[c] for c in names)))


# ---------- the run ----------

def run(folder, cfg=None, env=None):
    """Check one arrival: (exit code, verdict dict). Raises Failed when Janus itself could not judge."""
    v = Verdict()
    if cfg is None:
        try:
            cfg = config.load(env and env.get("JANUS_CONFIG"))
        except config.ConfigError as e:
            raise Failed(str(e))
    arrival = Arrival(folder)
    if not arrival.data.exists():
        raise Failed("%s has no data" % arrival.folder)
    ctx = Context(arrival, cfg, env)
    check_route(ctx, v)
    check_kind(ctx, v)
    check_size(ctx, v)
    check_shape(ctx, v)
    check_rest(ctx, v)
    return EXIT[v.verdict], v.as_dict()


def main(args):
    """janus check [--json] <arrival>: the verdict on stdout, exit 0 / 10 / 11, or 2 with the failure on stderr."""
    import sys
    try:
        code, doc = run(args.arrival)
    except Failed as e:
        print("janus check: %s" % e, file=sys.stderr)
        if args.json:
            print(json.dumps({"verdict": "fail", "janus": version(), "sha256": None, "kind": None, "checks": {},
                              "reasons": ["Janus failed: %s." % e], "notes": [], "ms": 0}))
        return 2
    if args.json:
        print(json.dumps(doc))
    else:
        print("%s: %s" % (doc["verdict"], args.arrival))
        for r in doc["reasons"]:
            print("  " + r)
        for n in doc["notes"]:
            print("  note: " + n)
    return code
