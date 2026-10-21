"""`janus verify-approval`: the second face, for Zeus (docs/design.md §4; zeus docs/contract.md §5).

Zeus writes one JSON object to stdin: {"action", "repo", "sha" | "arrival", "user" | null, "ip", "when", "via"}. Janus
answers "is this person, on this device, allowed to approve this, now?" — and nothing else: the request's freshness
in Zeus's queue, its signature and the deploy are Zeus's. Exit 0 allowed · 10 refused · 2 Janus failed. One JSON object
on stdout either way; one line in log/approvals-YYYY-MM.jsonl either way."""
import json
import re
import sys
from datetime import datetime

from janus import config, identity, log, version

ACTIONS = ("deploy", "rollback", "release")
APPROVER = "zeus"
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
ARRIVAL = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{4,16}$")
IP = re.compile(r"^[0-9A-Fa-f:.]{3,45}$")
VIAS = ("elaia", "ssh")
MAX_INPUT = 4096


def parse_when(text):
    """An ISO 8601 time with an offset (or Z). A naive time is taken as local time."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("missing")
    t = text.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    d = datetime.fromisoformat(t)
    return d if d.tzinfo else d.astimezone()


def well_formed(req):
    """Checks that need no tailnet: the shape of the request. Returns the reasons (empty when fine)."""
    if not isinstance(req, dict):
        return ["The request must be one JSON object."]
    reasons = []
    action = req.get("action")
    if action not in ACTIONS:
        reasons.append("The action must be one of %s." % ", ".join(ACTIONS))
    if action in ("deploy", "rollback"):
        if not (isinstance(req.get("repo"), str) and REPO.match(req["repo"])):
            reasons.append("The repository must be written owner/name.")
        if not (isinstance(req.get("sha"), str) and SHA.match(req["sha"])):
            reasons.append("The commit must be a full 40-character sha.")
    elif action == "release":
        if not (isinstance(req.get("arrival"), str) and ARRIVAL.match(req["arrival"])):
            reasons.append("A release names a Hermes arrival id (date-time-hex).")
    via = req.get("via", "elaia")
    if via not in VIAS:
        reasons.append("via must be elaia or ssh.")
    user = req.get("user")
    if user is not None and not (isinstance(user, str) and user.strip()):
        reasons.append("The user must be a tailnet login, or null over ssh.")
    if user is None and via != "ssh":
        reasons.append("A request from the page must name the user it saw; only an ssh approval leaves the user to Janus.")
    if not (isinstance(req.get("ip"), str) and IP.match(req["ip"]) and not req["ip"].startswith("-")):
        reasons.append("The client address must be an IP address.")
    try:
        parse_when(req.get("when"))
    except ValueError:
        reasons.append("when must be an ISO 8601 time.")
    return reasons


def verify(req, cfg=None, now=None, whois=None):
    """The decision. Returns (exit code, answer)."""
    answer = {"janus": version(), "action": req.get("action") if isinstance(req, dict) else None,
              "verdict": "refused", "reasons": [], "user": None, "node": None}
    reasons = well_formed(req)
    if reasons:
        answer["reasons"] = reasons
        return 10, answer
    try:
        cfg = cfg or config.load()
    except config.ConfigError as e:
        answer.update(verdict="failed", reasons=["Janus cannot use his routes file: %s." % e])
        return 2, answer
    rule = cfg.approvers.get(APPROVER)
    if rule is None:
        answer["reasons"] = ['routes.json has no "approvers": {"zeus": …} entry, so nobody may approve. Add one and run janus check-config.']
        return 10, answer
    now = now or datetime.now().astimezone()
    age = (now - parse_when(req["when"])).total_seconds()
    if age > rule["max_age_s"]:
        reasons.append("The approval is %d s old; Janus accepts one up to %d s old. Approve again." % (age, rule["max_age_s"]))
    if age < -rule["max_age_s"]:
        reasons.append("The approval is dated %d s in the future; check the clocks." % -age)
    claimed = req.get("user")
    if claimed is not None and claimed not in rule["users"]:
        reasons.append("%s may not approve for Zeus." % claimed)
    try:
        who = (whois or identity.Whois())(req["ip"])
    except identity.Unavailable as e:
        answer.update(verdict="failed", reasons=reasons + ["Janus could not ask the tailnet who is at %s: %s." % (req["ip"], e)])
        return 2, answer
    node, login = who.get("node"), who.get("login")
    answer["node"], answer["user"] = node, login
    if node not in rule["nodes"]:
        reasons.append("%s is not an approved device for Zeus." % node)
    if not login:
        reasons.append("The tailnet reports no login for %s (a tagged device cannot approve)." % node)
    elif claimed is not None and login != claimed:
        reasons.append("The page says %s but the tailnet says %s is using %s." % (claimed, login, node))
    elif claimed is None and login not in rule["users"]:
        reasons.append("%s may not approve for Zeus." % login)
    answer["reasons"] = reasons
    answer["verdict"] = "allowed" if not reasons else "refused"
    return (0 if not reasons else 10), answer


def record(req, answer):
    entry = {"action": answer.get("action"), "verdict": answer["verdict"], "reasons": answer["reasons"],
             "user": answer.get("user"), "node": answer.get("node"), "janus": answer["janus"]}
    if isinstance(req, dict):
        entry.update({k: req.get(k) for k in ("repo", "sha", "arrival", "ip", "via", "when") if k in req})
        entry["claimed_user"] = req.get("user")
    log.write("approvals", entry)


def main(args):
    """janus verify-approval [--routes <file>]: the request on stdin, the answer on stdout, one log line."""
    raw = sys.stdin.read(MAX_INPUT + 1)
    try:
        if len(raw) > MAX_INPUT:
            raise ValueError("too long")
        req = json.loads(raw)
    except ValueError:
        answer = {"janus": version(), "action": None, "verdict": "refused", "user": None, "node": None,
                  "reasons": ["The request must be one JSON object of at most %d bytes on stdin." % MAX_INPUT]}
        print(json.dumps(answer, ensure_ascii=False))
        record(None, answer)
        return 10
    cfg = None
    if getattr(args, "routes", None):
        try:
            cfg = config.load(args.routes)
        except config.ConfigError as e:
            answer = {"janus": version(), "action": req.get("action") if isinstance(req, dict) else None, "verdict": "failed",
                      "reasons": ["Janus cannot use his routes file: %s." % e], "user": None, "node": None}
            print(json.dumps(answer, ensure_ascii=False))
            record(req, answer)
            return 2
    code, answer = verify(req, cfg)
    print(json.dumps(answer, ensure_ascii=False))
    record(req, answer)
    return code
