"""The shape rules (docs/design.md §3 check 3): what a kind's `shape` list names. Each rule reads the file and returns
plain sentences that name the file; all of a kind's rules run, in order. A rule never echoes a real name, path or
address it found inside a file (§5: nothing from inside a file is ever logged); it says what it found and on which
line. `archive-listing` lives in archives.py (issue #7)."""
import json
import os
import re
from pathlib import Path

from janus import config

DENYLIST = "~/.config/leafy/denylist.txt"      # or $LEAFY_DENYLIST: the owner's own names, one per line, never committed
PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
KNOWN = tuple(config.REALM_DEFAULTS)            # argus-ui's seven: SERVER, PC, PHONE, SSH, HOME_PC, HOME_SERVER, REPO_URL
BLANK = re.compile(r"^BLANK(_\d+)?$")           # a lesson's cloze blanks are Mentor's, not realm placeholders
LESSON_CARDS = ("tier_1_faded_code_drills", "tier_2_self_explanation_cards", "tier_3_terminology_cards",
                "faded_code_drills", "self_explanation_flashcards")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
BTIH = re.compile(r"xt=urn:btih:([0-9A-Fa-f]{40}|[A-Za-z2-7]{32})(&|$)")
REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")

# the generic patterns of scripts/check-private.sh, as it has them
OK_NAMES = {"you", "user", "username", "name", "me", "runner", "example", "your-name", "yourname", "public", "default",
            "all", "users", "shared", "<name>", "<user>"}
OK_TAILNETS = {"example", "tailnet", "your-tailnet", "tailnet-name"}
OK_MAIL_DOMAINS = {"example.com", "example.org", "example.net", "users.noreply.github.com"}
OK_ADDRESSES = {"git@github.com", "noreply@anthropic.com", "noreply@github.com"}
HOME_WIN = re.compile(r"[A-Za-z]:[\\/]+[Uu]sers[\\/]+([A-Za-z0-9_][A-Za-z0-9._-]*)")
HOME_NIX = re.compile(r"(?<![:\w])/(?:home|Users)/([A-Za-z0-9_][A-Za-z0-9._-]*)")
TAILNET = re.compile(r"([A-Za-z0-9-]+)\.ts\.net")
IPV4 = re.compile(r"(?<![0-9.A-Za-z])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![0-9A-Za-z]|\.\d)")
IPV6 = re.compile(r"(?<![0-9A-Za-z_.])([0-9A-Fa-f]{0,4}:[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:]*)(?![0-9A-Za-z_.])")
EMAIL = re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")


def denylist_path(env=None):
    return Path(os.path.expanduser((env if env is not None else os.environ).get("LEAFY_DENYLIST") or DENYLIST))


def denylist(env=None):
    """The owner's names, lower-case, or [] when there is no file (the generic patterns still run)."""
    try:
        lines = denylist_path(env).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line.lower())
    return out


def read_text(path, limit=1 << 26):
    with open(path, "rb") as f:
        return f.read(limit).decode("utf-8", "replace")


def read_json(path):
    """The file as JSON, or None when it isn't (the kind check already said so)."""
    try:
        return json.loads(read_text(path))
    except ValueError:
        return None


# ---------- the rules: rule(name, path, route, env) -> [sentences] ----------

def mentor_lesson_fields(name, path, route, env):
    doc = read_json(path)
    if not isinstance(doc, dict):
        return ["%s isn't a lesson: Mentor's lesson file is one JSON object." % name]
    out = []
    meta = doc.get("metadata")
    if not isinstance(meta, dict) or not isinstance(meta.get("module_name"), str) or not meta["module_name"].strip():
        out.append("%s has no metadata.module_name, which Mentor needs to name the lesson." % name)
    cards = [k for k in LESSON_CARDS if isinstance(doc.get(k), list) and doc[k]]
    if not cards:
        out.append("%s has no cards (no %s list with anything in it), so Mentor would import nothing."
                   % (name, config.join(LESSON_CARDS[:3])))
    for k in cards:
        bad = [i for i, c in enumerate(doc[k]) if not isinstance(c, dict)]
        if bad:
            out.append("%s: %s has an entry that isn't a card (number %d)." % (name, k, bad[0] + 1))
    return out


def placeholders_known(name, path, route, env):
    """Private destination: every {{NAME}} is one of argus-ui's seven (a lesson's {{BLANK}}s are Mentor's own)."""
    if route is None or route.destination != "private":
        return []
    text = read_text(path)
    unknown = []
    for m in PLACEHOLDER.finditer(text):
        token = m.group(1)
        if token.upper() not in KNOWN and not BLANK.match(token) and token not in unknown:
            unknown.append(token)
    if not unknown:
        return []
    return ["%s uses %s, which %s a known placeholder (Mentor fills only %s)."
            % (name, config.join("{{%s}}" % t for t in unknown), "isn't" if len(unknown) == 1 else "aren't",
               config.join("{{%s}}" % k for k in KNOWN))]


def public_no_real_names(name, path, route, env):
    """Public destination: the check-private.sh patterns plus the owner's denylist. Says what and where, never the text."""
    if route is None or route.destination != "public":
        return []
    text = read_text(path)
    deny = denylist(env)
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if "private-ok" in line:
            continue
        found = []
        for m in HOME_WIN.finditer(line):
            if m.group(1).lower() not in OK_NAMES:
                found.append("a home path (use {{HOME_PC}})")
        for m in HOME_NIX.finditer(line):
            if m.group(1).lower() not in OK_NAMES:
                found.append("a home path (use {{HOME_SERVER}})")
        for m in TAILNET.finditer(line):
            if m.group(1).lower() not in OK_TAILNETS:
                found.append("a tailnet host name (use {{SERVER}} or {{PC}})")
        for m in IPV4.finditer(line):
            if ipv4_real(m.groups()):
                found.append("an IP address")
        for m in IPV6.finditer(line):
            if ipv6_real(m.group(1)):
                found.append("an IPv6 address")
        for m in EMAIL.finditer(line):
            if m.group(0).lower() not in OK_ADDRESSES and m.group(2).lower() not in OK_MAIL_DOMAINS \
                    and not m.group(2).lower().endswith(".example"):
                found.append("an email address")
        low = line.lower()
        for i, entry in enumerate(deny, 1):
            if entry in low:
                found.append("a name from your denylist (entry %d)" % i)
        if found:
            out.append("%s has %s on line %d but goes to a public destination; replace it with a placeholder."
                       % (name, config.join(dict.fromkeys(found)), n))
    return out


def ipv4_real(octets):
    o = [int(x) for x in octets]
    if any(v > 255 for v in o) or any(len(x) > 3 for x in octets):
        return False
    if o[0] == 127 or o == [0, 0, 0, 0] or o == [255, 255, 255, 255]:
        return False
    if o[:3] in ([192, 0, 2], [198, 51, 100], [203, 0, 113]):
        return False
    return True


def ipv6_real(t):
    if ":::" in t:
        return False
    dbl = "::" in t
    if dbl and "::" in t[t.index("::") + 2:]:
        return False
    groups = t.split(":")
    full = [g for g in groups if g]
    if any(len(g) > 4 for g in full):
        return False
    if t.lower() == "::1" or re.match(r"^2001:0?db8:", t.lower()):
        return False
    if not dbl:
        return len(groups) == 8
    if not 2 <= len(full) <= 7:
        return False
    return any(len(g) >= 3 or re.search(r"[A-Fa-f]", g) for g in groups)


def magnet_uri(name, path, route, env):
    text = read_text(path).strip()
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) != 1:
        return ["%s should hold one magnet link on one line, not %d lines." % (name, len(lines))]
    link = lines[0].strip()
    if not link.startswith("magnet:?") or not BTIH.search(link):
        return ["%s isn't a magnet link (it should start with magnet:?xt=urn:btih: followed by a 40-character hex or "
                "32-character base32 hash)." % name]
    return []


def deploy_request_fields(name, path, route, env):
    """A deploy-request message as Hermes's fetch writes it (Hermes design §4): type, repo, sha, and the optional rest."""
    doc = read_json(path)
    if not isinstance(doc, dict):
        return ["%s isn't a deploy request: it should be one JSON object." % name]
    out = []
    if doc.get("type") != "deploy-request":
        out.append("%s isn't a deploy request: its type is %r, not deploy-request." % (name, doc.get("type")))
    if not isinstance(doc.get("repo"), str) or not REPO.match(doc["repo"]):
        out.append("%s: repo must be owner/name." % name)
    if not isinstance(doc.get("sha"), str) or not HEX40.match(doc["sha"]):
        out.append("%s: sha must be the commit's 40 hex characters." % name)
    if "previous" in doc and doc["previous"] is not None and not (isinstance(doc["previous"], str) and HEX40.match(doc["previous"])):
        out.append("%s: previous must be a commit's 40 hex characters, or null." % name)
    for key in ("subject", "version", "checks", "seen"):
        if key in doc and not isinstance(doc[key], str):
            out.append("%s: %s must be text." % (name, key))
    if "changelog" in doc and not (isinstance(doc["changelog"], list) and all(isinstance(l, str) for l in doc["changelog"])):
        out.append("%s: changelog must be a list of lines." % name)
    return out


RULES = {"mentor-lesson-fields": mentor_lesson_fields, "placeholders-known": placeholders_known,
         "public-no-real-names": public_no_real_names, "magnet-uri": magnet_uri,
         "deploy-request-fields": deploy_request_fields}
