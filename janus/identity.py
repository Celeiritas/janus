"""Who is at the door: `tailscale whois --json <ip>` (docs/design.md §3 check 1). Janus never trusts a self-declared
node name; the node and the login come from Tailscale, for the address the arrival records. Answers are cached for
the run. A whois that fails is "Janus failed" (exit 2), never a pass: Hermes holds the arrival and tries again."""
import json
import os
import subprocess

TAILSCALE = "tailscale"       # or $JANUS_TAILSCALE (the tests point it at tests/fixtures/tailscale)
TIMEOUT = 10


class Unavailable(Exception):
    """tailscale whois gave no usable answer; the check cannot go on."""


def tailscale(env=None):
    return (env if env is not None else os.environ).get("JANUS_TAILSCALE") or TAILSCALE


class Whois:
    """whois(ip) -> {"node": "desktop", "login": "you@example.com"}, asked once per address per run."""
    def __init__(self, env=None):
        self.env = dict(env if env is not None else os.environ)
        self.cache = {}

    def __call__(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        answer = self.cache[ip] = whois(ip, self.env)
        return answer


def whois(ip, env=None):
    """One `tailscale whois --json <ip>`: the node's short name and the login that owns it. Raises Unavailable."""
    if not isinstance(ip, str) or not ip.strip() or ip.startswith("-"):
        raise Unavailable("no tailnet address to look up (%r)" % (ip,))
    env = dict(env if env is not None else os.environ)
    try:
        r = subprocess.run([tailscale(env), "whois", "--json", ip], capture_output=True, text=True, timeout=TIMEOUT, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Unavailable("tailscale whois could not run for %s (%s)" % (ip, e))
    if r.returncode != 0:
        raise Unavailable("tailscale whois gave no answer for %s (%s)" % (ip, (r.stderr or r.stdout).strip()[:200] or "exit %d" % r.returncode))
    try:
        doc = json.loads(r.stdout)
        node = doc["Node"]
        name = node.get("ComputedName") or str(node.get("Name", "")).split(".")[0]
        login = (doc.get("UserProfile") or {}).get("LoginName")
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Unavailable("tailscale whois answered for %s with something that is not a whois record" % ip)
    if not name:
        raise Unavailable("tailscale whois names no node for %s" % ip)
    return {"node": name, "login": login}
