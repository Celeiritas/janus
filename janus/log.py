"""Janus's records (docs/design.md §5): JSON lines, a new file each month, under ~/.local/share/janus/log/
($JANUS_STATE names the folder). verdicts-YYYY-MM.jsonl gets one line per `janus check`. Nothing from inside a file
is ever logged: names, sizes, hashes, the sender as Tailscale saw it, the per-check results and the sentences."""
import json
import sys
from datetime import datetime, timezone

from janus import seen


def now():
    return datetime.now(timezone.utc).astimezone()


def log_dir(env=None):
    return seen.state_dir(env) / "log"


def write(kind, entry, env=None):
    """Append one line to <kind>-YYYY-MM.jsonl. A log that cannot be written is said on stderr and never changes a
    verdict: the verdict is Hermes's record too (verdict.json)."""
    t = now()
    entry = {"t": t.isoformat(timespec="seconds"), **entry}
    try:
        folder = log_dir(env)
        folder.mkdir(parents=True, exist_ok=True)
        with open(folder / ("%s-%s.jsonl" % (kind, t.strftime("%Y-%m"))), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as e:
        print("janus: cannot write the %s log (%s)" % (kind, e), file=sys.stderr)
    return entry


def verdict_entry(arrival, doc, sender=None):
    """The verdicts log line for one check: what §5 lists."""
    meta, s = arrival.meta, arrival.sender
    return {"id": meta.get("id"), "route": arrival.route_id, "dir": arrival.direction,
            "sender": {"via": s.get("via"), "key": s.get("key"), "node": sender.get("node") if sender else None,
                       "user": sender.get("login") if sender else s.get("user"), "ip": s.get("ip")},
            "name": arrival.name, "bytes": meta.get("bytes"), "sha256": doc.get("sha256"), "kind": doc.get("kind"),
            "checks": doc.get("checks"), "verdict": doc.get("verdict"), "reasons": doc.get("reasons"),
            "notes": doc.get("notes"), "ms": doc.get("ms")}
