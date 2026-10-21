"""seen.db: the hashes Janus has passed (docs/design.md §3 check 4, §5). SQLite at ~/.local/share/janus/seen.db
($JANUS_STATE names the folder): sha256 -> route, arrival id, first seen. The same hash on the same route is a
duplicate (exit 11). A pass records the hash; `janus seen list` and `janus seen forget <hash>` edit the store."""
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

STATE = "~/.local/share/janus"       # or $JANUS_STATE
SCHEMA = """CREATE TABLE IF NOT EXISTS seen (
  sha256 TEXT NOT NULL, route TEXT NOT NULL, id TEXT NOT NULL, first_seen TEXT NOT NULL,
  PRIMARY KEY (sha256, route))"""


class Broken(Exception):
    """seen.db cannot be used (corrupt, unreadable): Janus failed, never a pass."""


def state_dir(env=None):
    return Path(os.path.expanduser((env if env is not None else os.environ).get("JANUS_STATE") or STATE))


def db_path(env=None):
    return state_dir(env) / "seen.db"


def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class Seen:
    """The store, opened once per run; created with its table when missing."""
    def __init__(self, path=None, env=None):
        self.path = Path(path) if path else db_path(env)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(str(self.path), timeout=10)
            self.db.execute(SCHEMA)
            self.db.commit()
        except (sqlite3.Error, OSError) as e:
            raise Broken("seen.db at %s cannot be used (%s)" % (self.path, e))

    def close(self):
        self.db.close()

    def lookup(self, sha256, route):
        """The earlier arrival with this hash on this route: {"id", "first_seen"} or None."""
        try:
            row = self.db.execute("SELECT id, first_seen FROM seen WHERE sha256 = ? AND route = ?", (sha256, route)).fetchone()
        except sqlite3.Error as e:
            raise Broken("seen.db at %s cannot be read (%s)" % (self.path, e))
        return {"id": row[0], "first_seen": row[1]} if row else None

    def record(self, sha256, route, id):
        try:
            self.db.execute("INSERT OR IGNORE INTO seen (sha256, route, id, first_seen) VALUES (?, ?, ?, ?)",
                            (sha256, route, id, now()))
            self.db.commit()
        except sqlite3.Error as e:
            raise Broken("seen.db at %s cannot be written (%s)" % (self.path, e))

    def forget(self, sha256):
        """Remove a hash from every route; returns how many rows went."""
        try:
            n = self.db.execute("DELETE FROM seen WHERE sha256 = ?", (sha256,)).rowcount
            self.db.commit()
        except sqlite3.Error as e:
            raise Broken("seen.db at %s cannot be written (%s)" % (self.path, e))
        return n

    def all(self):
        try:
            rows = self.db.execute("SELECT sha256, route, id, first_seen FROM seen ORDER BY first_seen, route").fetchall()
        except sqlite3.Error as e:
            raise Broken("seen.db at %s cannot be read (%s)" % (self.path, e))
        return [{"sha256": r[0], "route": r[1], "id": r[2], "first_seen": r[3]} for r in rows]


def main(args):
    """janus seen list | forget <hash>."""
    try:
        store = Seen()
    except Broken as e:
        print("janus seen: %s" % e, file=sys.stderr)
        return 2
    try:
        if args.action == "list":
            rows = store.all()
            for r in rows:
                print("%s  %s  %s  %s" % (r["first_seen"], r["route"], r["id"], r["sha256"]))
            print("%d hash%s seen" % (len(rows), "" if len(rows) == 1 else "es"))
            return 0
        if not args.hash:
            print("janus seen forget: give the sha256 to forget", file=sys.stderr)
            return 2
        n = store.forget(args.hash.lower())
        print("janus seen: %s forgotten on %d route%s" % (args.hash, n, "" if n == 1 else "s"))
        return 0
    except Broken as e:
        print("janus seen: %s" % e, file=sys.stderr)
        return 2
    finally:
        store.close()
