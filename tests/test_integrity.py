"""Check 4, integrity (docs/design.md §3 check 4, §0 "large files", issue #6): the hash is always recomputed, the
size on disk must match meta.bytes, and seen.db turns the same hash on the same route into a duplicate (exit 11).
Also the verdict's shape, the verdicts log, and `janus seen`."""
import json
import os
import sqlite3
import tempfile
import tracemalloc
import unittest
from pathlib import Path

from janus import check, seen
from tests import samples
from tests.helpers import Realm, sha256, snapshot

PNG = samples.sample(".png")


class IntegrityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.r = Realm(self.tmp.name)
        self.addCleanup(self.r.stop)
        self.db = seen.db_path()

    def test_a_clean_file_passes_and_is_recorded(self):
        folder = self.r.arrival("photo.png", PNG)
        code, doc = self.r.check(folder)
        self.assertEqual(code, 0, doc)
        self.assertEqual(doc["verdict"], "pass")
        self.assertEqual(doc["sha256"], sha256(PNG))
        self.assertEqual(doc["kind"], "image")
        self.assertEqual(doc["checks"], {"route": "ok", "kind": "ok", "shape": "ok", "integrity": "ok"})
        self.assertEqual(doc["reasons"], [])
        self.assertEqual(doc["notes"], [])
        self.assertIsInstance(doc["ms"], int)
        self.assertTrue(self.db.is_file())
        store = seen.Seen(self.db)
        self.assertEqual(store.lookup(sha256(PNG), "servermail")["id"], folder.name)
        self.assertIsNone(store.lookup(sha256(PNG), "roms"))
        store.close()

    def test_the_hash_is_recomputed_never_trusted(self):
        folder = self.r.arrival("photo.png", PNG, digest="0" * 64)
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(doc["checks"]["integrity"], "fail")
        self.assertEqual(doc["reasons"], ["photo.png's checksum doesn't match what desktop declared (the transfer may have "
                                          "been cut short or changed on the way)."])
        self.assertEqual(doc["sha256"], sha256(PNG))        # what Janus hashed, not the declared one
        self.assertIsNone(seen.Seen(self.db).lookup(sha256(PNG), "servermail"))

    def test_an_upper_case_declared_hash_is_the_same_hash(self):
        code, doc = self.r.check(self.r.arrival("photo.png", PNG, digest=sha256(PNG).upper()))
        self.assertEqual(code, 0, doc)

    def test_the_size_on_disk_must_match(self):
        code, doc = self.r.check(self.r.arrival("photo.png", PNG, size=len(PNG) + 7))
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], ["photo.png is %d bytes on disk but desktop declared %d bytes." % (len(PNG), len(PNG) + 7)])
        code, doc = self.r.check(self.r.arrival("photo.png", PNG, size="lots"))
        self.assertIn("declared 'lots'.", doc["reasons"][0])

    def test_a_second_identical_file_is_a_duplicate(self):
        self.assertEqual(self.r.check(self.r.arrival("photo.png", PNG))[0], 0)
        second = self.r.arrival("photo-again.png", PNG)
        code, doc = self.r.check(second)
        self.assertEqual(code, 11)
        self.assertEqual(doc["verdict"], "duplicate")
        self.assertEqual(doc["checks"], {"route": "ok", "kind": "ok", "shape": "ok", "integrity": "ok"})
        self.assertEqual(len(doc["reasons"]), 1)
        self.assertIn("photo-again.png already arrived on the servermail route as ", doc["reasons"][0])
        r = self.r.cli("check", "--json", str(second))
        self.assertEqual(r.returncode, 11)
        self.assertEqual(json.loads(r.stdout)["verdict"], "duplicate")

    def test_the_same_file_on_another_route_is_not_a_duplicate(self):
        self.assertEqual(self.r.check(self.r.arrival("photo.png", PNG))[0], 0)
        code, doc = self.r.check(self.r.arrival("photo.png", PNG, route="phone", via="local", direction="out"))
        self.assertEqual(code, 0, doc)

    def test_a_quarantined_file_is_not_recorded_but_a_known_hash_is_noted(self):
        self.assertEqual(self.r.check(self.r.arrival("photo.png", PNG))[0], 0)
        code, doc = self.r.check(self.r.arrival("photo.png", PNG, route="roms"))
        self.assertEqual(code, 10)
        self.assertEqual(doc["checks"]["integrity"], "ok")
        self.assertEqual(len(doc["notes"]), 0)          # a different route: not seen there
        code, doc = self.r.check(self.r.arrival("photo.png", PNG, digest="0" * 64))
        self.assertEqual(code, 10)
        self.assertIn("already arrived on the servermail route", doc["notes"][0])

    def test_seen_db_missing_is_created_and_a_corrupt_one_is_janus_failed(self):
        self.assertFalse(self.db.exists())
        self.assertEqual(self.r.check(self.r.arrival("photo.png", PNG))[0], 0)
        self.assertTrue(self.db.is_file())
        self.db.write_bytes(b"this is not a database, it only says so" * 100)
        code, doc = self.r.check(self.r.arrival("photo.png", PNG))
        self.assertEqual(code, 2)
        self.assertIn("seen.db", doc["failed"])
        r = self.r.cli("check", "--json", str(self.r.arrival("photo.png", PNG)))
        self.assertEqual(r.returncode, 2)
        self.assertIn("seen.db", r.stderr)

    def test_a_one_gb_sparse_file_hashes_without_loading_it(self):
        big = self.r.stage / "big.iso"
        with open(big, "wb") as f:
            f.truncate(1 << 30)
        tracemalloc.start()
        digest = check.sha256_file(big)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(digest, "49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14")   # sha256 of 1 GiB of zeros
        self.assertLess(peak, 64 << 20)
        folder = self.r.stage / "in" / "big"
        folder.mkdir(parents=True)
        os.link(big, folder / "data")
        (folder / "meta.json").write_text(json.dumps({"id": "big", "route": "roms", "direction": "in", "name": "big.iso",
                                                      "bytes": 1 << 30, "sha256": digest,
                                                      "sender": {"via": "ssh", "key": "desktop", "node": None, "user": None,
                                                                 "ip": "192.0.2.10"}}))
        code, doc = self.r.check(folder)
        self.assertEqual(code, 0, doc)
        self.assertEqual(doc["kind"], "rom")

    def test_janus_writes_only_its_own_files(self):
        folder = self.r.arrival("photo.png", PNG)
        before = snapshot(folder)
        self.assertEqual(self.r.check(folder)[0], 0)
        self.assertEqual(snapshot(folder), before)
        state = seen.state_dir()
        self.assertEqual(sorted(p.name for p in state.iterdir()), ["log", "seen.db"])

    def test_the_verdicts_log(self):
        folder = self.r.arrival("photo.png", PNG)
        self.r.check(folder)
        self.r.check(self.r.arrival("photo.png", PNG, digest="0" * 64))
        logs = list((seen.state_dir() / "log").glob("verdicts-*.jsonl"))
        self.assertEqual(len(logs), 1)
        lines = [json.loads(l) for l in logs[0].read_text().splitlines()]
        self.assertEqual(len(lines), 2)
        first = lines[0]
        self.assertEqual(first["id"], folder.name)
        self.assertEqual(first["route"], "servermail")
        self.assertEqual(first["dir"], "in")
        self.assertEqual(first["sender"], {"via": "ssh", "key": "desktop", "node": "desktop", "user": "you@example.com",
                                           "ip": "192.0.2.10"})
        self.assertEqual(first["name"], "photo.png")
        self.assertEqual(first["sha256"], sha256(PNG))
        self.assertEqual(first["kind"], "image")
        self.assertEqual(first["verdict"], "pass")
        self.assertEqual(lines[1]["verdict"], "quarantine")
        self.assertEqual(lines[1]["checks"]["integrity"], "fail")
        for key in ("t", "checks", "reasons", "notes", "ms", "bytes"):
            self.assertIn(key, first)

    def test_a_failed_check_is_logged_too(self):
        self.r.check(self.r.arrival("photo.png", PNG), JANUS_FAKE_WHOIS="fail")
        logs = list((seen.state_dir() / "log").glob("verdicts-*.jsonl"))
        line = json.loads(logs[0].read_text().splitlines()[-1])
        self.assertEqual(line["verdict"], "fail")
        self.assertIn("Janus failed: tailscale whois", line["reasons"][0])

    def test_seen_list_and_forget(self):
        self.assertEqual(self.r.check(self.r.arrival("photo.png", PNG))[0], 0)
        r = self.r.cli("seen", "list")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(sha256(PNG), r.stdout)
        self.assertIn("1 hash seen", r.stdout)
        r = self.r.cli("seen", "forget", sha256(PNG).upper())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("forgotten on 1 route", r.stdout)
        self.assertIn("0 hashes seen", self.r.cli("seen", "list").stdout)
        self.assertEqual(self.r.check(self.r.arrival("photo.png", PNG))[0], 0)      # not a duplicate any more
        self.assertEqual(self.r.cli("seen", "forget").returncode, 2)

    def test_seen_db_keeps_one_row_per_hash_and_route(self):
        store = seen.Seen(self.db)
        store.record("a" * 64, "lesson", "one")
        store.record("a" * 64, "lesson", "two")
        self.assertEqual(store.lookup("a" * 64, "lesson")["id"], "one")
        self.assertEqual(len(store.all()), 1)
        store.close()
        self.assertEqual(sqlite3.connect(str(self.db)).execute("SELECT COUNT(*) FROM seen").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
