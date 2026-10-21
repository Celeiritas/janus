"""Tree arrivals (docs/design.md §3a, issue #8): data/<tree> plus manifest.json; check 1 once, checks 2-4 per file,
one verdict for the folder with the failing file named. Hermes's side (hermes#23) isn't built: these arrivals are
made by hand in the shape docs/contract.md describes."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from janus import tree
from tests import samples
from tests.helpers import PC_IP, Realm, sha256, snapshot

PNG, PDF, TXT = samples.sample(".png"), samples.sample(".pdf"), b"notes\n"


class TreeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.r = Realm(self.tmp.name)
        self.addCleanup(self.r.stop)
        self.n = 0

    def tree(self, files, name="photos", route="servermail", manifest=None, meta=None, extra_on_disk=None, symlink=None):
        """A tree arrival: files = {relative path: bytes}. manifest/meta override what Hermes would write."""
        self.n += 1
        folder = self.r.stage / "in" / ("20261021-130000-%06x" % self.n)
        data = folder / "data"
        for path, content in files.items():
            p = data / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
        for path, content in (extra_on_disk or {}).items():
            p = data / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
        if symlink:
            p = data / symlink[0]
            p.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(symlink[1], p)
        data.mkdir(parents=True, exist_ok=True)
        doc = manifest if manifest is not None else {
            "version": 1, "files": [{"path": p, "bytes": len(c), "sha256": sha256(c)} for p, c in files.items()]}
        raw = json.dumps(doc).encode()
        (folder / "manifest.json").write_bytes(raw)
        m = {"id": folder.name, "route": route, "direction": "in", "name": name, "tree": True,
             "bytes": sum(len(c) for c in files.values()), "sha256": hashlib.sha256(raw).hexdigest(),
             "sender": {"via": "ssh", "key": "desktop", "node": None, "user": None, "ip": PC_IP},
             "received": "2026-10-21T13:00:00-06:00", "hermes": "0.2.0"}
        m.update(meta or {})
        (folder / "meta.json").write_text(json.dumps(m))
        return folder

    def test_a_three_file_tree_passes(self):
        folder = self.tree({"a.png": PNG, "docs/b.pdf": PDF, "docs/c.txt": TXT})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 0, doc)
        self.assertEqual(doc["verdict"], "pass")
        self.assertEqual(doc["kind"], "tree")
        self.assertEqual(doc["checks"], {"route": "ok", "kind": "ok", "shape": "ok", "integrity": "ok"})
        self.assertEqual(doc["notes"], ["tree: 3 files (image and document)"])
        self.assertEqual(doc["sha256"], hashlib.sha256((folder / "manifest.json").read_bytes()).hexdigest())
        r = self.r.cli("check", "--json", str(folder))
        self.assertEqual(r.returncode, 11, r.stderr)          # the same manifest again: a duplicate

    def test_one_bad_file_fails_the_whole_tree_with_that_file_named(self):
        folder = self.tree({"a.png": PNG, "photos/setup.exe": samples.IMPOSTORS["exe"], "docs/c.txt": TXT})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(doc["checks"]["kind"], "fail")
        self.assertEqual(doc["reasons"], [".exe files are never allowed on any route (setup.exe inside photos/)."])
        folder = self.tree({"a.png": PNG, "photos/setup.png": samples.IMPOSTORS["exe"]})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], ["setup.png inside photos/ is a Windows program (it starts with MZ), which is never "
                                          "allowed on any route, whatever its name says.",
                                          "setup.png inside photos/ isn't a PNG inside."])
        folder = self.tree({"a.png": PNG, "b.png": samples.sample(".jpg")})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], ["b.png inside photos/ isn't a PNG inside."])

    def test_every_file_is_checked_and_every_reason_listed(self):
        folder = self.tree({"a.png": samples.sample(".jpg"), "b/run.sh": b"#!/bin/sh\n", "c.xyz": b"?", "d.png": PNG})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(len(doc["reasons"]), 3)
        self.assertIn("c.xyz inside photos/", " ".join(doc["reasons"]))
        self.assertIn("run.sh inside b/", " ".join(doc["reasons"]))

    def test_the_route_decides_the_kinds_for_every_file(self):
        folder = self.tree({"a.png": PNG, "game.iso": samples.sample(".iso")}, route="roms")
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], ["a.png inside photos/ is an image, which the roms route doesn't take (it takes "
                                          "rom, archive and archive-opaque)."])

    def test_check_one_runs_once_for_the_folder(self):
        folder = self.tree({"a.mp3": samples.sample(".mp3"), "b.mp3": samples.sample(".mp3")}, route="jellyfin-theme")
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(doc["checks"]["route"], "fail")
        self.assertEqual(doc["reasons"], ["desktop may not send on the jellyfin-theme route (it takes files from fetch:jellyfin-themes)."])

    def test_a_climbing_path_fails(self):
        for path, why in (("../x.png", "a path that climbs out of the folder (../x.png)"),
                          ("a/../../x.png", "a path that climbs out of the folder (a/../../x.png)"),
                          ("/etc/x.png", "an absolute path (/etc/x.png)"),
                          ("C:/x.png", "an absolute path (C:/x.png)"),
                          ("a\\\\x.png", "a path with a backslash or a NUL in it (a\\\\x.png)"),
                          (".git/x.png", "a hidden name in a path (.git/x.png)"),
                          ("", "an empty path")):
            manifest = {"version": 1, "files": [{"path": "a.png", "bytes": len(PNG), "sha256": sha256(PNG)},
                                                {"path": path, "bytes": 1, "sha256": "0" * 64}]}
            folder = self.tree({"a.png": PNG}, manifest=manifest)
            code, doc = self.r.check(folder)
            self.assertEqual(code, 10, path)
            self.assertEqual(doc["checks"]["shape"], "fail", path)
            self.assertIn("photos/'s manifest has %s, which is never allowed." % why, doc["reasons"])
            self.assertEqual(doc["checks"]["integrity"], "ok", path)   # the manifest itself matched what was declared

    def test_a_symlink_in_the_folder_fails(self):
        target = self.r.home / "outside.png"
        target.write_bytes(PNG)
        folder = self.tree({"a.png": PNG}, symlink=("docs/link.png", str(target)))
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertIn("docs/link.png inside photos/ is a symbolic link, which is never allowed.", doc["reasons"])
        folder = self.tree({"a.png": PNG}, symlink=("docs", str(self.r.home)))
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertIn("docs inside photos/ is a symbolic link, which is never allowed.", doc["reasons"])

    def test_manifest_hash_mismatch_fails(self):
        folder = self.tree({"a.png": PNG}, meta={"sha256": "0" * 64})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(doc["checks"]["integrity"], "fail")
        self.assertEqual(doc["reasons"], ["photos/'s manifest checksum doesn't match what desktop declared (the folder may "
                                          "have arrived incomplete or changed on the way)."])

    def test_a_file_hash_or_size_mismatch_names_the_file(self):
        manifest = {"version": 1, "files": [{"path": "a.png", "bytes": len(PNG), "sha256": "0" * 64},
                                            {"path": "b.png", "bytes": 1, "sha256": sha256(PNG)}]}
        folder = self.tree({"a.png": PNG, "b.png": PNG}, manifest=manifest, meta={"bytes": len(PNG) + 1})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], [
            "a.png inside photos/'s checksum doesn't match what desktop declared (the transfer may have been cut short or changed on the way).",
            "b.png inside photos/ is %d bytes on disk but desktop declared 1 bytes." % len(PNG)])

    def test_holes_and_strays(self):
        folder = self.tree({"a.png": PNG, "b.png": PNG}, extra_on_disk={"c.png": PNG})
        (folder / "data" / "b.png").unlink()
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], ["c.png inside photos/ is in the folder but not in the manifest.",
                                          "b.png inside photos/ is in the manifest but not in the folder (the folder arrived with holes)."])

    def test_total_bytes_must_match(self):
        folder = self.tree({"a.png": PNG}, meta={"bytes": 5})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], ["photos/'s manifest adds up to %d bytes but desktop declared 5 bytes." % len(PNG)])

    def test_a_malformed_manifest(self):
        folder = self.tree({"a.png": PNG}, manifest={"version": 1, "files": [{"path": "a.png"}]})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertIn("photos/'s manifest entry 1 is malformed (each needs path, bytes and sha256).", doc["reasons"])
        folder = self.tree({"a.png": PNG}, manifest={"version": 1})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertIn("photos/'s manifest has no files list, so the folder can't be checked.", doc["reasons"])
        manifest = {"version": 1, "files": [{"path": "a.png", "bytes": len(PNG), "sha256": sha256(PNG)}] * 2}
        folder = self.tree({"a.png": PNG}, manifest=manifest)
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertIn("photos/'s manifest lists a.png twice.", doc["reasons"])
        folder = self.tree({"a.png": PNG})
        (folder / "manifest.json").write_text("{")
        self.assertEqual(self.r.check(folder)[0], 2)             # Hermes left a broken arrival: Janus failed, held

    def test_the_duplicate_rule_uses_the_manifest_hash_not_each_file(self):
        self.assertEqual(self.r.check(self.r.arrival("a.png", PNG))[0], 0)     # the same photo, alone, on the same route
        folder = self.tree({"a.png": PNG})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 0, doc)                                        # the tree is new: not a duplicate
        folder2 = self.tree({"a.png": PNG})
        code, doc = self.r.check(folder2)
        self.assertEqual(code, 11)
        self.assertIn("photos already arrived on the servermail route as %s" % folder.name, doc["reasons"][0])

    def test_archives_inside_a_tree_are_listed(self):
        from tests.test_archives import zip_with
        folder = self.tree({"a.png": PNG, "tools/t.zip": zip_with({"tool.exe": samples.IMPOSTORS["exe"]})})
        code, doc = self.r.check(folder)
        self.assertEqual(code, 10)
        self.assertIn("tool.exe inside t.zip inside tools/ is never allowed on any route (.exe files never are).", doc["reasons"])

    def test_clean_path(self):
        self.assertIsNone(tree.clean_path("a/b/c.png"))
        self.assertIsNone(tree.clean_path("c.png"))
        for bad in ("", "/a", "a//b", "./a", "a/.", "..", "a/..", "a/.hidden", "C:a", "a\\b", "a\x00b"):
            self.assertIsNotNone(tree.clean_path(bad), bad)

    def test_janus_never_writes_inside_a_tree_arrival(self):
        folder = self.tree({"a.png": PNG, "docs/b.pdf": PDF})
        before = snapshot(folder)
        self.r.check(folder)
        self.assertEqual(snapshot(folder), before)


if __name__ == "__main__":
    unittest.main()
