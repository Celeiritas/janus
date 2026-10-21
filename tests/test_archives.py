"""Archives by listing (docs/design.md §3b, issue #7): zip by its central directory, tar by streaming headers, never
extracted. Fixtures are made in code: a clean zip, a zip with tool.exe, a zip with ../etc/x, a tar with a symlink,
a zip bomb, three nested archives, and a 1 GB zip whose listing must read only the central directory."""
import io
import json
import os
import tarfile
import tempfile
import time
import unittest
import zipfile
import zlib
from pathlib import Path

from janus import archives, check
from tests import samples
from tests.helpers import Realm, sha256


def zip_with(members, attrs=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if attrs and name in attrs:
                info.external_attr = attrs[name]
            z.writestr(info, data)
    return buf.getvalue()


def tar_with(members, links=None, gz=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as t:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        for name, (kind, target) in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
            info.linkname = target
            t.addfile(info)
    return buf.getvalue()


class ArchiveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.r = Realm(self.tmp.name)
        self.addCleanup(self.r.stop)

    def verdict(self, name, data, route="servermail", **way):
        code, doc = self.r.check(self.r.arrival(name, data, route=route, **way))
        return code, doc

    # --- the fixtures the issue names ---
    def test_a_clean_zip_passes(self):
        code, doc = self.verdict("photos.zip", zip_with({"photos/": b"", "photos/a.png": samples.sample(".png"), "photos/b.txt": b"two"}))
        self.assertEqual(code, 0, doc)
        self.assertEqual(doc["kind"], "archive")
        self.assertEqual(doc["notes"], [])

    def test_a_zip_with_an_exe_quarantines(self):
        code, doc = self.verdict("tools.zip", zip_with({"docs/readme.txt": b"hi", "bin/tool.exe": samples.IMPOSTORS["exe"]}))
        self.assertEqual(code, 10)
        self.assertEqual(doc["checks"]["shape"], "fail")
        self.assertEqual(doc["reasons"], ["tool.exe inside tools.zip is never allowed on any route (.exe files never are)."])

    def test_a_zip_member_that_is_a_program_inside_quarantines(self):
        code, doc = self.verdict("tools.zip", zip_with({"photo.png": samples.IMPOSTORS["exe"], "x.bin": samples.IMPOSTORS["elf"]}))
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], [
            "photo.png inside tools.zip is a Windows program (it starts with MZ), which is never allowed on any route.",
            "x.bin inside tools.zip is a Linux program (it starts with ELF), which is never allowed on any route."])

    def test_a_zip_with_a_climbing_path_quarantines(self):
        code, doc = self.verdict("bad.zip", zip_with({"../etc/x": b"root::0:0", "ok.txt": b"fine"}))
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], ["bad.zip has a member whose path climbs out of the folder (../etc/x), which is never allowed."])
        for path in ("/etc/x", "C:/Users/you/x", "a/../../x", "a\\..\\..\\x"):
            code, doc = self.verdict("bad.zip", zip_with({path: b"x"}))
            self.assertEqual(code, 10, path)
            self.assertIn("climbs out of the folder", doc["reasons"][0])

    def test_a_tar_with_a_symlink_quarantines(self):
        data = tar_with({"photos/a.txt": b"one"}, links={"photos/link": ("sym", "/etc/passwd")})
        code, doc = self.verdict("photos.tar", data)
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], ["photos.tar has a symbolic link (photos/link), which is never allowed inside an archive."])
        data = tar_with({"photos/a.txt": b"one"}, links={"photos/hard": ("hard", "photos/a.txt")}, gz=True)
        code, doc = self.verdict("photos.tar.gz", data)
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], ["photos.tar.gz has a hard link (photos/hard), which is never allowed inside an archive."])

    def test_a_zip_symlink_quarantines(self):
        data = zip_with({"link": b"/etc/passwd"}, attrs={"link": (0o120777 << 16)})
        code, doc = self.verdict("links.zip", data)
        self.assertEqual(code, 10)
        self.assertIn("links.zip has a symbolic link (link)", doc["reasons"][0])

    def test_a_zip_bomb_quarantines(self):
        data = zip_with({"zeros.bin": b"\x00" * (64 << 20)})          # 64 MB of nothing packs into about 64 KB
        self.assertLess(len(data), 1 << 20)
        code, doc = self.verdict("bomb.zip", data)
        self.assertEqual(code, 10)
        self.assertEqual(len(doc["reasons"]), 1)
        self.assertRegex(doc["reasons"][0], r"^bomb\.zip says it holds 64 MB packed into [0-9.]+ KB \(\d+ times smaller\), "
                                             r"which is what a zip bomb looks like\.$")

    def test_a_small_well_packed_file_is_not_a_bomb(self):
        data = zip_with({"zeros.txt": b"\x00" * 4096})                 # 4 KB -> a few bytes: under the 1 MB floor
        self.assertEqual(self.verdict("small.zip", data)[0], 0)
        data = tar_with({"zeros.bin": b"\x00" * (8 << 20)}, gz=True)   # a tar.gz bomb is caught the same way
        self.assertEqual(self.verdict("bomb.tar.gz", data)[0], 10)

    def test_nested_archives_are_counted_never_opened(self):
        inner = zip_with({"evil.exe": samples.IMPOSTORS["exe"]})       # would fail if it were opened
        data = zip_with({"a/inner.zip": inner, "b/inner.tar.gz": samples.sample(".tar.gz"), "c/inner.7z": samples.sample(".7z"),
                         "readme.txt": b"hi"})
        code, doc = self.verdict("nest.zip", data)
        self.assertEqual(code, 0, doc)
        self.assertEqual(doc["notes"], ["nested archives: 3 (not opened)"])
        data = tar_with({"a/inner.zip": inner, "b.rar": samples.sample(".rar"), "c.tgz": samples.sample(".tgz")})
        code, doc = self.verdict("nest.tar", data)
        self.assertEqual(code, 0, doc)
        self.assertEqual(doc["notes"], ["nested archives: 3 (not opened)"])

    def test_declared_size_over_the_cap(self):
        doc = json.loads(json.dumps(self.r.routes_doc))
        doc["routes"]["servermail"]["max_bytes"] = 100 << 10
        self.r.write(doc)
        data = zip_with({"big.bin": os.urandom(200 << 10)})            # random bytes don't pack: on disk over the cap too
        code, doc = self.verdict("big.zip", data)
        self.assertEqual(code, 10)
        self.assertIn("big.zip would unpack to 200 KB, over the 100 KB cap.", doc["reasons"])

    def test_too_many_members(self):
        data = zip_with({"f%05d" % i: b"" for i in range(archives.MAX_MEMBERS + 5)})
        code, doc = self.verdict("many.zip", data)
        self.assertEqual(code, 10)
        self.assertEqual(doc["reasons"], ["many.zip holds more than 50 000 members, more than Janus will list; split it."])

    def test_an_encrypted_member_cannot_be_checked(self):
        data = zip_with({"secret.txt": b"x"})
        data = data.replace(b"PK\x03\x04\x14\x00\x00\x00", b"PK\x03\x04\x14\x00\x01\x00").replace(b"PK\x01\x02\x14\x03\x14\x00\x00\x00", b"PK\x01\x02\x14\x03\x14\x00\x01\x00")
        code, doc = self.verdict("locked.zip", data)
        self.assertEqual(code, 10)
        self.assertIn("locked.zip has an encrypted member (secret.txt), which can't be checked.", doc["reasons"])

    def test_a_broken_table_of_contents(self):
        data = zip_with({"a.txt": b"hi"})[:-10]        # the end-of-central-directory record is gone
        code, doc = self.verdict("torn.zip", data)
        self.assertEqual(code, 10)
        self.assertIn("torn.zip's table of contents can't be read", doc["reasons"][0])
        data = b"\x1f\x8b" + os.urandom(64)
        code, doc = self.verdict("torn.tar.gz", data)
        self.assertEqual(code, 10)
        self.assertIn("torn.tar.gz's headers can't be read", doc["reasons"][0])

    def test_every_reason_is_listed_at_once(self):
        data = zip_with({"../x": b"x", "tool.exe": samples.IMPOSTORS["exe"], ".hidden": b"x", "a.sh": b"#!/bin/sh\n"})
        code, doc = self.verdict("worst.zip", data)
        self.assertEqual(code, 10)
        self.assertEqual(len(doc["reasons"]), 4)
        self.assertIn(".hidden inside worst.zip is a hidden file (its name starts with a dot), which is never allowed.", doc["reasons"])

    # --- opaque archives ---
    def test_7z_and_rar_pass_with_the_note_where_the_route_lists_the_kind(self):
        for name, ext in (("disc.7z", ".7z"), ("disc.rar", ".rar")):
            code, doc = self.verdict(name, samples.sample(ext), route="roms")
            self.assertEqual(code, 0, doc)
            self.assertEqual(doc["kind"], "archive-opaque")
            self.assertEqual(doc["notes"], ["archive contents unchecked (%s)" % ext])
        code, doc = self.verdict("disc.7z", samples.sample(".7z"), route="servermail", via="taildrop")
        self.assertEqual(code, 10)
        self.assertIn("doesn't take by Taildrop", doc["reasons"][0])
        code, doc = self.verdict("disc.7z", samples.sample(".7z"), route="torrent", via="elaia", user="you@example.com")
        self.assertEqual(code, 10)

    # --- the listing reads only the central directory ---
    def test_a_one_gb_zip_is_listed_from_its_central_directory_only(self):
        small = zip_with({"photos/a.txt": b"one", "photos/b.txt": b"two"})
        big = self.r.stage / "big.zip"
        with open(big, "wb") as f:
            f.truncate(1 << 30)            # a sparse gigabyte of nothing, then a real zip: readers find the directory at the end
            f.seek(1 << 30)
            f.write(small)
        t = time.monotonic()
        reasons, notes = archives.listing("big.zip", big, 8 << 30, ".zip")
        took = time.monotonic() - t
        self.assertEqual((reasons, notes), ([], []))
        self.assertLess(took, 1.0, "listing read more than the central directory (%.2f s)" % took)

    def test_listing_never_writes_or_extracts(self):
        folder = self.r.arrival("photos.zip", zip_with({"photos/a.txt": b"one"}))
        before = sorted(p.name for p in folder.iterdir())
        self.assertEqual(self.r.check(folder)[0], 0)
        self.assertEqual(sorted(p.name for p in folder.iterdir()), before)
        self.assertEqual(sorted(p.name for p in self.r.stage.iterdir()), ["in"])


if __name__ == "__main__":
    unittest.main()
