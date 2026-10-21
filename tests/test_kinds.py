"""Check 2, the kind (docs/design.md §3 check 2, issue #4): executables refused in code, extension and content must
agree, the route must take the kind (the Taildrop list for Taildrop), and the size caps (the first line of check 3).
Until checks 3 (rules) and 4 are built nothing passes: a clean file is exit 2 and the arrival waits."""
import json
import os
import tempfile
import unittest

from janus import check, kinds
from tests import samples
from tests.helpers import Realm

# how each ending reaches Janus in the example config: the route and the sender that may send it
WAYS = {"mentor-lesson": ("lesson", {}), "deploy-request": ("deploy-request", {"via": "fetch", "fetch": "github"}),
        "note": ("pcmail", {"via": "local", "direction": "out"})}
EXT_KIND = {".json": "mentor-lesson", ".torrent": "torrent", ".magnet": "magnet", ".txt": "document", ".md": "document"}


class KindCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.r = Realm(self.tmp.name)
        self.addCleanup(self.r.stop)
        self.cfg = self.r.config()

    def kind_of(self, ext):
        if ext in EXT_KIND:
            return EXT_KIND[ext]
        for k in self.cfg.kinds.values():
            if ext in k.ext:
                return k.name
        raise KeyError(ext)

    def way(self, kind):
        if kind in WAYS:
            return WAYS[kind]
        for rid in ("servermail", "torrent", "roms"):
            if kind in self.cfg.routes[rid].kinds:
                return rid, {}
        raise KeyError(kind)

    def verdict(self, folder, **env):
        """Checks 1-3 (size) on an arrival, without the unbuilt-checks gate: the Verdict and the Context."""
        v = check.Verdict()
        ctx = check.Context(check.Arrival(folder), self.cfg, {**os.environ, **env})
        check.check_route(ctx, v)
        check.check_kind(ctx, v)
        check.check_size(ctx, v)
        return v, ctx

    # --- one fixture per kind passes ---
    def test_every_sample_passes_as_its_kind(self):
        for ext, data in samples.SAMPLES.items():
            kind = self.kind_of(ext)
            route, way = self.way(kind)
            name = "sample" + ext
            if kind == "deploy-request":
                data = json.dumps(samples.DEPLOY_REQUEST).encode()
            v, ctx = self.verdict(self.r.arrival(name, data, route=route, **way))
            self.assertEqual(v.reasons, [], "%s on %s: %s" % (name, route, v.reasons))
            self.assertEqual(v.kind, kind, name)
            self.assertEqual(v.checks["kind"], "ok", name)

    def test_the_example_config_covers_every_sample_ending(self):
        known = {e for k in self.cfg.kinds.values() for e in k.ext}
        self.assertEqual(set(samples.SAMPLES), known)

    def test_opaque_archives_pass_with_a_note(self):
        v, _ = self.verdict(self.r.arrival("disc.7z", samples.sample(".7z"), route="roms"))
        self.assertEqual(v.reasons, [])
        self.assertEqual(v.notes, ["archive opaque contents unchecked (.7z)."])

    # --- executables: refused in code, whatever the route or the config says ---
    def test_an_exe_renamed_png_quarantines(self):
        v, _ = self.verdict(self.r.arrival("photo.png", samples.IMPOSTORS["exe"]))
        self.assertEqual(v.checks["kind"], "fail")
        self.assertIn("photo.png is a Windows program (it starts with MZ), which is never allowed on any route, "
                      "whatever its name says.", v.reasons)
        self.assertIn("photo.png isn't a PNG inside.", v.reasons)

    def test_a_double_extension_quarantines(self):
        v, _ = self.verdict(self.r.arrival("report.pdf.exe", samples.sample(".pdf")))
        self.assertEqual(v.reasons[0], ".exe files are never allowed on any route (report.pdf.exe).")

    def test_a_script_quarantines_on_every_route(self):
        for rid in self.cfg.routes:
            if rid.endswith("*"):
                continue
            route = self.cfg.routes[rid]
            sender = self.cfg.senders[route.senders[0]]
            way = {"ssh": dict(key=sender.key), "taildrop": dict(via="taildrop"), "elaia": dict(via="elaia", user="you@example.com"),
                   "fetch": dict(via="fetch", fetch=sender.fetch), "local": dict(via="local", direction="out")}[sender.via]
            v, _ = self.verdict(self.r.arrival("run.sh", samples.IMPOSTORS["script"], route=rid, **way))
            self.assertEqual(v.checks["route"], "ok", rid)
            self.assertEqual(v.checks["kind"], "fail", rid)
            self.assertEqual(v.reasons[0], ".sh files are never allowed on any route (run.sh).", rid)

    def test_every_refused_extension_and_content(self):
        for ext in kinds.EXECUTABLE_EXT:
            self.assertEqual(kinds.executable_extension("x" + ext), ext)
            self.assertEqual(kinds.executable_extension("x" + ext.upper()), ext)
            self.assertEqual(kinds.executable_extension("photo.png" + ext), ext)
        self.assertIsNone(kinds.executable_extension("photo.png"))
        self.assertIsNone(kinds.executable_extension("shell.shx"))
        for what in ("exe", "elf", "macho", "script"):
            self.assertIsNotNone(kinds.executable_content(samples.IMPOSTORS[what]), what)
        self.assertIsNone(kinds.executable_content(samples.sample(".png")))

    def test_a_hidden_file_quarantines(self):
        v, _ = self.verdict(self.r.arrival(".bashrc", b"export X=1\n"))
        self.assertIn(".bashrc is a hidden file (its name starts with a dot), which is never allowed on any route.", v.reasons)

    def test_an_elf_named_rom_quarantines(self):
        v, _ = self.verdict(self.r.arrival("game.bin", samples.IMPOSTORS["elf"], route="roms"))
        self.assertIn("game.bin is a Linux program (it starts with ELF), which is never allowed on any route, whatever "
                      "its name says.", v.reasons)

    def test_config_cannot_allow_an_executable(self):
        doc = json.loads(json.dumps(self.r.routes_doc))
        doc["kinds"]["rom"]["ext"].append(".exe")
        self.r.write(doc)
        from janus import config
        with self.assertRaises(config.ConfigError):
            config.load()

    # --- extension and content must agree ---
    def test_content_must_match_the_ending(self):
        cases = [("photo.png", ".jpg", "photo.png isn't a PNG inside."),
                 ("photo.jpg", ".png", "photo.jpg isn't a JPEG inside."),
                 ("song.flac", ".mp3", "song.flac isn't a FLAC inside."),
                 ("film.mkv", ".webm", "film.mkv isn't a Matroska inside."),
                 ("paper.pdf", ".docx", "paper.pdf isn't a PDF inside."),
                 ("paper.docx", ".zip", "paper.docx isn't a docx inside."),
                 ("book.epub", ".odt", "book.epub isn't an EPUB inside."),
                 ("files.zip", ".tar", "files.zip isn't a zip inside."),
                 ("files.tar", ".zip", "files.tar isn't a tar inside."),
                 ("files.tar.gz", ".tar", "files.tar.gz isn't a gzip inside."),
                 ("files.7z", ".zip", "files.7z isn't a 7z inside.")]
        for name, inside, sentence in cases:
            v, _ = self.verdict(self.r.arrival(name, samples.sample(inside)))
            self.assertEqual(v.reasons, [sentence], name)

    def test_parsed_kinds(self):
        v, _ = self.verdict(self.r.arrival("lesson.json", b"{not json", route="lesson"))
        self.assertEqual(v.reasons, ["lesson.json isn't a JSON inside."])
        v, _ = self.verdict(self.r.arrival("x.torrent", b"d8:announce3:url", route="torrent"))
        self.assertEqual(v.reasons, ["x.torrent isn't a torrent (bencode) inside."])
        v, _ = self.verdict(self.r.arrival("x.torrent", samples.IMPOSTORS["binary-text"], route="torrent"))
        self.assertEqual(v.checks["kind"], "fail")
        v, _ = self.verdict(self.r.arrival("note.txt", samples.IMPOSTORS["binary-text"]))
        self.assertEqual(v.reasons, ["note.txt isn't a plain text inside."])
        v, _ = self.verdict(self.r.arrival("link.magnet", samples.IMPOSTORS["binary-text"], route="torrent"))
        self.assertEqual(v.reasons, ["link.magnet isn't a plain text inside."])

    def test_text_sniffer(self):
        self.assertTrue(kinds.is_text("café".encode(), True))
        self.assertFalse(kinds.is_text(b"a\x00b", True))
        self.assertFalse(kinds.is_text(b"\xff\xfe", True))
        self.assertTrue(kinds.is_text("café".encode()[:-1], False))     # a character cut at the end of the head
        self.assertFalse(kinds.is_text("café".encode()[:-1], True))

    def test_bencode_parser(self):
        self.assertTrue(kinds.bencode_ok(samples.torrent_bytes()))
        self.assertTrue(kinds.bencode_ok(b"li1ei2ee"))
        self.assertFalse(kinds.bencode_ok(b"d3:keyi1e"))         # unterminated
        self.assertFalse(kinds.bencode_ok(b"di1ei2ee"))          # a key must be a string
        self.assertFalse(kinds.bencode_ok(b"5:ab"))              # short string
        self.assertFalse(kinds.bencode_ok(b"i1ei2e"))            # trailing data
        self.assertFalse(kinds.bencode_ok(b"l" * 100))

    def test_a_kind_without_sniff_checks_the_ending_only(self):
        v, _ = self.verdict(self.r.arrival("game.iso", b"anything at all", route="roms"))
        self.assertEqual(v.reasons, [])
        self.assertEqual(v.kind, "rom")

    def test_txt_is_a_note_or_a_document_by_route(self):
        v, _ = self.verdict(self.r.arrival("a.txt", b"hi\n", route="pcmail", via="local", direction="out"))
        self.assertEqual(v.kind, "document")        # pcmail lists document before note; the first match wins
        v, _ = self.verdict(self.r.arrival("a.txt", b"hi\n", route="servermail"))
        self.assertEqual(v.kind, "document")

    # --- the route must take the kind ---
    def test_a_kind_the_route_does_not_take(self):
        v, _ = self.verdict(self.r.arrival("photo.png", samples.sample(".png"), route="roms"))
        self.assertEqual(v.reasons, ["photo.png is an image, which the roms route doesn't take (it takes rom, archive and archive-opaque)."])

    def test_an_ending_no_kind_knows(self):
        v, _ = self.verdict(self.r.arrival("data.xyz", b"?"))
        self.assertIn("has files ending like data.xyz, so it can't arrive on any route.", v.reasons[0])
        self.assertIsNone(v.kind)

    def test_a_taildrop_archive_on_servermail_quarantines_while_the_same_file_from_pc_passes(self):
        data = samples.sample(".zip")
        v, _ = self.verdict(self.r.arrival("photos.zip", data, route="servermail", via="taildrop"))
        self.assertEqual(v.checks["route"], "ok")
        self.assertEqual(v.reasons, ["photos.zip is an archive, which the servermail route doesn't take by Taildrop (by "
                                     "Taildrop it takes only image and document); send it from a keyed device instead."])
        v, _ = self.verdict(self.r.arrival("photos.zip", data, route="servermail"))
        self.assertEqual(v.reasons, [])
        self.assertEqual(v.kind, "archive")
        v, _ = self.verdict(self.r.arrival("photo.png", samples.sample(".png"), route="servermail", via="taildrop"))
        self.assertEqual(v.reasons, [])

    def test_the_kind_is_still_detected_when_the_route_is_unknown(self):
        v, _ = self.verdict(self.r.arrival("photo.png", samples.sample(".png"), route="scans"))
        self.assertEqual(v.checks["route"], "fail")
        self.assertEqual(v.checks["kind"], "ok")
        self.assertEqual(v.kind, "image")

    # --- size caps ---
    def test_kind_and_route_caps(self):
        doc = json.loads(json.dumps(self.r.routes_doc))
        doc["kinds"]["note"]["max_bytes"] = 16
        doc["routes"]["pcmail"]["max_bytes"] = 8
        doc["routes"]["pcmail"]["kinds"] = ["note"]
        self.r.write(doc)
        self.cfg = self.r.config()
        v, _ = self.verdict(self.r.arrival("a.txt", b"x" * 20, route="pcmail", via="local", direction="out"))
        self.assertEqual(v.checks["shape"], "fail")
        self.assertEqual(v.reasons, ["a.txt is 20 bytes, over the 16 bytes cap for note files.",
                                     "a.txt is 20 bytes, over the 8 bytes cap of the pcmail route."])
        v, _ = self.verdict(self.r.arrival("a.txt", b"x" * 8, route="pcmail", via="local", direction="out"))
        self.assertEqual(v.reasons, [])

    # --- every reason names the file, and the command line ---
    def test_every_reason_is_a_sentence_that_names_the_file(self):
        cases = [("photo.png", samples.IMPOSTORS["exe"], "servermail", {}),
                 ("report.pdf.exe", samples.sample(".pdf"), "servermail", {}),
                 ("photos.zip", samples.sample(".zip"), "servermail", {"via": "taildrop"}),
                 ("photo.png", samples.sample(".png"), "roms", {}),
                 ("data.xyz", b"?", "servermail", {}),
                 ("song.flac", samples.sample(".mp3"), "servermail", {})]
        for name, data, route, way in cases:
            v, _ = self.verdict(self.r.arrival(name, data, route=route, **way))
            self.assertTrue(v.reasons, name)
            for r in v.reasons:
                self.assertIn(name, r)
                self.assertTrue(r.endswith("."), r)

    def test_command_line_quarantines_with_the_kind_and_passes_nothing_yet(self):
        folder = self.r.arrival("photo.png", samples.IMPOSTORS["exe"])
        r = self.r.cli("check", "--json", str(folder))
        self.assertEqual(r.returncode, 10, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["kind"], "image")
        self.assertEqual(doc["checks"], {"route": "ok", "kind": "fail", "shape": "ok", "integrity": "not-built"})
        folder = self.r.arrival("photo.png", samples.sample(".png"))
        r = self.r.cli("check", "--json", str(folder))
        self.assertEqual(r.returncode, 2)
        self.assertIn("not built yet", r.stderr)


if __name__ == "__main__":
    unittest.main()
