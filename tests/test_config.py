"""routes.json and doors.json: load, expand, validate and explain (docs/design.md §2, §6b, issue #2). Every test builds
its own temporary HOME, so nothing on this machine is read."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from janus import config

ROOT = Path(__file__).resolve().parent.parent
ROUTES_EXAMPLE = ROOT / "examples" / "routes.example.json"
DOORS_EXAMPLE = ROOT / "examples" / "doors.example.json"
HERMES_EXAMPLE = {"version": 1, "stages": {"home": "~/stage"},
                  "routes": {"lesson": {"to": "~/inbox", "stage": "home"}, "torrent-movies": {"to": "~/t", "stage": "home"}}}


class Home:
    """A temporary HOME with Janus's two files (the examples by default) and no Hermes file."""
    def __init__(self, tmp):
        self.home = Path(tmp) / "home"
        self.routes = self.home / ".config" / "janus" / "routes.json"
        self.doors = self.home / ".config" / "janus" / "doors.json"
        self.hermes = self.home / ".config" / "hermes" / "routes.json"
        self.realm = self.home / ".config" / "leafy" / "realm.json"
        self.routes.parent.mkdir(parents=True)
        self.hermes.parent.mkdir(parents=True)
        self.env = mock.patch.dict(os.environ, {"HOME": str(self.home), "JANUS_CONFIG": str(self.routes),
                                                "JANUS_DOORS": str(self.doors), "HERMES_CONFIG": str(self.hermes),
                                                "LEAFY_REALM": str(self.realm)})
        self.env.start()
        self.routes_doc = json.loads(ROUTES_EXAMPLE.read_text())
        self.doors_doc = json.loads(DOORS_EXAMPLE.read_text())
        self.write()

    def write(self, routes=None, doors=None, text=None):
        self.routes.write_text(text if text is not None else json.dumps(routes or self.routes_doc))
        self.doors.write_text(json.dumps(doors or self.doors_doc))
        return self


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Home(self.tmp.name)
        self.addCleanup(self.h.env.stop)

    def changed(self, section, name, **changes):
        """The routes example with one entry changed; None removes a setting."""
        doc = json.loads(json.dumps(self.h.routes_doc))
        for k, v in changes.items():
            if v is None:
                doc[section][name].pop(k, None)
            else:
                doc[section][name][k] = v
        return doc

    def errors(self, routes=None, doors=None):
        cfg = self.h.write(routes, doors) and config.check()
        return cfg.errors

    # --- the examples ---
    def test_the_examples_pass_and_are_explained(self):
        cfg = config.check()
        self.assertEqual(cfg.errors, [])
        self.assertEqual(cfg.warnings, [])
        self.assertTrue(cfg.ok)
        self.assertEqual(len(cfg.routes), 9)
        self.assertEqual(len(cfg.senders), 8)
        self.assertEqual(len(cfg.kinds), 12)
        self.assertEqual(len(cfg.devices), 5)
        lines = cfg.explain()
        self.assertIn("lesson: desktop and fetch:decks may send mentor-lesson; a private destination.", lines)
        self.assertIn("servermail: desktop, laptop and taildrop may send image, audio, video, document, archive and "
                      "archive-opaque (by Taildrop only image and document).", lines)
        self.assertIn("torrent-*: the same as torrent.", lines)
        self.assertIn("jellyfin-theme: fetch:jellyfin-themes may send audio, up to 20 MB.", lines)
        self.assertIn("homeserver (always): ssh 2200, jellyfin 8096, audiobookshelf 13378, qbittorrent 8080, "
                      "elaia (serve /argus/api/health), sunshine 47990 (sometimes), steam-link 27036 (sometimes), "
                      "syncthing 22000 (sometimes).", lines)
        self.assertIn("tablet (sometimes): no doors.", lines)

    def test_placeholders_come_from_realm_json(self):
        self.h.realm.parent.mkdir(parents=True)
        self.h.realm.write_text(json.dumps({"PC": "tower", "SERVER": "box", "PHONE": "pixel"}))
        cfg = config.check()
        self.assertEqual(cfg.errors, [])
        self.assertIn("tower", cfg.senders)
        self.assertEqual(cfg.senders["tower"].node, "tower")
        self.assertEqual(cfg.routes["lesson"].senders, ["tower", "fetch:decks"])
        self.assertEqual(cfg.approvers["zeus"]["nodes"], ["pixel", "tower"])
        self.assertIn("box", cfg.devices)

    def test_the_example_files_hold_placeholders_only(self):
        for path in (ROUTES_EXAMPLE, DOORS_EXAMPLE):
            text = path.read_text()
            self.assertIn("{{SERVER}}", text)
            self.assertIn("{{PC}}", text)
            for real in ("ts.net", "@gmail", "/home/"):
                self.assertNotIn(real, text)

    def test_route_lookup_covers_patterns_and_same_as(self):
        cfg = config.check()
        self.assertEqual(cfg.route("torrent-movies").id, "torrent")
        self.assertEqual(cfg.route("torrent").id, "torrent")
        self.assertIsNone(cfg.route("torrentmovies"))
        self.assertIsNone(cfg.route("nothing"))
        self.assertEqual(cfg.route("servermail").kinds_for("taildrop"), ["image", "document"])
        self.assertEqual(cfg.route("roms").kinds_for("taildrop"), ["rom", "archive", "archive-opaque"])
        self.assertEqual(cfg.sender_by_key("desktop").name, "desktop")
        self.assertIsNone(cfg.sender_by_key("nobody"))
        self.assertEqual(cfg.sender_by_fetch("decks").name, "fetch:decks")

    # --- file problems ---
    def test_missing_file(self):
        self.h.routes.unlink()
        cfg = config.check()
        self.assertEqual(len(cfg.errors), 1)
        self.assertIn("cannot read it", cfg.errors[0])
        self.assertIn("examples/routes.example.json", cfg.errors[0])

    def test_broken_json(self):
        self.h.write(text="{ 'version': 1 }")
        self.assertIn("not valid JSON", config.check().errors[0])

    def test_wrong_version(self):
        doc = dict(self.h.routes_doc, version=2)
        self.assertIn("version must be 1", self.errors(doc)[0])

    def test_load_raises_on_errors(self):
        self.h.write(text="[]")
        with self.assertRaises(config.ConfigError) as cm:
            config.load()
        self.assertIn("run `janus check-config`", str(cm.exception))

    # --- senders ---
    def test_sender_needs_a_known_via(self):
        errs = self.errors(self.changed("senders", "laptop", via="carrier-pigeon"))
        self.assertEqual(len(errs), 1)
        self.assertIn('senders.laptop: "via" must be one of ssh, local, taildrop, elaia, fetch', errs[0])

    def test_ssh_sender_defaults_key_and_node_to_its_name(self):
        cfg = self.h.write(self.changed("senders", "laptop", key=None, node=None)) and config.check()
        self.assertEqual(cfg.errors, [])
        self.assertEqual((cfg.senders["laptop"].key, cfg.senders["laptop"].node), ("laptop", "laptop"))

    def test_two_senders_cannot_share_a_key(self):
        errs = self.errors(self.changed("senders", "laptop", key="desktop"))
        self.assertIn("both use the ssh key 'desktop'", errs[0])

    def test_elaia_sender_needs_users(self):
        errs = self.errors(self.changed("senders", "elaia", users=[]))
        self.assertIn('senders.elaia: an elaia sender needs "users"', errs[0])

    def test_unknown_setting_is_a_warning(self):
        self.h.write(self.changed("senders", "laptop", colour="blue"))
        cfg = config.check()
        self.assertEqual(cfg.errors, [])
        self.assertIn("senders.laptop: unknown setting 'colour' is ignored", cfg.warnings[0])

    # --- kinds ---
    def test_a_kind_listing_an_executable_extension_is_an_error(self):
        for ext in (".ps1", ".exe", ".sh", ".py", ".jar", ".appimage", ".tar.exe"):
            errs = self.errors(self.changed("kinds", "document", ext=[".pdf", ext]))
            self.assertTrue(errs, ext)
            self.assertIn("kinds.document: %s is an executable or script ending, which Janus refuses on every route" % ext, errs[0])

    def test_kind_needs_extensions_with_a_dot(self):
        errs = self.errors(self.changed("kinds", "image", ext=["png"]))
        self.assertIn('kinds.image: "ext" must be a non-empty list of file endings that start with a dot', errs[0])

    def test_kind_sniff_must_be_known(self):
        errs = self.errors(self.changed("kinds", "image", sniff="picture"))
        self.assertIn('"sniff" must be one of json, bencode, text, image, audio, video, document, archive', errs[0])

    def test_kind_max_bytes(self):
        errs = self.errors(self.changed("kinds", "image", max_bytes="50MB"))
        self.assertIn('kinds.image: "max_bytes" must be a whole number of bytes above 0', errs[0])

    def test_kind_shape_rules_must_be_known(self):
        errs = self.errors(self.changed("kinds", "magnet", shape=["magnet-uri", "no-such-rule"]))
        self.assertIn('kinds.magnet: "shape" must be a list of shape rules from', errs[0])

    # --- routes ---
    def test_route_id_rules(self):
        doc = json.loads(json.dumps(self.h.routes_doc))
        doc["routes"]["Bad Route"] = {"from": ["laptop"], "kinds": ["note"]}
        self.assertIn("route Bad Route: route ids are lowercase letters", self.errors(doc)[0])

    def test_route_needs_known_senders_and_kinds(self):
        errs = self.errors(self.changed("routes", "roms", **{"from": ["desktop", "toaster"]}))
        self.assertIn('route roms: "from" names toaster, which is not defined under senders', errs[0])
        errs = self.errors(self.changed("routes", "roms", kinds=["rom", "tape"]))
        self.assertIn('route roms: "kinds" names tape, which is not defined under kinds', errs[0])

    def test_taildrop_kinds_must_be_a_subset(self):
        errs = self.errors(self.changed("routes", "servermail", taildrop_kinds=["image", "rom"]))
        self.assertIn('route servermail: "taildrop_kinds" names rom, which the route\'s "kinds" don\'t include', errs[0])

    def test_taildrop_kinds_without_a_taildrop_sender_is_a_warning(self):
        self.h.write(self.changed("routes", "roms", taildrop_kinds=["rom"]))
        cfg = config.check()
        self.assertEqual(cfg.errors, [])
        self.assertIn('route roms: "taildrop_kinds" is set but no taildrop sender', cfg.warnings[0])

    def test_destination_and_max_bytes(self):
        errs = self.errors(self.changed("routes", "lesson", destination="shared"))
        self.assertIn('route lesson: "destination" must be private or public', errs[0])
        errs = self.errors(self.changed("routes", "lesson", max_bytes=0))
        self.assertIn('route lesson: "max_bytes" must be a whole number of bytes above 0', errs[0])

    def test_same_as_must_name_another_route(self):
        errs = self.errors(self.changed("routes", "torrent-*", same_as="torrent-*"))
        self.assertIn('route torrent-*: "same_as" must name another route', errs[0])
        errs = self.errors(self.changed("routes", "torrent-*", same_as="nowhere"))
        self.assertIn('route torrent-*: "same_as" must name another route', errs[0])

    # --- approvers ---
    def test_approvers(self):
        errs = self.errors(self.changed("approvers", "zeus", nodes=[]))
        self.assertIn('approvers.zeus: needs "users" (tailnet logins) and "nodes"', errs[0])
        errs = self.errors(self.changed("approvers", "zeus", max_age_s=-1))
        self.assertIn('approvers.zeus: "max_age_s" must be a whole number of seconds above 0', errs[0])
        cfg = self.h.write(self.changed("approvers", "zeus", max_age_s=None)) and config.check()
        self.assertEqual(cfg.approvers["zeus"]["max_age_s"], 120)

    # --- doors ---
    def doors(self, device, **changes):
        doc = json.loads(json.dumps(self.h.doors_doc))
        for k, v in changes.items():
            if v is None:
                doc["devices"][device].pop(k, None)
            else:
                doc["devices"][device][k] = v
        return doc

    def test_device_expect_must_be_known(self):
        errs = self.errors(doors=self.doors("laptop", expect="maybe"))
        self.assertIn('devices.laptop: "expect" must be one of always, when-online, sometimes', errs[0])

    def test_door_needs_exactly_one_way(self):
        errs = self.errors(doors=self.doors("laptop", doors={"x": {"port": 80, "taildrop": True}}))
        self.assertIn('devices.laptop.doors.x: needs exactly one of "port", "serve": true or "taildrop": true (found port and taildrop)', errs[0])
        errs = self.errors(doors=self.doors("laptop", doors={"x": {"note": "nothing"}}))
        self.assertIn("(found none)", errs[0])

    def test_door_port_range_and_serve_health(self):
        errs = self.errors(doors=self.doors("laptop", doors={"x": {"port": 70000}}))
        self.assertIn('devices.laptop.doors.x: "port" must be a whole number from 1 to 65535', errs[0])
        errs = self.errors(doors=self.doors("laptop", doors={"x": {"serve": True}}))
        self.assertIn('devices.laptop.doors.x: a serve door needs "health"', errs[0])

    def test_doors_file_missing(self):
        self.h.doors.unlink()
        cfg = config.check()
        self.assertEqual(len(cfg.errors), 1)
        self.assertIn("doors.json: cannot read it", cfg.errors[0])
        self.assertEqual(config.check(doors=False).errors, [])

    # --- Hermes's routes ---
    def test_a_route_hermes_defines_but_janus_does_not_is_a_warning(self):
        self.h.hermes.write_text(json.dumps(HERMES_EXAMPLE))
        self.assertEqual(config.check().warnings, [])      # lesson and torrent-movies (torrent-*) are both known
        doc = dict(HERMES_EXAMPLE, routes=dict(HERMES_EXAMPLE["routes"], scans={"to": "~/s", "stage": "home"}))
        self.h.hermes.write_text(json.dumps(doc))
        cfg = config.check()
        self.assertEqual(cfg.errors, [])
        self.assertEqual(len(cfg.warnings), 1)
        self.assertIn("defines route scans, which Janus doesn't: every arrival on it would be quarantined", cfg.warnings[0])

    def test_an_unreadable_hermes_file_is_a_warning(self):
        self.h.hermes.write_text("nope")
        self.assertIn("cannot read Hermes's routes from it", config.check().warnings[0])


class CheckConfigCommandTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Home(self.tmp.name)
        self.addCleanup(self.h.env.stop)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "janus", "check-config", *args], cwd=ROOT, capture_output=True,
                              text=True, env=dict(os.environ))

    def test_both_examples_pass(self):
        r = self.run_cli()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("lesson: desktop and fetch:decks may send mentor-lesson", r.stdout)
        self.assertIn("9 routes, 5 devices ok", r.stdout)
        self.assertEqual(r.stderr, "")

    def test_explicit_files(self):
        r = self.run_cli("--routes", str(ROUTES_EXAMPLE), "--doors", str(DOORS_EXAMPLE))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_kind_with_ps1_fails(self):
        doc = json.loads(json.dumps(self.h.routes_doc))
        doc["kinds"]["document"]["ext"].append(".ps1")
        self.h.write(doc)
        r = self.run_cli()
        self.assertEqual(r.returncode, 1)
        self.assertIn("error: kinds.document: .ps1 is an executable or script ending", r.stderr)
        self.assertIn("1 error. Fix them; Janus passes nothing until the config is right.", r.stderr)

    def test_a_hermes_route_janus_does_not_know_warns(self):
        doc = dict(HERMES_EXAMPLE, routes=dict(HERMES_EXAMPLE["routes"], scans={"to": "~/s", "stage": "home"}))
        self.h.hermes.write_text(json.dumps(doc))
        r = self.run_cli()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("warning: Hermes's", r.stderr)
        self.assertIn("1 warning", r.stdout)


if __name__ == "__main__":
    unittest.main()
