"""Check 3, the shape rules (docs/design.md §3 check 3, issue #5): lesson fields, known placeholders (private
destination), no real names (public destination, the check-private.sh patterns plus the owner's denylist), magnet
links, deploy requests. Every rule of a kind runs; reasons name the file and the offending token (never a real name
found inside a file, only what it is and the line)."""
import json
import os
import tempfile
import unittest

from janus import check, shapes
from tests import samples
from tests.helpers import Realm


class ShapeCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.r = Realm(self.tmp.name)
        self.addCleanup(self.r.stop)
        # a public twin of the lesson route, for the real-name rule
        doc = json.loads(json.dumps(self.r.routes_doc))
        doc["routes"]["lesson-public"] = {"from": ["{{PC}}"], "kinds": ["mentor-lesson"], "destination": "public"}
        doc["routes"]["lesson-plain"] = {"from": ["{{PC}}"], "kinds": ["mentor-lesson"]}
        self.r.write(doc)
        self.cfg = self.r.config()

    def verdict(self, folder, **env):
        v = check.Verdict()
        ctx = check.Context(check.Arrival(folder), self.cfg, {**os.environ, **env})
        check.check_route(ctx, v)
        check.check_kind(ctx, v)
        check.check_size(ctx, v)
        check.check_shape(ctx, v)
        return v

    def lesson(self, route="lesson", **changes):
        doc = json.loads(json.dumps(samples.LESSON))
        doc.update(changes)
        return self.r.arrival("lesson.json", json.dumps(doc).encode(), route=route)

    # --- mentor-lesson-fields ---
    def test_a_good_lesson_passes_every_rule(self):
        v = self.verdict(self.lesson())
        self.assertEqual(v.reasons, [])
        self.assertEqual(v.checks["shape"], "ok")

    def test_lesson_needs_a_module_name(self):
        v = self.verdict(self.lesson(metadata={"project": "x"}))
        self.assertEqual(v.reasons, ["lesson.json has no metadata.module_name, which Mentor needs to name the lesson."])

    def test_lesson_needs_cards(self):
        v = self.verdict(self.lesson(tier_1_faded_code_drills=[], tier_3_terminology_cards=None))
        self.assertEqual(v.reasons, ["lesson.json has no cards (no tier_1_faded_code_drills, tier_2_self_explanation_cards "
                                     "and tier_3_terminology_cards list with anything in it), so Mentor would import nothing."])

    def test_the_old_lesson_shape_still_counts(self):
        v = self.verdict(self.lesson(tier_1_faded_code_drills=None, tier_3_terminology_cards=None,
                                     faded_code_drills=[{"id": "d1"}]))
        self.assertEqual(v.reasons, [])

    def test_a_card_that_is_not_an_object(self):
        v = self.verdict(self.lesson(tier_3_terminology_cards=[{"id": "t1"}, "oops"]))
        self.assertEqual(v.reasons, ["lesson.json: tier_3_terminology_cards has an entry that isn't a card (number 2)."])

    def test_a_lesson_that_is_a_list(self):
        folder = self.r.arrival("lesson.json", b"[1, 2]", route="lesson")
        v = self.verdict(folder)
        self.assertIn("lesson.json isn't a lesson: Mentor's lesson file is one JSON object.", v.reasons)

    def test_all_rules_run_and_every_reason_is_listed(self):
        doc = json.loads(json.dumps(samples.LESSON))
        doc["metadata"] = {}
        doc["cta_summary"]["schematic_mental_model"] = "On {{LAPTOP}} ..."
        v = self.verdict(self.r.arrival("lesson.json", json.dumps(doc).encode(), route="lesson"))
        self.assertEqual(len(v.reasons), 2)
        self.assertIn("no metadata.module_name", v.reasons[0])
        self.assertIn("{{LAPTOP}}", v.reasons[1])

    # --- placeholders-known ---
    def test_an_unknown_placeholder_on_a_private_destination(self):
        doc = json.loads(json.dumps(samples.LESSON))
        doc["cta_summary"]["schematic_mental_model"] = "Runs on {{LAPTOP}} next to {{SERVER}}."
        v = self.verdict(self.r.arrival("lesson.json", json.dumps(doc).encode(), route="lesson"))
        self.assertEqual(v.reasons, ["lesson.json uses {{LAPTOP}}, which isn't a known placeholder (Mentor fills only "
                                     "{{SERVER}}, {{PC}}, {{PHONE}}, {{SSH}}, {{HOME_PC}}, {{HOME_SERVER}} and {{REPO_URL}})."])
        doc["cta_summary"]["schematic_mental_model"] = "{{LAPTOP}} and {{ TABLET }} and {{LAPTOP}}"
        v = self.verdict(self.r.arrival("lesson.json", json.dumps(doc).encode(), route="lesson"))
        self.assertIn("lesson.json uses {{LAPTOP}} and {{TABLET}}, which aren't a known placeholder", v.reasons[0])

    def test_blanks_and_the_seven_are_known(self):
        self.assertEqual(shapes.placeholders_known.__name__, "placeholders_known")
        text = "{{BLANK}} {{BLANK_12}} {{SERVER}} {{ pc }} {{HOME_PC}} {{REPO_URL}}"
        doc = json.loads(json.dumps(samples.LESSON))
        doc["cta_summary"]["schematic_mental_model"] = text
        v = self.verdict(self.r.arrival("lesson.json", json.dumps(doc).encode(), route="lesson"))
        self.assertEqual(v.reasons, [])

    def test_the_placeholder_rule_is_off_without_a_private_destination(self):
        doc = json.loads(json.dumps(samples.LESSON))
        doc["cta_summary"]["schematic_mental_model"] = "{{LAPTOP}}"
        v = self.verdict(self.r.arrival("lesson.json", json.dumps(doc).encode(), route="lesson-plain"))
        self.assertEqual(v.reasons, [])

    # --- public-no-real-names ---
    def real(self, text, route="lesson-public"):
        doc = json.loads(json.dumps(samples.LESSON))
        doc["cta_summary"]["schematic_mental_model"] = text
        return self.r.arrival("lesson.json", json.dumps(doc, indent=1).encode(), route=route)

    def test_a_real_device_name_bound_for_a_public_destination_quarantines(self):
        v = self.verdict(self.real("ssh into box.tail0000.ts.net"))   # private-ok: a deliberate example of the pattern
        self.assertEqual(v.checks["shape"], "fail")
        self.assertEqual(v.reasons, ["lesson.json has a tailnet host name (use {{SERVER}} or {{PC}}) on line 14 but goes to "
                                     "a public destination; replace it with a placeholder."])
        self.assertNotIn("tail0000", v.reasons[0])

    def test_the_same_file_for_a_private_destination_passes(self):
        v = self.verdict(self.real("ssh into box.tail0000.ts.net", route="lesson"))   # private-ok: a deliberate example of the pattern
        self.assertEqual(v.reasons, [])

    def test_the_generic_patterns(self):
        cases = [("C:\\\\Users\\\\someone\\\\x", "a home path (use {{HOME_PC}})"),   # private-ok: a deliberate example of the pattern
                 ("/home/someone/x", "a home path (use {{HOME_SERVER}})"),   # private-ok: a deliberate example of the pattern
                 ("/Users/someone/x", "a home path (use {{HOME_SERVER}})"),   # private-ok: a deliberate example of the pattern
                 ("at 10.1.2.3 now", "an IP address"),   # private-ok: a deliberate example of the pattern
                 ("at fd7a:115c:a1e0::1234 now", "an IPv6 address"),   # private-ok: a deliberate example of the pattern
                 ("mail someone@somewhere.org", "an email address")]   # private-ok: a deliberate example of the pattern
        for text, what in cases:
            v = self.verdict(self.real(text))
            self.assertEqual(len(v.reasons), 1, text)
            self.assertIn(what, v.reasons[0])
            self.assertIn("on line 14", v.reasons[0])
        for fine in ("C:\\\\Users\\\\you\\\\x", "/home/user/x", "box.example.ts.net", "127.0.0.1", "192.0.2.1", "::1",
                     "2001:db8::1", "you@example.com", "git@github.com", "a 1.2.3.4.5 version", "secret 10.1.2.3 private-ok"):
            v = self.verdict(self.real(fine))
            self.assertEqual(v.reasons, [], fine)

    def test_the_denylist_when_present(self):
        deny = self.r.home / "denylist.txt"
        deny.write_text("# my names\nTowerOfPower\n\nmycat\n")
        v = self.verdict(self.real("the towerofpower box"), LEAFY_DENYLIST=str(deny))
        self.assertEqual(v.reasons, ["lesson.json has a name from your denylist (entry 1) on line 14 but goes to a public "
                                     "destination; replace it with a placeholder."])
        v = self.verdict(self.real("the towerofpower at 10.1.2.3"), LEAFY_DENYLIST=str(deny))   # private-ok: a deliberate example of the pattern
        self.assertIn("an IP address and a name from your denylist (entry 1)", v.reasons[0])

    def test_denylist_absent_the_generic_patterns_still_run(self):
        self.assertEqual(shapes.denylist({"LEAFY_DENYLIST": str(self.r.home / "none.txt")}), [])
        v = self.verdict(self.real("at 10.1.2.3"), LEAFY_DENYLIST=str(self.r.home / "none.txt"))   # private-ok: a deliberate example of the pattern
        self.assertIn("an IP address", v.reasons[0])

    # --- magnet-uri ---
    def test_magnet_links(self):
        ok = "magnet:?xt=urn:btih:" + "a" * 40 + "&dn=x"
        v = self.verdict(self.r.arrival("x.magnet", ok.encode(), route="torrent"))
        self.assertEqual(v.reasons, [])
        v = self.verdict(self.r.arrival("x.magnet", ("magnet:?xt=urn:btih:" + "B" * 32).encode(), route="torrent"))
        self.assertEqual(v.reasons, [])
        v = self.verdict(self.r.arrival("x.magnet", b"https://example.com/x.torrent", route="torrent"))
        self.assertEqual(v.reasons, ["x.magnet isn't a magnet link (it should start with magnet:?xt=urn:btih: followed by a "
                                     "40-character hex or 32-character base32 hash)."])
        v = self.verdict(self.r.arrival("x.magnet", ("magnet:?xt=urn:btih:" + "a" * 39).encode(), route="torrent"))
        self.assertEqual(len(v.reasons), 1)
        v = self.verdict(self.r.arrival("x.magnet", (ok + "\n" + ok).encode(), route="torrent"))
        self.assertEqual(v.reasons, ["x.magnet should hold one magnet link on one line, not 2 lines."])

    # --- deploy-request-fields ---
    def request(self, **changes):
        doc = dict(samples.DEPLOY_REQUEST)
        for k, val in changes.items():
            if val is None:
                doc.pop(k, None)
            else:
                doc[k] = val
        return self.r.arrival("argus-ui-aaaaaaa.json", json.dumps(doc).encode(), route="deploy-request", via="fetch", fetch="github")

    def test_deploy_requests(self):
        self.assertEqual(self.verdict(self.request()).reasons, [])
        self.assertEqual(self.verdict(self.request(previous=None, changelog=None, subject=None)).reasons, [])
        v = self.verdict(self.request(type="deploy", repo="argus-ui", sha="abc", previous="x", version=4, changelog="x"))
        self.assertEqual(v.reasons, [
            "argus-ui-aaaaaaa.json isn't a deploy request: its type is 'deploy', not deploy-request.",
            "argus-ui-aaaaaaa.json: repo must be owner/name.",
            "argus-ui-aaaaaaa.json: sha must be the commit's 40 hex characters.",
            "argus-ui-aaaaaaa.json: previous must be a commit's 40 hex characters, or null.",
            "argus-ui-aaaaaaa.json: version must be text.",
            "argus-ui-aaaaaaa.json: changelog must be a list of lines."])

    # --- the archive rule waits for #7 ---
    def test_an_archive_waits_until_the_listing_rule_is_built(self):
        code, doc = self.r.check(self.r.arrival("photos.zip", samples.sample(".zip")))
        self.assertEqual(code, 2)
        self.assertIn("archive-listing shape rule is not built yet", doc["failed"])

    def test_a_shape_failure_is_a_quarantine_on_the_command_line(self):
        r = self.r.cli("check", "--json", str(self.lesson(metadata={})))
        self.assertEqual(r.returncode, 10, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["checks"]["shape"], "fail")
        self.assertEqual(doc["kind"], "mentor-lesson")


if __name__ == "__main__":
    unittest.main()
