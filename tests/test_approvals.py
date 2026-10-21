"""janus verify-approval: the second face, for Zeus (docs/design.md §4; zeus docs/contract.md §5)."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import GUEST_IP, LAPTOP_IP, PC_IP, PHONE_IP, Realm

SERVER_IP = "192.0.2.14"        # a tagged device with no login (tests/fixtures/tailnet/whois.json)
SHA = "3fa9c1b" + "0" * 33


def now(offset_s=0):
    return (datetime.now().astimezone() + timedelta(seconds=offset_s)).isoformat(timespec="seconds")


def req(**over):
    base = {"action": "deploy", "repo": "you/argus-ui", "sha": SHA, "user": "you@example.com", "ip": PHONE_IP, "when": now(), "via": "elaia"}
    base.update(over)
    return {k: v for k, v in base.items() if v is not ...}


class VerifyApprovalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.realm = Realm(self.tmp.name)
        self.state = Path(self.tmp.name) / "state"

    def tearDown(self):
        self.realm.stop()
        self.tmp.cleanup()

    def ask(self, request, raw=None, **env):
        r = self.realm.cli("verify-approval", input=raw if raw is not None else json.dumps(request), JANUS_STATE=str(self.state), **env)
        try:
            answer = json.loads(r.stdout)
        except ValueError:
            answer = None
        return r.returncode, answer, r

    def log_lines(self):
        d = self.state / "log"
        return [json.loads(l) for p in sorted(d.glob("approvals-*.jsonl")) for l in p.read_text().splitlines()] if d.exists() else []

    def test_allowed_from_the_page(self):
        code, a, r = self.ask(req())
        self.assertEqual(code, 0, r.stdout + r.stderr)
        self.assertEqual((a["verdict"], a["user"], a["node"], a["reasons"]), ("allowed", "you@example.com", "phone", []))
        line = self.log_lines()[-1]
        self.assertEqual((line["verdict"], line["action"], line["repo"], line["node"], line["claimed_user"]),
                         ("allowed", "deploy", "you/argus-ui", "phone", "you@example.com"))

    def test_rollback_and_release_actions(self):
        self.assertEqual(self.ask(req(action="rollback"))[0], 0)
        code, a, _ = self.ask(req(action="release", repo=..., sha=..., arrival="20261021-141203-3fa9c1"))
        self.assertEqual((code, a["verdict"]), (0, "allowed"))
        code, a, _ = self.ask(req(action="release", repo=..., sha=...))
        self.assertEqual(code, 10)
        self.assertIn("A release names a Hermes arrival id (date-time-hex).", a["reasons"])

    def test_ssh_path_user_null_is_filled_from_whois(self):
        code, a, _ = self.ask(req(user=None, via="ssh", ip=PC_IP))
        self.assertEqual((code, a["verdict"], a["user"], a["node"]), (0, "allowed", "you@example.com", "desktop"))
        self.assertIsNone(self.log_lines()[-1]["claimed_user"])

    def test_user_null_from_the_page_is_refused(self):
        code, a, _ = self.ask(req(user=None))
        self.assertEqual(code, 10)
        self.assertTrue(any("only an ssh approval leaves the user to Janus" in s for s in a["reasons"]), a["reasons"])

    def test_wrong_user_is_refused_on_both_paths(self):
        code, a, _ = self.ask(req(user="someone-else@example.com", ip=GUEST_IP))
        self.assertEqual(code, 10)
        self.assertIn("someone-else@example.com may not approve for Zeus.", a["reasons"])
        self.assertIn("guest is not an approved device for Zeus.", a["reasons"])
        code, a, _ = self.ask(req(user=None, via="ssh", ip=GUEST_IP))
        self.assertEqual((code, a["user"]), (10, "someone-else@example.com"))
        self.assertIn("someone-else@example.com may not approve for Zeus.", a["reasons"])

    def test_page_user_differs_from_tailnet_user(self):
        code, a, _ = self.ask(req(ip=GUEST_IP))
        self.assertEqual(code, 10)
        self.assertIn("The page says you@example.com but the tailnet says someone-else@example.com is using guest.", a["reasons"])

    def test_right_user_wrong_device(self):
        code, a, _ = self.ask(req(ip=LAPTOP_IP))
        self.assertEqual((code, a["node"], a["reasons"]), (10, "laptop", ["laptop is not an approved device for Zeus."]))

    def test_tagged_device_without_a_login(self):
        code, a, _ = self.ask(req(ip=SERVER_IP))
        self.assertEqual(code, 10)
        self.assertTrue(any("a tagged device cannot approve" in s for s in a["reasons"]), a["reasons"])

    def test_stale_and_future_requests(self):
        code, a, _ = self.ask(req(when=now(-300)))
        self.assertEqual(code, 10)
        self.assertTrue(any("Janus accepts one up to 120 s old" in s for s in a["reasons"]), a["reasons"])
        code, a, _ = self.ask(req(when=now(+600)))
        self.assertEqual(code, 10)
        self.assertTrue(any("in the future" in s for s in a["reasons"]), a["reasons"])
        self.assertEqual(self.ask(req(when=now(-100)))[0], 0)
        utc_z = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")      # a Z suffix is accepted too
        self.assertEqual(self.ask(req(when=utc_z))[0], 0)

    def test_malformed_requests_are_refused_and_logged(self):
        code, a, _ = self.ask(req(sha="abc123"))
        self.assertEqual(code, 10)
        self.assertIn("The commit must be a full 40-character sha.", a["reasons"])
        self.assertIn("The repository must be written owner/name.", self.ask(req(repo="argus-ui"))[1]["reasons"])
        self.assertIn("The client address must be an IP address.", self.ask(req(ip="phone"))[1]["reasons"])
        self.assertTrue(any("The action must be one of" in s for s in self.ask(req(action="deploy-now"))[1]["reasons"]))
        self.assertIn("via must be elaia or ssh.", self.ask(req(via="carrier-pigeon"))[1]["reasons"])
        code, a, _ = self.ask(None, raw="not json")
        self.assertEqual(code, 10)
        self.assertIn("one JSON object", a["reasons"][0])
        code, a, _ = self.ask(None, raw="[" + "1," * 3000 + "1]")
        self.assertEqual(code, 10)
        self.assertEqual(len(self.log_lines()), 7)

    def test_unknown_peer_and_tailscale_down_are_exit_2(self):
        code, a, _ = self.ask(req(ip="192.0.2.99"))
        self.assertEqual((code, a["verdict"]), (2, "failed"))
        self.assertTrue(any("could not ask the tailnet" in s for s in a["reasons"]), a["reasons"])
        code, a, _ = self.ask(req(), JANUS_FAKE_WHOIS="fail")
        self.assertEqual((code, a["verdict"]), (2, "failed"))
        self.assertEqual(self.log_lines()[-1]["verdict"], "failed")

    def test_broken_routes_file_is_exit_2(self):
        doc = json.loads(json.dumps(self.realm.routes_doc))
        doc["kinds"]["note"]["ext"].append(".exe")
        self.realm.write(doc)
        code, a, _ = self.ask(req())
        self.assertEqual((code, a["verdict"]), (2, "failed"))
        self.assertIn("cannot use his routes file", a["reasons"][0])

    def test_routes_flag_judges_by_another_file(self):
        other = Path(self.tmp.name) / "other.json"
        doc = json.loads(json.dumps(self.realm.routes_doc))
        doc["approvers"]["zeus"]["nodes"] = ["laptop"]
        other.write_text(json.dumps(doc))
        code, a, _ = self.realm.cli("verify-approval", "--routes", str(other), input=json.dumps(req(ip=LAPTOP_IP)), JANUS_STATE=str(self.state)).returncode, None, None
        self.assertEqual(code, 0)

    def test_no_approvers_entry_refuses_everyone(self):
        doc = json.loads(json.dumps(self.realm.routes_doc))
        del doc["approvers"]
        self.realm.write(doc)
        code, a, _ = self.ask(req())
        self.assertEqual(code, 10)
        self.assertIn("nobody may approve", a["reasons"][0])
