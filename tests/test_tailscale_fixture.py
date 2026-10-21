"""The fake tailscale in tests/fixtures/tailscale answers status, whois and ping from tests/fixtures/tailnet."""
import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FAKE = ROOT / "tests" / "fixtures" / "tailscale"


def run(*args, **env):
    with mock.patch.dict(os.environ, env):
        return subprocess.run([str(FAKE), *args], capture_output=True, text=True)


class FakeTailscaleTest(unittest.TestCase):
    def test_status(self):
        r = run("status", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["Self"]["HostName"], "homeserver")
        self.assertEqual(sorted(p["HostName"] for p in doc["Peer"].values()), ["desktop", "laptop", "phone"])

    def test_whois_names_the_node_and_the_login(self):
        r = run("whois", "--json", "192.0.2.10")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["Node"]["ComputedName"], "desktop")
        self.assertEqual(doc["UserProfile"]["LoginName"], "you@example.com")

    def test_whois_unknown_ip_fails_like_the_real_one(self):
        r = run("whois", "--json", "192.0.2.99")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no match", r.stderr)

    def test_whois_failure_modes(self):
        self.assertEqual(run("whois", "--json", "192.0.2.10", JANUS_FAKE_WHOIS="fail").returncode, 1)
        r = run("whois", "--json", "192.0.2.10", JANUS_FAKE_WHOIS="garbage")
        self.assertEqual(r.returncode, 0)
        with self.assertRaises(ValueError):
            json.loads(r.stdout)

    def test_ping(self):
        self.assertEqual(run("ping", "--c", "1", "192.0.2.10").returncode, 0)
        self.assertEqual(run("ping", "--c", "1", "192.0.2.11").returncode, 1)

    def test_unknown_command(self):
        self.assertEqual(run("file", "cp").returncode, 2)


if __name__ == "__main__":
    unittest.main()
