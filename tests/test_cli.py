"""The janus command line and its version (python3 -m janus from the checkout)."""
import subprocess
import sys
import unittest
from pathlib import Path

import janus

ROOT = Path(__file__).resolve().parent.parent
VERSION = (ROOT / "VERSION").read_text().strip()


def run(*args):
    return subprocess.run([sys.executable, "-m", "janus", *args], cwd=ROOT, capture_output=True, text=True)


class CliTest(unittest.TestCase):
    def test_version_matches_the_version_file(self):
        self.assertEqual(janus.version(), VERSION)
        self.assertRegex(VERSION, r"^\d+\.\d+\.\d+$")

    def test_version_flag(self):
        r = run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "janus " + VERSION)

    def test_no_command_prints_help(self):
        r = run()
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage: janus", r.stdout)
        self.assertIn("never carries, moves, unpacks or runs", r.stdout)

    def test_unknown_command_is_refused(self):
        r = run("unpack")
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage: janus", r.stderr)

    def test_the_commands_exist(self):
        for cmd in ("check", "verify-approval", "map", "check-config", "seen"):
            self.assertIn(cmd, run("--help").stdout)


if __name__ == "__main__":
    unittest.main()
