"""Check 1, the route (docs/design.md §3, issue #3): the route exists, the sender is who Tailscale says (never what
meta.json claims), the direction fits, and the route allows that sender."""
import json
import tempfile
import unittest

from janus import check, identity
from tests.helpers import GUEST_IP, LAPTOP_IP, PC_IP, Realm, snapshot
from tests.samples import sample

PNG = sample(".png")


class RouteCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.r = Realm(self.tmp.name)
        self.addCleanup(self.r.stop)

    def route_check(self, folder, **env):
        """Run check 1 alone and return the Verdict, so a clean route shows as ok while checks 2-4 are unbuilt."""
        import os
        v = check.Verdict()
        ctx = check.Context(check.Arrival(folder), self.r.config(), {**os.environ, **env})
        check.check_route(ctx, v)
        return v, ctx

    # --- allowed ---
    def test_pc_by_ssh_on_servermail_is_allowed(self):
        v, ctx = self.route_check(self.r.arrival("photo.png", route="servermail"))
        self.assertEqual(v.checks["route"], "ok")
        self.assertEqual(v.reasons, [])
        self.assertEqual(ctx.sender.name, "desktop")
        self.assertEqual(ctx.route.id, "servermail")

    def test_a_pattern_route_resolves(self):
        v, ctx = self.route_check(self.r.arrival("x.torrent", route="torrent-movies"))
        self.assertEqual(v.reasons, [])
        self.assertEqual(ctx.route.id, "torrent")

    def test_taildrop_elaia_fetch_and_local_senders(self):
        v, _ = self.route_check(self.r.arrival("x.torrent", route="torrent", via="taildrop"))
        self.assertEqual(v.reasons, [])
        v, _ = self.route_check(self.r.arrival("x.torrent", route="torrent", via="elaia", user="you@example.com"))
        self.assertEqual(v.reasons, [])
        v, _ = self.route_check(self.r.arrival("a.json", route="lesson", via="fetch", fetch="decks"))
        self.assertEqual(v.reasons, [])
        v, _ = self.route_check(self.r.arrival("a.png", route="pcmail", via="local", direction="out"))
        self.assertEqual(v.reasons, [])
        v, _ = self.route_check(self.r.arrival("a.png", route="phone", via="elaia", user="you@example.com", direction="out"))
        self.assertEqual(v.reasons, [])

    # --- refused ---
    def test_wrong_route(self):
        v, _ = self.route_check(self.r.arrival("a.json", route="lesson", key="laptop", ip=LAPTOP_IP))
        self.assertEqual(v.checks["route"], "fail")
        self.assertEqual(v.reasons, ["laptop may not send on the lesson route (it takes files from desktop and fetch:decks)."])

    def test_unknown_route(self):
        v, _ = self.route_check(self.r.arrival("a.png", route="scans"))
        self.assertIn("Janus knows no route named scans, so nothing can arrive on it; add it to", v.reasons[0])

    def test_key_and_node_must_name_the_same_device(self):
        v, _ = self.route_check(self.r.arrival("a.png", key="desktop", ip=LAPTOP_IP))
        self.assertEqual(v.reasons, ["The ssh key says desktop but Tailscale says laptop."])

    def test_a_self_declared_node_is_never_trusted(self):
        """meta.json says the node is desktop; Tailscale says the address is laptop's: quarantine."""
        folder = self.r.arrival("a.png", key="desktop", node="desktop", ip=LAPTOP_IP)
        self.assertEqual(json.loads((folder / "meta.json").read_text())["sender"]["node"], "desktop")
        v, _ = self.route_check(folder)
        self.assertEqual(v.reasons, ["The ssh key says desktop but Tailscale says laptop."])
        folder = self.r.arrival("a.png", key="desktop", node="desktop", ip=GUEST_IP)
        v, _ = self.route_check(folder)
        self.assertEqual(v.reasons, ["The ssh key says desktop but Tailscale says guest."])

    def test_unknown_sender(self):
        v, _ = self.route_check(self.r.arrival("a.png", key="toaster"))
        self.assertIn("No sender in", v.reasons[0])
        self.assertIn("uses the ssh key named toaster.", v.reasons[0])
        v, _ = self.route_check(self.r.arrival("a.png", key=None))
        self.assertEqual(v.reasons, ["The arrival names no ssh key, so Janus can't tell which device sent it."])
        v, _ = self.route_check(self.r.arrival("a.png", via="pigeon"))
        self.assertIn("has no known way in (via 'pigeon')", v.reasons[0])

    def test_no_address_means_no_proof(self):
        v, _ = self.route_check(self.r.arrival("a.png", ip=None))
        self.assertEqual(v.reasons, ["The arrival records no tailnet address for desktop, so Tailscale can't confirm who sent it."])

    def test_elaia_login_must_be_allowed(self):
        v, _ = self.route_check(self.r.arrival("x.torrent", route="torrent", via="elaia", user="guest@example.com"))
        self.assertIn("guest@example.com may not send through Elaia", v.reasons[0])
        v, _ = self.route_check(self.r.arrival("x.torrent", route="torrent", via="elaia"))
        self.assertIn("names no tailnet login", v.reasons[0])

    def test_fetch_job_must_be_known(self):
        v, _ = self.route_check(self.r.arrival("a.json", route="lesson", via="fetch", fetch="mystery"))
        self.assertIn("is the fetch job named mystery", v.reasons[0])
        v, _ = self.route_check(self.r.arrival("a.mp3", route="lesson", via="fetch", fetch="jellyfin-themes"))
        self.assertEqual(v.reasons, ["fetch:jellyfin-themes may not send on the lesson route (it takes files from desktop and fetch:decks)."])

    def test_direction(self):
        v, _ = self.route_check(self.r.arrival("a.png", route="pcmail", via="local", direction="in"))
        self.assertEqual(v.reasons, ["homeserver is the server itself, which can't be the sender of an incoming delivery."])
        v, _ = self.route_check(self.r.arrival("a.png", route="servermail", direction="out"))
        self.assertIn("An outbound delivery must come from the server itself or from Elaia, not from desktop by ssh.", v.reasons)
        v, _ = self.route_check(self.r.arrival("a.png", direction="sideways"))
        self.assertIn("The arrival's direction is 'sideways'; Hermes records in or out.", v.reasons)

    def test_every_route_reason_is_listed_at_once(self):
        v, _ = self.route_check(self.r.arrival("a.png", route="scans", key="toaster", direction="out"))
        self.assertEqual(len(v.reasons), 2)       # unknown route, unknown key (direction needs a resolved sender)

    # --- whois ---
    def test_whois_unavailable_is_janus_failed_never_a_pass(self):
        folder = self.r.arrival("a.png")
        code, doc = self.r.check(folder, JANUS_FAKE_WHOIS="fail")
        self.assertEqual(code, 2)
        self.assertIn("tailscale whois gave no answer for " + PC_IP, doc["failed"])
        code, doc = self.r.check(folder, JANUS_FAKE_WHOIS="garbage")
        self.assertEqual(code, 2)
        self.assertIn("not a whois record", doc["failed"])
        code, doc = self.r.check(folder, JANUS_TAILSCALE="/no/such/tailscale")
        self.assertEqual(code, 2)
        self.assertIn("could not run", doc["failed"])

    def test_whois_is_asked_once_per_address(self):
        import os
        w = identity.Whois(os.environ)
        self.assertEqual(w(PC_IP), {"node": "desktop", "login": "you@example.com"})
        w.env["JANUS_FAKE_WHOIS"] = "fail"           # a second ask would fail; the cache answers instead
        self.assertEqual(w(PC_IP)["node"], "desktop")
        with self.assertRaises(identity.Unavailable):
            w(LAPTOP_IP)

    # --- the command ---
    def test_a_refused_route_is_a_quarantine_on_the_command_line(self):
        folder = self.r.arrival("a.png", PNG, key="desktop", ip=LAPTOP_IP)
        r = self.r.cli("check", "--json", str(folder))
        self.assertEqual(r.returncode, 10, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["verdict"], "quarantine")
        self.assertEqual(doc["checks"]["route"], "fail")
        self.assertEqual(doc["reasons"], ["The ssh key says desktop but Tailscale says laptop."])
        for key in ("janus", "sha256", "kind", "checks", "reasons", "notes", "ms"):
            self.assertIn(key, doc)

    def test_a_clean_arrival_passes_on_the_command_line(self):
        folder = self.r.arrival("a.png", PNG)
        r = self.r.cli("check", "--json", str(folder))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["verdict"], "pass")
        self.assertEqual(doc["checks"], {"route": "ok", "kind": "ok", "shape": "ok", "integrity": "ok"})

    def test_without_json_the_reasons_are_printed_as_lines(self):
        folder = self.r.arrival("a.png", key="desktop", ip=LAPTOP_IP)
        r = self.r.cli("check", str(folder))
        self.assertEqual(r.returncode, 10)
        self.assertIn("quarantine: ", r.stdout)
        self.assertIn("  The ssh key says desktop but Tailscale says laptop.", r.stdout)

    def test_bad_config_or_arrival_is_janus_failed(self):
        folder = self.r.arrival("a.png")
        self.r.routes.write_text("{")
        r = self.r.cli("check", "--json", str(folder))
        self.assertEqual(r.returncode, 2)
        self.assertIn("run `janus check-config`", r.stderr)
        self.r.write()
        (folder / "meta.json").write_text("nonsense")
        self.assertEqual(self.r.cli("check", str(folder)).returncode, 2)
        (folder / "meta.json").unlink()
        self.assertEqual(self.r.cli("check", str(folder)).returncode, 2)
        self.assertEqual(self.r.cli("check", str(folder.parent / "nothing")).returncode, 2)

    def test_janus_never_writes_inside_the_arrival(self):
        folder = self.r.arrival("a.png", key="desktop", ip=LAPTOP_IP)
        before = snapshot(folder)
        self.r.cli("check", "--json", str(folder))
        self.assertEqual(snapshot(folder), before)


if __name__ == "__main__":
    unittest.main()
