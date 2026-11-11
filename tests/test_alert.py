"""The alert file and `janus ack` (issue #13; docs/plans/2026-11-09-map-page.md section 3.6). A door that should be open
and is closed makes one alert file that names its doors; `janus ack` marks the doors of the current alert as seen,
which quiets Argus until one of those doors changes. Same stand-ins as test_mapper.py: the fake tailscale, local
listeners and a temporary realm per test; the device names are invented."""
import json
import subprocess
import sys
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from janus import mapper
from tests.helpers import ROOT, snapshot
from tests.test_mapper import DOT, T0, MapCase, fcntl, stamp

ACK_ONE = "Marked 1 closed door as seen: homeserver's jellyfin. Argus stays quiet about it until it changes."
ACK_TWO = ("Marked 2 closed doors as seen: homeserver's jellyfin, desktop's apollo. "
           "Argus stays quiet about them until one of them changes.")
NOTHING = "Nothing to mark as seen."


class AlertCase(MapCase):
    def close(self, *ports):
        """Shut these doors and run twice: the second failed probe is the one that calls a door closed."""
        for p in ports:
            p.shut()
        self.run_map()
        return self.run_map()

    def probe(self, did):
        """What the last probe of a door said (a closed port is refused on Linux, a timeout elsewhere)."""
        return self.door(self.map(), did)["probe"]

    def ack(self, **env):
        return self.realm.cli("ack", **env)

    def acked_ok(self, text):
        r = self.ack()
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, text + "\n", ""))


class AlertFileTest(AlertCase):
    def test_an_unexpected_close_writes_the_file_with_the_sentence(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.run_map()
        self.assertIsNone(self.alert())
        self.run_map()
        self.assertEqual(self.alert(), {
            "job": "janus-map", "level": "alert", "since": stamp(2), "link": "map",
            "message": "homeserver's jellyfin door closed unexpectedly (%s). Open the Map for its history."
                       % self.probe("homeserver/jellyfin")})

    def test_a_reopen_removes_the_file(self):
        self.world()
        self.close(self.jellyfin)
        self.assertIsNotNone(self.alert())
        self.jellyfin.open()
        self.run_map()
        self.assertIsNone(self.alert())

    def test_two_doors_make_one_file_that_names_both(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.apollo.shut()
        self.run_map()
        doc = self.run_map()
        self.assertEqual(doc["alert"]["doors"], ["homeserver/jellyfin", "desktop/apollo"])
        self.assertEqual(self.alert()["message"], "2 doors closed unexpectedly: homeserver's jellyfin, desktop's apollo. "
                                                  "Open the Map for their history.")
        self.assertEqual([p.name for p in self.alerts.iterdir()], ["janus.json"])

    def test_a_second_door_gives_one_file_and_a_new_message(self):
        self.world()
        self.close(self.jellyfin)
        self.assertIn("homeserver's jellyfin door closed unexpectedly", self.alert()["message"])
        self.apollo.shut()
        self.run_map()
        self.run_map()
        self.assertEqual(self.alert()["message"], "2 doors closed unexpectedly: homeserver's jellyfin, desktop's apollo. "
                                                  "Open the Map for their history.")
        self.assertEqual([p.name for p in self.alerts.iterdir()], ["janus.json"])

    def test_three_doors_are_all_named(self):
        self.world()
        self.devices["{{SERVER}}"]["doors"]["sunshine"]["expect"] = "always"
        self.doors_are(self.devices)
        self.run_map()
        self.jellyfin.shut()
        self.sunshine.shut()
        self.apollo.shut()
        self.run_map()
        self.run_map()
        self.assertEqual(self.alert()["message"],
                         "3 doors closed unexpectedly: homeserver's jellyfin, homeserver's sunshine, desktop's apollo. "
                         "Open the Map for their history.")

    def test_more_than_three_doors_name_the_first_three_and_count_the_rest(self):
        self.world()
        self.devices["{{SERVER}}"]["doors"]["sunshine"]["expect"] = "always"
        extra = [self.port() for _ in range(3)]
        for i, p in enumerate(extra):
            self.devices["{{SERVER}}"]["doors"]["extra%d" % i] = {"port": p.port}
        self.doors_are(self.devices)
        self.run_map()
        for p in [self.jellyfin, self.sunshine, self.apollo] + extra:
            p.shut()
        self.run_map()
        doc = self.run_map()
        self.assertEqual(len(doc["alert"]["doors"]), 6)
        message = self.alert()["message"]
        self.assertEqual(message, "6 doors closed unexpectedly: homeserver's jellyfin, homeserver's sunshine, "
                                  "homeserver's extra0 and 3 more. Open the Map for their history.")
        self.assertLessEqual(len(message), 300)

    def test_the_names_never_hold_an_address_or_the_tailnet_name(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.apollo.shut()
        self.run_map()
        self.run_map()
        text = json.dumps(self.alert())
        for forbidden in ("127.0.0.1", "example.ts.net", "{{"):
            self.assertNotIn(forbidden, text)

    def test_the_file_is_valid_for_argus_ui_and_written_atomically(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.apollo.shut()
        self.run_map()
        self.run_map()
        alert = self.alert()                    # argus-ui docs/alerts.md
        self.assertEqual(sorted(alert), ["job", "level", "link", "message", "since"])
        self.assertTrue(alert["job"].startswith("janus-"))
        self.assertEqual((alert["level"], alert["link"]), ("alert", "map"))
        self.assertLessEqual(len(alert["message"]), 300)
        self.assertNotIn("\n", alert["message"])
        self.assertEqual(datetime.fromisoformat(alert["since"]), T0 + timedelta(minutes=10))
        self.assertEqual(list(self.tmp.rglob("*.tmp")), [])


class AckTest(AlertCase):
    def test_ack_removes_the_file_marks_the_door_and_exits_0(self):
        self.world()
        self.close(self.jellyfin)
        self.assertIsNotNone(self.alert())
        self.acked_ok(ACK_ONE)
        self.assertIsNone(self.alert())
        self.assertEqual(list(self.alerts.iterdir()), [])
        doc = self.map()
        self.assertEqual(doc["alert"], {"doors": [], "since": None, "acked": ["homeserver/jellyfin"]})
        self.assertEqual(self.door(doc, "homeserver/jellyfin")["state"], "closed")      # the door itself is untouched
        self.assertIn("1 closed unexpectedly", doc["line"])
        self.assertEqual(doc["counts"]["unexpected"], 1)
        self.assertEqual(list(self.tmp.rglob("*.tmp")), [])

    def test_ack_names_every_door_of_the_set(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.apollo.shut()
        self.run_map()
        self.run_map()
        self.acked_ok(ACK_TWO)
        self.assertEqual(self.map()["alert"], {"doors": [], "since": None, "acked": ["homeserver/jellyfin", "desktop/apollo"]})
        self.assertIsNone(self.alert())

    def test_ack_names_the_first_three_and_counts_the_rest(self):
        self.world()
        self.devices["{{SERVER}}"]["doors"]["sunshine"]["expect"] = "always"
        extra = [self.port() for _ in range(2)]
        for i, p in enumerate(extra):
            self.devices["{{SERVER}}"]["doors"]["extra%d" % i] = {"port": p.port}
        self.doors_are(self.devices)
        self.run_map()
        for p in [self.jellyfin, self.sunshine, self.apollo] + extra:
            p.shut()
        self.run_map()
        self.run_map()
        self.acked_ok("Marked 5 closed doors as seen: homeserver's jellyfin, homeserver's sunshine, homeserver's extra0 "
                      "and 2 more. Argus stays quiet about them until one of them changes.")

    def test_ack_with_nothing_to_clear_is_exit_0_and_writes_nothing(self):
        self.world()
        self.run_map()
        self.age()
        before = snapshot(self.state), snapshot(self.alerts)
        self.acked_ok(NOTHING)
        self.assertEqual((snapshot(self.state), snapshot(self.alerts)), before)

    def test_ack_a_second_time_has_nothing_to_mark(self):
        self.world()
        self.close(self.jellyfin)
        self.acked_ok(ACK_ONE)
        self.age()
        before = snapshot(self.state), snapshot(self.alerts)
        self.acked_ok(NOTHING)
        self.assertEqual((snapshot(self.state), snapshot(self.alerts)), before)
        self.assertEqual(self.map()["alert"]["acked"], ["homeserver/jellyfin"])

    def test_ack_with_no_map_is_exit_0_and_writes_nothing(self):
        self.world()
        r = self.ack()
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, NOTHING + "\n", ""))
        self.assertFalse((self.state / "map.json").exists())
        self.assertFalse(self.alerts.exists() and list(self.alerts.iterdir()))

    def test_ack_with_a_broken_map_is_exit_2_and_writes_nothing(self):
        self.world()
        self.state.mkdir(parents=True)
        (self.state / "map.json").write_text("{ not json", encoding="utf-8")
        self.alerts.mkdir(parents=True)
        (self.alerts / "janus.json").write_text('{"keep": true}', encoding="utf-8")
        before = snapshot(self.state), snapshot(self.alerts)
        r = self.ack()
        self.assertEqual((r.returncode, r.stdout), (2, ""))
        self.assertTrue(r.stderr.startswith("janus ack: ") and "is not a version 1 map" in r.stderr, r.stderr)
        self.assertEqual(len(r.stderr.splitlines()), 1)
        self.assertEqual((snapshot(self.state), snapshot(self.alerts)), before)

    def test_ack_needs_neither_tailscale_nor_doors_json(self):
        self.world()
        self.close(self.jellyfin)
        self.realm.doors.write_text("{ not json", encoding="utf-8")
        r = self.ack(JANUS_FAKE_STATUS="fail")
        self.assertEqual((r.returncode, r.stdout.startswith("Marked 1 closed door"), r.stderr), (0, True, ""))

    @unittest.skipUnless(fcntl, "runs are serialised with flock, which this platform doesn't have")
    def test_ack_waits_for_a_run_that_holds_the_lock_and_never_writes_half_a_file(self):
        self.world()
        self.close(self.jellyfin)
        with mapper.locked():
            p = subprocess.Popen([sys.executable, "-m", "janus", "ack"], cwd=ROOT, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
            self.addCleanup(p.kill)
            with self.assertRaises(subprocess.TimeoutExpired):
                p.wait(1.5)                     # it waits, as a second run of `janus map` does
            self.assertEqual(self.map()["alert"]["acked"], [])
            self.assertIsNotNone(self.alert())
        out, err = p.communicate(timeout=30)
        self.assertEqual((p.returncode, out, err), (0, ACK_ONE + "\n", ""))
        self.assertEqual(self.map()["alert"]["acked"], ["homeserver/jellyfin"])
        self.assertIsNone(self.alert())

    def test_help_lists_ack(self):
        r = self.realm.cli("--help")
        self.assertIn("ack", r.stdout)
        r = self.realm.cli("ack", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("seen", r.stdout)


class KeepsAckTest(AlertCase):
    """`janus map` after an acknowledgement: quiet until the door changes, then loud again."""
    def test_an_acknowledged_door_stays_quiet_run_after_run_and_writes_nothing(self):
        self.world()
        self.close(self.jellyfin)
        self.acked_ok(ACK_ONE)
        self.age()
        before = snapshot(self.state), snapshot(self.alerts)
        for _ in range(3):
            doc = self.run_map()
        self.assertEqual(doc["alert"], {"doors": [], "since": None, "acked": ["homeserver/jellyfin"]})
        self.assertEqual((snapshot(self.state), snapshot(self.alerts)), before)
        self.assertIsNone(self.alert())

    def test_an_acknowledged_door_that_reopens_and_closes_again_alerts_again(self):
        self.world()
        self.close(self.jellyfin)
        self.acked_ok(ACK_ONE)
        self.jellyfin.open()
        doc = self.run_map()
        self.assertEqual(doc["alert"], {"doors": [], "since": None, "acked": []})
        self.jellyfin.shut()
        self.run_map()
        doc = self.run_map()
        self.assertEqual(doc["alert"], {"doors": ["homeserver/jellyfin"], "since": stamp(4), "acked": []})
        self.assertIn("homeserver's jellyfin door closed unexpectedly", self.alert()["message"])

    def test_an_acknowledged_door_whose_room_sleeps_and_wakes_closed_alerts_again(self):
        self.world()
        self.close(self.apollo)
        self.acked_ok("Marked 1 closed door as seen: desktop's apollo. Argus stays quiet about it until it changes.")
        self.online(desktop=False)
        doc = self.run_map()
        self.assertEqual(doc["alert"]["acked"], [])
        self.online(desktop=True)
        self.run_map()
        self.assertIsNone(self.alert())         # one miss never alarms
        doc = self.run_map()
        self.assertEqual(doc["alert"]["doors"], ["desktop/apollo"])
        self.assertIn("desktop's apollo door closed unexpectedly", self.alert()["message"])

    def test_a_room_that_leaves_the_tailnet_takes_its_acknowledgement_with_it(self):
        self.world()
        self.close(self.apollo)
        self.acked_ok("Marked 1 closed door as seen: desktop's apollo. Argus stays quiet about it until it changes.")
        self.tailnet_is()
        doc = self.run_map()
        self.assertEqual(doc["alert"], {"doors": [], "since": None, "acked": []})

    def test_a_door_taken_out_of_doors_json_leaves_acked(self):
        self.world()
        self.close(self.jellyfin)
        self.acked_ok(ACK_ONE)
        del self.devices["{{SERVER}}"]["doors"]["jellyfin"]
        self.doors_are(self.devices)
        self.assertEqual(self.run_map()["alert"], {"doors": [], "since": None, "acked": []})

    def test_a_door_doors_json_no_longer_expects_open_leaves_acked(self):
        self.world()
        self.close(self.jellyfin)
        self.acked_ok(ACK_ONE)
        self.devices["{{SERVER}}"]["doors"]["jellyfin"]["expect"] = "sometimes"
        self.doors_are(self.devices)
        self.assertEqual(self.run_map()["alert"], {"doors": [], "since": None, "acked": []})

    def test_one_of_two_acknowledged_doors_reopens_and_the_other_stays_quiet(self):
        self.world()
        self.run_map()
        self.jellyfin.shut()
        self.apollo.shut()
        self.run_map()
        self.run_map()
        self.acked_ok(ACK_TWO)
        self.apollo.open()
        doc = self.run_map()
        self.assertEqual(doc["alert"], {"doors": [], "since": None, "acked": ["homeserver/jellyfin"]})
        self.assertIsNone(self.alert())
        self.assertEqual(self.door(doc, "desktop/apollo")["state"], "open")

    def test_a_third_door_closing_brings_the_file_back_naming_only_the_new_one(self):
        self.world()
        self.devices["{{SERVER}}"]["doors"]["sunshine"]["expect"] = "always"
        self.doors_are(self.devices)
        self.run_map()
        self.jellyfin.shut()
        self.apollo.shut()
        self.run_map()
        self.run_map()
        self.acked_ok(ACK_TWO)
        self.sunshine.shut()
        self.run_map()
        doc = self.run_map()
        self.assertEqual(doc["alert"], {"doors": ["homeserver/sunshine"], "since": stamp(4),
                                        "acked": ["homeserver/jellyfin", "desktop/apollo"]})
        self.assertEqual(self.alert(), {
            "job": "janus-map", "level": "alert", "since": stamp(4), "link": "map",
            "message": "homeserver's sunshine door closed unexpectedly (%s). Open the Map for its history."
                       % self.probe("homeserver/sunshine")})
        self.assertEqual(doc["line"], "1 door open" + DOT + "3 closed unexpectedly" + DOT + "laptop asleep")
        self.acked_ok("Marked 1 closed door as seen: homeserver's sunshine. Argus stays quiet about it until it changes.")
        self.assertEqual(self.map()["alert"]["acked"], ["homeserver/jellyfin", "desktop/apollo", "homeserver/sunshine"])

    def test_the_alert_since_ignores_acknowledged_doors(self):
        self.world()
        self.close(self.jellyfin)
        self.acked_ok(ACK_ONE)
        self.apollo.shut()
        self.run_map()
        doc = self.run_map()
        self.assertEqual((doc["alert"]["doors"], doc["alert"]["since"]), (["desktop/apollo"], stamp(3)))
        self.assertEqual(self.alert()["since"], stamp(3))

    def test_a_broken_map_is_drawn_again_without_acknowledgements(self):
        self.world()
        self.close(self.jellyfin)
        self.acked_ok(ACK_ONE)
        (self.state / "map.json").write_text("{ not json", encoding="utf-8")
        self.run_map()
        self.run_map()
        self.assertEqual(self.map()["alert"]["acked"], [])
        self.assertIsNotNone(self.alert())


if __name__ == "__main__":
    unittest.main()
