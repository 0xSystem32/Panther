import ipaddress
import os
import tempfile
import unittest

from panther import demo, history


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


class DemoDataTests(unittest.TestCase):
    def test_fictional_network_is_consistent(self):
        ds = demo.devices()
        self.assertEqual(len({d["ip"] for d in ds}), len(ds))
        self.assertEqual(len({d["mac"] for d in ds}), len(ds))
        for d in ds:
            self.assertTrue(ipaddress.ip_address(d["ip"]).is_private)
            self.assertTrue(d["mac"].startswith("a4:00:5e:"))                       # préfixe fictif, jamais une vraie MAC
        self.assertEqual(sum(d["is_self"] for d in ds), 1)
        self.assertEqual(sum(d["is_gateway"] for d in ds), 1)
        self.assertEqual({d["network"] for d in ds}, {demo.NET, demo.VLAN})

    def test_offline_device_is_not_in_the_online_list(self):
        self.assertNotIn("ancien-pc", [d["hostname"] for d in demo.online_devices()])
        self.assertIn("ancien-pc", [d["hostname"] for d in demo.devices()])

    def test_security_findings_only_when_asked(self):
        self.assertTrue(all(d["security"] is None for d in demo.devices()))
        cam = next(d for d in demo.devices(sec=True) if d["hostname"] == "camera-garage")
        self.assertTrue(cam["security"])


class DemoScannerTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.sc = demo.DemoScanner(duration=10, clock=self.clock)

    def test_idle_before_start(self):
        s = self.sc.snapshot()
        self.assertEqual((s["status"], s["devices"], s["progress"]), ("idle", [], 0))

    def test_progress_and_devices_grow_then_finish_with_everybody(self):
        self.assertTrue(self.sc.start())
        counts = []
        for t in (1, 3, 5, 7, 9):
            self.clock.t = 100 + t
            s = self.sc.snapshot()
            self.assertEqual(s["status"], "scanning")
            counts.append(len(s["devices"]))
        self.assertEqual(counts, sorted(counts))
        self.assertEqual(counts[0], 0)                                               # rien pendant la découverte
        self.clock.t = 111
        s = self.sc.snapshot()
        self.assertEqual((s["status"], s["progress"], len(s["devices"])), ("done", 100, len(demo.online_devices())))
        self.assertEqual(s["network"]["cidr"], demo.NET)

    def test_cannot_start_twice_but_can_restart_after_the_end(self):
        self.assertTrue(self.sc.start()); self.assertFalse(self.sc.start())
        self.clock.t = 120
        self.assertTrue(self.sc.start())

    def test_stop_keeps_what_was_found(self):
        self.sc.start(); self.clock.t = 107
        self.assertTrue(self.sc.stop())
        s = self.sc.snapshot()
        self.assertEqual(s["status"], "stopped")
        self.assertTrue(0 < len(s["devices"]) < len(demo.online_devices()))
        self.clock.t = 150
        self.assertEqual(len(self.sc.snapshot()["devices"]), len(s["devices"]))     # figé
        self.assertFalse(self.sc.stop())

    def test_security_and_listening_mode(self):
        self.sc.start(security=True); self.clock.t = 120
        self.assertTrue(any(d["security"] for d in self.sc.snapshot()["devices"]))
        self.sc.start(depth="ecoute", security=True); self.clock.t = 140
        s = self.sc.snapshot()
        self.assertFalse(s["security"])

    def test_snapshot_is_a_copy(self):
        self.sc.start(); self.clock.t = 120
        self.sc.snapshot()["devices"][0]["hostname"] = "modifié"
        self.assertNotEqual(self.sc.snapshot()["devices"][0]["hostname"], "modifié")


class SeedTests(unittest.TestCase):
    def test_seed_history_builds_a_past_with_an_offline_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            old, history.PATH = history.PATH, os.path.join(tmp, "p.db")
            try:
                demo.seed_history(now=1_800_000_000)
                self.assertEqual(len(history.list_scans()), 2)
                self.assertTrue(history.recent_events())                                  # le journal n'est pas vide dès le départ
            finally:
                history.PATH = old


if __name__ == "__main__":
    unittest.main()
