import unittest
from unittest import mock

from panther import exporter, scanner

OUT = """\
2001:db8:0:1:5054:ff:fe12:3456 dev wlp3s0 lladdr 52:54:00:12:34:56 router STALE
fe80::5054:ff:fe12:3456 dev wlp3s0 lladdr 52:54:00:12:34:56 router REACHABLE
fe80::1c2:3ff:fe04:506 dev wlp3s0 lladdr AA:BB:CC:00:00:10 REACHABLE
fe80::dead:beef dev wlp3s0  FAILED
fe80::cafe dev wlp3s0 lladdr aa:bb:cc:00:00:11 INCOMPLETE
ff02::1 dev wlp3s0 lladdr 33:33:00:00:00:01 NOARP
::1 dev lo lladdr 00:00:00:00:00:00 PERMANENT
pas une adresse dev x lladdr aa:bb:cc:00:00:12 STALE
2001:db8::5 dev wlp3s0 lladdr aa:bb:cc:00:00:13 DELAY
"""


class Ipv6Tests(unittest.TestCase):
    def test_parse_groups_by_mac_and_drops_noise(self):
        r = scanner.parse_ipv6_neighbors(OUT)
        self.assertEqual(r["52:54:00:12:34:56"], ["2001:db8:0:1:5054:ff:fe12:3456", "fe80::5054:ff:fe12:3456"])   # globale d'abord
        self.assertEqual(r["aa:bb:cc:00:00:10"], ["fe80::1c2:3ff:fe04:506"])                                                 # MAC en minuscules
        self.assertEqual(r["aa:bb:cc:00:00:13"], ["2001:db8::5"])
        self.assertNotIn("aa:bb:cc:00:00:11", r)                                                                             # INCOMPLETE
        self.assertNotIn("aa:bb:cc:00:00:12", r)                                                                             # adresse invalide
        self.assertEqual(len(r), 3)                                                                                          # ni multicast, ni boucle locale, ni FAILED

    def test_limit_garbage_and_huge_input(self):
        many = "\n".join(f"fe80::{i:x} dev e lladdr aa:bb:cc:00:00:01 REACHABLE" for i in range(1, 30))
        self.assertEqual(len(scanner.parse_ipv6_neighbors(many)["aa:bb:cc:00:00:01"]), 4)
        self.assertEqual(scanner.parse_ipv6_neighbors(""), {})
        self.assertEqual(scanner.parse_ipv6_neighbors("\x00\xff garbage\n" * 5000), {})

    def test_neighbors_reads_the_kernel_table_for_one_interface(self):
        with mock.patch.object(scanner.networks, "_run", lambda cmd: OUT if cmd[:4] == ["ip", "-6", "neigh", "show"] and cmd[-1] == "wlp3s0" else "") as run:
            self.assertIn("aa:bb:cc:00:00:10", scanner.ipv6_neighbors("wlp3s0"))
            self.assertEqual(scanner.ipv6_neighbors("eth9"), {})
            self.assertTrue(run)

    def test_nudge_is_one_multicast_ping_and_never_raises(self):
        calls = []
        with mock.patch.object(scanner.subprocess, "run", lambda *a, **k: calls.append(a[0])):
            scanner.ipv6_nudge("eth0")
        self.assertEqual(calls, [["ping", "-6", "-c1", "-W1", "ff02::1%eth0"]])
        with mock.patch.object(scanner.subprocess, "run", side_effect=OSError("pas de ping")):
            scanner.ipv6_nudge("eth0")

    def test_export_has_an_ipv6_column(self):
        d = {"ip": "10.0.0.5", "hostname": "x", "type": "tv", "online": True, "mac": "aa", "ports": [], "services": [], "ipv6": ["fe80::1", "2001:db8::5"]}
        self.assertEqual(exporter.row(d)["ipv6"], "fe80::1 2001:db8::5")
        self.assertIn("ipv6", [k for k, _l in exporter.COLUMNS])


if __name__ == "__main__":
    unittest.main()
