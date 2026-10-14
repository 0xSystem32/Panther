import ipaddress
import unittest
from unittest import mock

from panther import scanner
from panther import topology
from tests.test_snmp import FakeAgent, switch_data


class ScannerSnmpTests(unittest.TestCase):
    def setUp(self):
        self.agent = FakeAgent(switch_data())
        self.agent.start()
        self.nets = [ipaddress.ip_network("192.168.20.0/24")]

    def tearDown(self):
        self.agent.stop = True
        self.agent.join(1)
        self.agent.sock.close()

    def test_router_arp_reveals_hosts_and_macs_of_other_vlan(self):
        found = set()
        arp, fdb, warnings, info = scanner.Scanner()._read_snmp(
            [{"host": "127.0.0.1", "community": "public", "port": self.agent.port}], self.nets, found)
        self.assertEqual(len(found), 45)                       # hôtes vus par le routeur, même muets
        self.assertEqual(arp["192.168.20.9"], "aa:bb:cc:00:00:09")
        self.assertEqual(fdb["aa:bb:cc:00:11:22"], {"vlan": 20, "port": "Gi1/0/3", "switch": "core-sw"})
        self.assertEqual((warnings, info[0]["name"]), ([], "core-sw"))

    def test_hosts_outside_scanned_networks_are_not_added(self):
        found = set()
        scanner.Scanner()._read_snmp([{"host": "127.0.0.1", "community": "public", "port": self.agent.port}],
                                     [ipaddress.ip_network("10.9.9.0/24")], found)
        self.assertEqual(found, set())

    def test_bad_community_becomes_a_warning_not_a_crash(self):
        with mock.patch("panther.snmp.read_tables", side_effect=scanner.snmp.SnmpError("pas de réponse")):
            _, _, warnings, info = scanner.Scanner()._read_snmp([{"host": "192.168.1.254", "community": "x"}], self.nets, set())
        self.assertIn("SNMP 192.168.1.254", warnings[0])
        self.assertEqual(info, [])

    def test_public_snmp_host_is_refused(self):
        _, _, warnings, _ = scanner.Scanner()._read_snmp([{"host": "8.8.8.8", "community": "public"}], self.nets, set())
        self.assertIn("non privée", warnings[0])

    def test_paths_use_traceroute_to_a_live_host(self):
        calls = []
        with mock.patch.object(topology, "traceroute", lambda ip: calls.append(ip) or ["192.168.1.1", ip]):
            paths = scanner.Scanner()._trace_paths(self.nets, {"192.168.20.30", "192.168.20.10", "192.168.1.5"})
        self.assertEqual(calls, ["192.168.20.10"])
        self.assertEqual(paths["192.168.20.0/24"], ["192.168.1.1", "192.168.20.10"])

    def test_snmp_bridge_and_lldp_neighbour_are_reclassified_as_switch_keeping_manual_type(self):
        sc = scanner.Scanner(); sc.overrides = {}
        def mk(ip, **kw):
            d = {"ip": ip, "mac": "", "vendor": "", "hostname": "h", "ports": [], "services": [], "banners": {}, "ttl": 64,
                 "is_gateway": False, "is_self": False, "random_mac": False, "mdns_services": [], "mdns_names": [],
                 "mdns_txt": {}, "ssdp": {}, "os": "Inconnu", "type": "unknown", "confidence": 0, "reasons": []}
            d.update(kw); return d
        a, b, c, gw = mk("192.168.1.2"), mk("192.168.1.3"), mk("192.168.1.4"), mk("192.168.1.1", is_gateway=True, type="router")
        sc.overrides = {"ip:192.168.1.4": {"type": "nas"}}                      # type choisi à la main : doit survivre
        sc._apply_switch_hints([a, b, c, gw], [{"host": "192.168.1.2", "fdb": 12}, {"host": "192.168.1.1", "fdb": 5}],
                               [{"mgmt_ip": "192.168.1.3"}, {"mgmt_ip": "192.168.1.4"}])
        self.assertEqual((a["type"], b["type"], c["type"], gw["type"]), ("switch", "switch", "nas", "router"))
        self.assertEqual(c["auto_type"], "switch")


if __name__ == "__main__":
    unittest.main()
