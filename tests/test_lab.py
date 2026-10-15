"""Scan complet d'un vrai réseau virtuel (VLAN 802.1Q, routeur, hôtes avec services), sans root : voir `tools/lab.py`.
Ignoré si le noyau n'autorise pas les espaces de noms sans privilèges (certaines machines d'intégration)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import lab

AVAILABLE = lab.available()


@unittest.skipUnless(AVAILABLE, "espaces de noms réseau sans privilèges indisponibles")
class LabScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = lab.run_scenario(targets=("192.168.20.0/24", "192.168.40.0/24"))
        cls.by_ip = {d["ip"]: d for d in cls.r["devices"]}

    def test_scan_completes_in_reasonable_time(self):
        self.assertEqual(self.r["status"], "done", self.r["error"])
        self.assertLess(self.r["duration"], 90)

    def test_attached_vlan_is_found_automatically_and_scanned_by_arp(self):
        self.assertEqual(self.r["auto_targets"], ["192.168.30.0/24"])
        self.assertEqual(self.r["vlan_ids"], {"s0.30": 30})
        nets = {n["cidr"]: n for n in self.r["networks"]}
        self.assertEqual((nets["192.168.30.0/24"]["kind"], nets["192.168.30.0/24"]["vlan"]), ("interface", 30))
        iot = self.by_ip["192.168.30.10"]
        self.assertTrue(iot["mac"], "l'ARP donne la MAC d'un hôte d'un VLAN rattaché")
        self.assertEqual(iot["vlan"], 30)
        self.assertEqual(iot["path"], [], "réseau rattaché : aucun routeur à traverser")
        self.assertEqual(iot["ports"], [80, 1883])

    def test_own_address_on_the_vlan_is_this_machine(self):
        self.assertTrue(self.by_ip["192.168.30.2"]["is_self"])
        self.assertTrue(self.by_ip["192.168.1.2"]["is_self"])

    def test_routed_vlan_through_the_router(self):
        nets = {n["cidr"]: n for n in self.r["networks"]}
        self.assertEqual(nets["192.168.20.0/24"]["kind"], "routé")
        self.assertEqual(self.r["paths"]["192.168.20.0/24"], ["192.168.20.1"])
        srv = self.by_ip["192.168.20.10"]
        self.assertEqual(srv["ports"], [22, 80])
        self.assertEqual(srv["path"], ["192.168.20.1"])
        self.assertEqual(srv["mac"], "", "pas de MAC au-delà d'un routeur")

    def test_unreachable_range_gives_a_warning(self):
        self.assertTrue(any("192.168.40.0/24" in w for w in self.r["warnings"]), self.r["warnings"])

    def test_security_findings_without_false_positives(self):
        sec = {ip: d["security"] for ip, d in self.by_ip.items()}
        self.assertIn("redis-open", sec["192.168.1.11"])
        self.assertNotIn("redis-open", sec["192.168.1.15"], "Redis protégé par mot de passe : pas de constat critique")
        self.assertIn("rtsp-open", sec["192.168.1.10"])
        self.assertIn("telnet", sec["192.168.1.12"])
        self.assertEqual(sec["192.168.1.13"], [], "OpenSSH récent : rien à signaler")
        self.assertEqual(sec["192.168.1.16"], [])

    def test_gateway_and_types(self):
        gw = self.by_ip["192.168.1.1"]
        self.assertTrue(gw["is_gateway"])
        self.assertEqual(gw["type"], "router")
        self.assertEqual(self.by_ip["192.168.1.10"]["type"], "camera")
        self.assertEqual(self.by_ip["192.168.1.14"]["type"], "printer")


@unittest.skipUnless(AVAILABLE, "espaces de noms réseau sans privilèges indisponibles")
class LabSwitchTests(unittest.TestCase):
    """Un routeur/switch fictif répond en SNMP (vrai UDP) et émet de vraies trames LLDP/CDP."""

    @classmethod
    def setUpClass(cls):
        cls.r = lab.run_scenario(snmp=True, security=False)
        cls.by_ip = {d["ip"]: d for d in cls.r["devices"]}

    def test_snmp_reads_the_switch_over_the_network(self):
        self.assertEqual(self.r["snmp"], [{"host": "192.168.1.1", "name": "core-sw", "arp": 2, "fdb": 2}])
        self.assertEqual(self.r["warnings"], [])

    def test_switch_ports_come_from_the_forwarding_table(self):
        cam = self.by_ip["192.168.1.10"]
        self.assertEqual((cam["switch"], cam["switch_port"], cam["vlan"]), ("core-sw", "Gi1/0/3", 1))
        self.assertEqual(self.by_ip["192.168.1.11"]["switch_port"], "Gi1/0/4")

    def test_router_with_a_forwarding_table_is_flagged_as_switch(self):
        self.assertTrue(self.by_ip["192.168.1.1"]["is_switch"])

    def test_hosts_of_the_routed_vlan_get_their_mac_from_the_router_arp_table(self):
        self.assertTrue(self.by_ip["192.168.20.10"]["mac"])
        self.assertTrue(self.by_ip["192.168.20.11"]["mac"])

    def test_snmp_v3_over_the_network(self):
        r = lab.run_scenario(snmp=True, v3=True, security=False, targets=())
        self.assertEqual(r["snmp"], [{"host": "192.168.1.1", "name": "core-sw", "arp": 2, "fdb": 2}])
        self.assertEqual(r["warnings"], [])
        cam = next(d for d in r["devices"] if d["ip"] == "192.168.1.10")
        self.assertEqual((cam["switch"], cam["switch_port"]), ("core-sw", "Gi1/0/3"))

    def test_ipv6_neighbours_are_read_for_lan_devices(self):
        withv6 = [d for d in self.r["devices"] if d["ip"].startswith("192.168.1.") and d.get("ipv6")]
        self.assertGreaterEqual(len(withv6), 3, "les hôtes du LAN ont une adresse fe80:: connue du noyau après le ping multicast")
        self.assertTrue(all(a.startswith("fe80:") for d in withv6 for a in d["ipv6"]))

    def test_lldp_and_cdp_frames_are_received_from_the_wire(self):
        r = lab.run_scenario(name="lldp")
        self.assertEqual(r["status"], "ok")
        got = {n["proto"]: n for n in r["neighbors"]}
        self.assertEqual((got["LLDP"]["name"], got["LLDP"]["port"], got["LLDP"]["vlan"], got["LLDP"]["vlan_names"]), ("core-sw", "Gi1/0/3", 20, {"20": "SERVEURS"}))
        self.assertEqual((got["CDP"]["name"], got["CDP"]["platform"], got["CDP"]["mgmt_ip"]), ("dist-sw", "cisco WS-C2960", "192.168.1.253"))


if __name__ == "__main__":
    unittest.main()
