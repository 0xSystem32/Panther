"""Écoute seule : le scan ne doit RIEN envoyer sur le réseau."""
import time
import unittest
from unittest import mock

from panther import scanner

NET = {"iface": "eth0", "ip": "192.168.99.2", "cidr": "192.168.99.0/29", "gateway": "192.168.99.1"}
ARP = {"192.168.99.1": "aa:bb:cc:00:00:01", "192.168.99.5": "aa:bb:cc:00:00:05"}
REC = {"key": "aa:bb:cc:00:00:01", "ip": "192.168.99.1", "mac": "aa:bb:cc:00:00:01", "name": "box", "type": "router", "vendor": "Acme",
       "os": "Linux", "network": NET["cidr"], "ports": [80]}


def wait(sc, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        s = sc.snapshot()
        if s["status"] != "scanning":
            return s
        time.sleep(0.02)
    raise AssertionError("scan trop long")


class PassiveTests(unittest.TestCase):
    def run_passive(self, known=None, targets=(), snmp=(), security=True):
        sent = []

        def tripwire(name):
            def f(*a, **k):
                sent.append(name)
                raise AssertionError(f"{name} appelé en écoute seule")
            return f
        patches = [mock.patch.object(scanner, "local_network", lambda iface=None: dict(NET)),
                   mock.patch.object(scanner.networks, "vlan_ids", lambda: {}),
                   mock.patch.object(scanner, "read_arp", lambda: dict(ARP)),
                   mock.patch.object(scanner.dhcp, "read_leases", lambda: {"aa:bb:cc:00:00:05": "tablette-salon"}),
                   mock.patch.object(scanner.time, "sleep", lambda s: None)]
        for name in ("probe_alive", "arp_discover", "udp_nudge", "tcp_open", "scan_ports", "resolve_names", "ping_ttl", "grab_banner"):
            patches.append(mock.patch.object(scanner, name, tripwire(name)))
        patches += [mock.patch.object(scanner.discovery, "scan_all", tripwire("scan_all")),
                    mock.patch.object(scanner.topology, "discover_neighbors", tripwire("discover_neighbors")),
                    mock.patch.object(scanner.topology, "traceroute", tripwire("traceroute")),
                    mock.patch.object(scanner.snmp, "read_tables", tripwire("snmp")),
                    mock.patch.object(scanner.security, "active_probes", tripwire("active_probes"))]
        for p in patches:
            p.start()
        try:
            sc = scanner.Scanner()
            sc.start(list(targets), snmp_sources=list(snmp), depth="ecoute", security=security, known=known)
            return wait(sc), sent
        finally:
            for p in patches:
                p.stop()

    def test_profile_is_passive_and_light(self):
        p = scanner.PROFILES["ecoute"]
        self.assertTrue(p["passive"] and p["light"])
        self.assertEqual((p["scan_ports"], p["ssdp"], p["mdns"], p["lldp"], p["arp_rounds"]), ((), 0, 0, 0, 0))
        self.assertFalse(any(scanner.PROFILES[k].get("passive") for k in ("presence", "rapide", "normal", "approfondi")))

    def test_nothing_is_sent_even_with_targets_snmp_and_security_requested(self):
        r, sent = self.run_passive(known={REC["key"]: REC}, targets=["10.20.0.0/30"], snmp=[{"host": "192.168.99.1", "community": "public"}])
        self.assertEqual((r["status"], sent), ("done", []), r.get("error"))
        self.assertFalse(r["security"])                                                  # l'analyse de sécurité est coupée
        self.assertEqual(r["warnings"], [])

    def test_devices_come_from_the_kernel_table_leases_and_last_scan(self):
        r, _ = self.run_passive(known={REC["key"]: REC})
        by = {d["ip"]: d for d in r["devices"]}
        self.assertEqual(set(by), {"192.168.99.1", "192.168.99.5", "192.168.99.2"})     # box, tablette, cette machine
        self.assertEqual((by["192.168.99.1"]["hostname"], by["192.168.99.1"]["type"]), ("box", "router"))
        unknown = by["192.168.99.5"]
        self.assertEqual((unknown["hostname"], unknown["ports"], unknown["ttl"]), ("tablette-salon", [], None))
        self.assertTrue(unknown["light"])                                                # présenté comme non vérifié
        self.assertIsNone(unknown["security"])
        self.assertTrue(by["192.168.99.2"]["is_self"])

    def test_extra_ranges_are_ignored(self):
        r, sent = self.run_passive(targets=["10.20.0.0/30"])
        self.assertEqual({n["cidr"] for n in r["networks"]}, {NET["cidr"]})
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
