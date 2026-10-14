import os
import tempfile
import unittest
from unittest import mock

from panther import history, scanner
from tests.test_scan_flow import ScanFlowTests

NET = {"iface": "eth0", "ip": "192.168.1.13", "cidr": "192.168.1.0/24", "gateway": "192.168.1.1"}
REC = {"key": "aa:bb:cc:00:00:0a", "ip": "192.168.1.10", "mac": "aa:bb:cc:00:00:0a", "name": "salon-tv", "type": "tv", "vendor": "Samsung",
       "os": "Android", "network": "192.168.1.0/24", "ports": [8009, 8060], "sec": ["telnet"]}


def inspect(sc, ip="192.168.1.10", mac="aa:bb:cc:00:00:0a", net=NET):
    calls = {"ports": [], "names": 0}
    patches = [mock.patch.object(scanner, "scan_ports", lambda i, ports, t: calls["ports"].append(tuple(ports)) or []),
               mock.patch.object(scanner, "resolve_names", lambda i, t=1.5: calls.__setitem__("names", calls["names"] + 1) or ("", "", "")),
               mock.patch.object(scanner, "ping_ttl", lambda i: 64), mock.patch.object(scanner, "grab_banner", lambda i, p: "")]
    for p in patches:
        p.start()
    try:
        return sc._inspect(ip, net, {ip: mac}, {"mdns": {}, "ssdp": {}}), calls
    finally:
        for p in patches:
            p.stop()


def light_scanner(known):
    sc = scanner.Scanner(); sc.overrides = {}
    sc.profile, sc.known = scanner.PROFILES["presence"], known
    return sc


class PresenceProfileTests(unittest.TestCase):
    def test_presence_profile_is_light_and_sends_almost_nothing(self):
        p = scanner.PROFILES["presence"]
        self.assertTrue(p["light"])
        self.assertEqual((p["scan_ports"], p["ssdp"], p["mdns"], p["lldp"]), ((), 0, 0, 0))
        self.assertFalse(any(scanner.PROFILES[k]["light"] for k in ("rapide", "normal", "approfondi")))

    def test_empty_port_list_is_a_noop(self):
        self.assertEqual(scanner.scan_ports("127.0.0.1", (), 0.5), [])

    def test_known_device_is_rebuilt_from_the_last_full_scan_with_no_network_traffic(self):
        dev, calls = inspect(light_scanner({REC["key"]: REC}))
        self.assertEqual((calls["ports"], calls["names"]), ([], 0))                       # rien n'est sondé, aucun nom demandé
        self.assertEqual((dev["hostname"], dev["type"], dev["vendor"], dev["os"], dev["ports"]), ("salon-tv", "tv", "Samsung", "Android", [8009, 8060]))
        self.assertTrue(dev["light"] and dev["online"])
        self.assertIsNone(dev["security"])                                                # pas d'analyse de sécurité : pas de faux « corrigé »
        self.assertEqual(dev["services"], ["Cast", "Roku"])

    def test_manual_name_and_type_still_apply_to_known_devices(self):
        sc = light_scanner({REC["key"]: REC}); sc.overrides = {REC["key"]: {"name": "Télé", "type": "console"}}
        dev, _ = inspect(sc)
        self.assertEqual((dev["hostname"], dev["type"], dev["auto_type"]), ("Télé", "console", "tv"))

    def test_gateway_stays_a_router(self):
        rec = dict(REC, type="unknown", ip="192.168.1.1", key="aa:bb:cc:00:00:01")
        dev, _ = inspect(light_scanner({rec["key"]: rec}), ip="192.168.1.1", mac="aa:bb:cc:00:00:01")
        self.assertEqual(dev["type"], "router")

    def test_unknown_device_gets_a_full_analysis_with_normal_settings(self):
        dev, calls = inspect(light_scanner({}))
        self.assertEqual(calls["ports"], [tuple(scanner.PROFILES["normal"]["scan_ports"])])
        self.assertEqual(calls["names"], 1)
        self.assertFalse(dev.get("light"))

    def test_device_without_mac_is_matched_by_its_ip_key(self):
        rec = dict(REC, key="ip:10.0.7.20", ip="10.0.7.20", mac="", name="compta")
        dev, calls = inspect(light_scanner({"ip:10.0.7.20": rec}), ip="10.0.7.20", mac="")
        self.assertEqual((dev["hostname"], calls["names"]), ("compta", 0))

    def test_this_machine_is_never_taken_from_the_cache(self):
        sc = light_scanner({REC["key"]: dict(REC, name="faux")})
        dev, _ = inspect(sc, ip=NET["ip"], mac=REC["key"])
        self.assertFalse(dev.get("light"))


class PresenceFlowTests(unittest.TestCase):
    """Le multicast SSDP/mDNS ne part que s'il y a un appareil inconnu à identifier."""
    run_scan = ScanFlowTests.run_scan  # même réseau simulé : hôtes .1 (box) et .2 (cette machine)

    def test_no_multicast_when_everybody_is_known(self):
        sent = []
        known = {"aa:bb:cc:00:00:01": {}}                                                  # la box est connue ; .2 est cette machine
        r = self.run_scan([], depth="presence", known=known, scan_all=lambda ip, *a: sent.append(a) or ({}, {}))
        self.assertEqual((r["status"], sent), ("done", []))

    def test_multicast_runs_with_normal_timeouts_when_someone_is_unknown(self):
        sent = []
        r = self.run_scan([], depth="presence", known={}, scan_all=lambda ip, *a: sent.append(a) or ({}, {}))
        self.assertEqual(r["status"], "done")
        self.assertEqual(sent, [(scanner.PROFILES["normal"]["ssdp"], scanner.PROFILES["normal"]["mdns"])])


class LastSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "p.db")

    def tearDown(self):
        self.tmp.cleanup()

    def dev(self, ip, mac, ports=()):
        return {"ip": ip, "mac": mac, "hostname": "h" + ip[-1], "type": "tv", "vendor": "V", "network": "192.168.1.0/24", "online": True,
                "os": "L", "ports": list(ports)}

    def test_empty_history_gives_an_empty_map(self):
        self.assertEqual(history.last_snapshot_map(), {})

    def test_returns_the_devices_of_the_latest_scan_by_key(self):
        history.record_scan([self.dev("192.168.1.2", "aa:00:00:00:00:02", [80])], now=1000, networks=["192.168.1.0/24"])
        history.record_scan([self.dev("192.168.1.2", "aa:00:00:00:00:02", [80, 22]), self.dev("192.168.1.3", "aa:00:00:00:00:03")], now=2000,
                            networks=["192.168.1.0/24"])
        m = history.last_snapshot_map()
        self.assertEqual(sorted(m), ["aa:00:00:00:00:02", "aa:00:00:00:00:03"])
        self.assertEqual(m["aa:00:00:00:00:02"]["ports"], [22, 80])


if __name__ == "__main__":
    unittest.main()
