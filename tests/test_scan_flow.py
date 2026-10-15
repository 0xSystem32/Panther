import time
import unittest
from unittest import mock

from panther import scanner
from panther import topology


def wait(sc):
    end = time.time() + 20
    while sc.snapshot()["status"] == "scanning" and time.time() < end:
        time.sleep(0.05)
    return sc.snapshot()


class ScanFlowTests(unittest.TestCase):
    """Le flux complet du scanner, réseau simulé : plages, avertissements, robustesse."""

    def run_scan(self, targets, inspect=None, alive=lambda ip, t=0, p=None: True, depth="normal", holder=None, known=None, scan_all=None):
        net = {"iface": "eth0", "ip": "192.168.99.2", "cidr": "192.168.99.0/30", "gateway": "192.168.99.1"}
        def fake_inspect(self_, ip, net_, arp, extra):
            if inspect:
                inspect(ip)
            return {"ip": ip, "mac": "", "vendor": "", "hostname": "h" + ip[-1], "ports": [], "services": [],
                    "banners": {}, "ttl": 64, "is_gateway": ip == net_["gateway"], "is_self": ip == net_["ip"],
                    "type": "unknown", "confidence": 0, "reasons": []}
        patches = [mock.patch.object(scanner, "local_network", lambda iface=None: dict(net, asked=iface)),
                   mock.patch.object(scanner, "probe_alive", alive),
                   mock.patch.object(scanner, "read_arp", lambda: {}),
                   mock.patch.object(scanner, "arp_discover", lambda iface, hosts, P, cancel, progress=None, **kw:
                                     ({h: "aa:bb:cc:00:00:%02x" % int(h.split(".")[-1]) for h in hosts if alive(h)}, [], True)),
                   mock.patch.object(scanner.networks, "vlan_ids", lambda: {}),
                   mock.patch.object(scanner.discovery, "scan_all", scan_all or (lambda ip, *a: ({}, {}))),
                   mock.patch.object(scanner.topology, "discover_neighbors", lambda i, s: {"status": "ok", "neighbors": []}),
                   mock.patch.object(scanner.topology, "traceroute", lambda ip: ["192.168.99.1", None]),
                   mock.patch.object(scanner.Scanner, "_inspect", fake_inspect),
                   mock.patch.object(scanner.time, "sleep", lambda s: None)]
        for p in patches:
            p.start()
        try:
            sc = scanner.Scanner()
            if holder is not None:
                holder["sc"] = sc
            sc.start(targets, depth=depth, known=known)
            return wait(sc)
        finally:
            for p in patches:
                p.stop()

    def test_extra_network_is_scanned_and_tagged(self):
        r = self.run_scan(["10.20.0.0/30"])
        self.assertEqual(r["status"], "done")
        nets = {d["network"] for d in r["devices"]}
        self.assertEqual(nets, {"192.168.99.0/30", "10.20.0.0/30"})
        self.assertEqual(r["paths"]["10.20.0.0/30"], ["192.168.99.1", None])
        self.assertEqual(r["warnings"], [])

    def test_public_range_is_ignored_with_a_warning(self):
        r = self.run_scan(["8.8.8.0/24"])
        self.assertEqual(r["status"], "done")
        self.assertTrue(any("Plage ignorée" in w for w in r["warnings"]))
        self.assertEqual({d["network"] for d in r["devices"]}, {"192.168.99.0/30"})

    def test_unreachable_network_gives_warning_with_last_hop(self):
        r = self.run_scan(["10.30.0.0/30"], alive=lambda ip, t=0, p=None: ip.startswith("192.168.99"))
        w = [x for x in r["warnings"] if "10.30.0.0/30" in x]
        self.assertTrue(w and "aucun hôte" in w[0] and "192.168.99.1" in w[0])

    def test_one_failing_device_does_not_abort_the_scan(self):
        def boom(ip):
            if ip == "192.168.99.1":
                raise OSError("réseau coupé")
        r = self.run_scan([], inspect=boom)
        self.assertEqual(r["status"], "done")
        self.assertTrue(any("192.168.99.1" in w for w in r["warnings"]))
        self.assertIn("192.168.99.2", [d["ip"] for d in r["devices"]])

    def test_routed_hosts_use_tcp_with_a_patient_second_pass_except_in_quick_mode(self):
        calls = []
        def silent(ip, t=0, p=None):
            if ip == "10.20.0.5":
                calls.append(p)
            return ip.startswith("192.168.99")
        self.run_scan(["10.20.0.5/32"], alive=silent, depth="rapide")
        self.assertEqual(calls, [scanner.PROFILES["rapide"]["disc_ports"]])                 # 1 seul passage
        calls.clear()
        r = self.run_scan(["10.20.0.5/32"], alive=silent, depth="normal")
        self.assertEqual(len(calls), 2)                                                     # 2e passe patiente
        self.assertEqual(r["depth"], "normal")

    def test_local_network_is_discovered_through_arp_not_tcp(self):
        tcp = []
        r = self.run_scan([], alive=lambda ip, t=0, p=None: (tcp.append(ip) if p is not None else None) or True)   # seules les sondes TCP passent des ports
        self.assertEqual(sorted(d["ip"] for d in r["devices"]), ["192.168.99.1", "192.168.99.2"])
        self.assertEqual(tcp, [])                                                           # aucune sonde TCP sur le réseau local

    def test_chosen_interface_is_forwarded_to_the_scan(self):
        asked = []
        orig = scanner.Scanner.start
        def spy(self_, targets=None, snmp_sources=None, depth="normal", security=False, iface=None, known=None):
            asked.append(iface); return orig(self_, targets, snmp_sources, depth, security, iface, known)
        with mock.patch.object(scanner.Scanner, "start", spy):
            r = self.run_scan([], depth="rapide")
        self.assertEqual(asked, [None])                     # sans choix : interface automatique
        sc = scanner.Scanner(); sc.start([], iface="eth9")
        self.assertEqual(sc.iface, "eth9")

    def test_unknown_depth_falls_back_to_normal(self):
        self.assertEqual(self.run_scan([], depth="nimportequoi")["depth"], "normal")

    def test_stop_keeps_status_stopped_and_does_not_hang(self):
        holder = {}
        def alive(ip, t=0, p=None):
            holder["sc"].stop(); return True
        r = self.run_scan([], alive=alive, holder=holder)
        self.assertEqual(r["status"], "stopped")

    def test_stop_when_idle_is_a_noop(self):
        self.assertFalse(scanner.Scanner().stop())

    def test_parallel_port_scan_finds_open_ports_only(self):
        import socket
        srv = [socket.socket() for _ in range(2)]
        for s_ in srv:
            s_.bind(("127.0.0.1", 0)); s_.listen(4)
        try:
            ports = sorted(s_.getsockname()[1] for s_ in srv)
            self.assertEqual(scanner.scan_ports("127.0.0.1", ports + [1], 0.5), ports)
        finally:
            for s_ in srv:
                s_.close()

    def test_all_profiles_are_complete(self):
        keys = set(scanner.PROFILES["normal"])
        for name, p in scanner.PROFILES.items():
            self.assertEqual(set(p) - {"passive"}, keys, name)  # « passive » : seulement l'écoute seule
            self.assertEqual("passive" in p, name == "ecoute", name)
        self.assertLess(len(scanner.PROFILES["rapide"]["scan_ports"]), len(scanner.PROFILES["normal"]["scan_ports"]))
        self.assertGreater(len(scanner.PROFILES["approfondi"]["scan_ports"]), len(scanner.PROFILES["normal"]["scan_ports"]))


class SecurityOptInTests(unittest.TestCase):
    """L'analyse de sécurité n'envoie rien tant qu'elle n'est pas activée."""

    def inspect(self, security_on, ip="192.168.1.9", me=False):
        sc = scanner.Scanner(); sc.overrides = {}; sc.security = security_on
        net = {"iface": "eth0", "ip": "192.168.1.13" if not me else ip, "cidr": "192.168.1.0/24", "gateway": "192.168.1.1"}
        calls = {"ports": None, "probes": 0}
        def fake_ports(ip_, ports, timeout):
            calls["ports"] = tuple(ports); return [23, 6379]
        def fake_probes(ip_, ports):
            calls["probes"] += 1; return {6379: "open"}
        patches = [mock.patch.object(scanner, "scan_ports", fake_ports), mock.patch.object(scanner, "grab_banner", lambda i, p: ""),
                   mock.patch.object(scanner, "ping_ttl", lambda i: 64), mock.patch.object(scanner, "netbios_name", lambda i: ""),
                   mock.patch.object(scanner, "mdns_name", lambda i: ""), mock.patch.object(scanner.socket, "gethostbyaddr", lambda i: ("h", [], [i])),
                   mock.patch.object(scanner.security, "active_probes", fake_probes)]
        for p in patches:
            p.start()
        try:
            return sc._inspect(ip, net, {}, {"mdns": {}, "ssdp": {}}), calls
        finally:
            for p in patches:
                p.stop()

    def test_disabled_sends_no_probe_scans_no_extra_port_and_reports_nothing(self):
        dev, calls = self.inspect(False)
        self.assertEqual((dev["security"], calls["probes"]), (None, 0))
        self.assertNotIn(11211, calls["ports"])

    def test_enabled_adds_security_ports_probes_and_analyses(self):
        dev, calls = self.inspect(True)
        self.assertIn(11211, calls["ports"]); self.assertEqual(calls["probes"], 1)
        self.assertEqual([f["id"] for f in dev["security"]], ["redis-open", "telnet"])

    def test_this_machine_is_never_probed(self):
        dev, calls = self.inspect(True, me=True)
        self.assertEqual((dev["security"], calls["probes"]), (None, 0))

    def test_flag_is_reported_in_state(self):
        self.assertFalse(scanner.Scanner().snapshot()["security"])


if __name__ == "__main__":
    unittest.main()
