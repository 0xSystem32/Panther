import unittest
from unittest import mock

from panther import networks

IP_ROUTE = """default via 192.168.1.1 dev wlp3s0 proto dhcp src 192.168.1.13 metric 600
10.20.0.0/24 via 192.168.1.254 dev wlp3s0
192.168.1.0/24 dev wlp3s0 proto kernel scope link src 192.168.1.13
8.8.8.0/24 via 192.168.1.1 dev wlp3s0
"""
IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo
2: wlp3s0    inet 192.168.1.13/24 brd 192.168.1.255 scope global dynamic wlp3s0
3: wg0    inet 10.167.124.69/32 scope global wg0
4: eth0.20    inet 192.168.20.5/24 brd 192.168.20.255 scope global eth0.20
"""
IP_LINK = """2: wlp3s0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP
4: eth0.20@eth0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP \\    vlan protocol 802.1Q id 20 <REORDER_HDR>
"""


def fake_run(cmd):
    return {"route": IP_ROUTE, "addr": IP_ADDR, "link": IP_LINK}[
        "route" if "route" in cmd else "addr" if "addr" in cmd else "link"]


class ValidateTests(unittest.TestCase):
    def test_private_ranges_accepted(self):
        for c in ("192.168.20.0/24", "10.0.0.0/20", "172.16.5.0/24", "192.168.1.5"):
            networks.validate_cidr(c)

    def test_public_range_refused(self):
        with self.assertRaises(ValueError) as cm:
            networks.validate_cidr("8.8.8.0/24")
        self.assertIn("privés", str(cm.exception))

    def test_too_large_refused(self):
        with self.assertRaises(ValueError):
            networks.validate_cidr("10.0.0.0/8")
        with self.assertRaises(ValueError):
            networks.validate_cidr("192.168.0.0/16")

    def test_garbage_refused(self):
        for c in ("", "abc", "192.168.1.0/99", "::1"):
            with self.assertRaises(ValueError):
                networks.validate_cidr(c)

    def test_host_bits_tolerated(self):
        self.assertEqual(str(networks.validate_cidr("192.168.20.7/24")), "192.168.20.0/24")


class DetectionTests(unittest.TestCase):
    def test_known_networks_from_system(self):
        with mock.patch.object(networks, "_run", fake_run):
            nets = {n["cidr"]: n for n in networks.known_networks("192.168.1.0/24")}
        self.assertEqual(nets["192.168.1.0/24"]["kind"], "local")
        self.assertEqual(nets["192.168.20.0/24"]["vlan"], 20)       # sous-interface 802.1Q
        self.assertEqual(nets["10.20.0.0/24"]["via"], "192.168.1.254")  # route vers un autre VLAN
        self.assertNotIn("10.167.124.69/32", nets)                  # VPN /32 ignoré
        self.assertNotIn("8.8.8.0/24", nets)                        # route publique ignorée

    def test_describe(self):
        self.assertEqual(networks.describe({"cidr": "10.20.0.0/24", "vlan": 20, "via": "192.168.1.254"}),
                         "10.20.0.0/24  ·  VLAN 20  ·  via 192.168.1.254")

    def test_hops_from_ttl(self):
        self.assertEqual(networks.hops_from_ttl(64), 0)    # le routeur lui-même
        self.assertEqual(networks.hops_from_ttl(63), 1)    # un hôte derrière le routeur
        self.assertEqual(networks.hops_from_ttl(126), 2)   # hôte Windows, 2 sauts
        self.assertIsNone(networks.hops_from_ttl(300))

    def test_discovery_reports_only_answering_gateways(self):
        with mock.patch.object(networks, "_alive", lambda ip, *a, **k: ip in ("192.168.20.1", "10.0.7.254")), \
                mock.patch.object(networks, "ping_hops", lambda ip: 0):
            res = networks.discover_reachable(exclude=["192.168.1.0/24"])
        self.assertEqual([r["cidr"] for r in res], ["10.0.7.0/24", "192.168.20.0/24"])
        self.assertEqual(res[1]["via"], "192.168.20.1")

    def test_discovery_skips_excluded(self):
        with mock.patch.object(networks, "_alive", lambda ip, *a, **k: True), \
                mock.patch.object(networks, "ping_hops", lambda ip: None):
            res = networks.discover_reachable(exclude=["192.168.1.0/24"])
        self.assertNotIn("192.168.1.0/24", [r["cidr"] for r in res])


class InterfaceTests(unittest.TestCase):
    def kind(self, name, wireless=False, hwtype=None, phy=False):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, name))
            if wireless:
                os.makedirs(os.path.join(d, name, "wireless"))
            if phy:
                os.makedirs(os.path.join(d, name, "phy80211"))
            if hwtype:
                with open(os.path.join(d, name, "type"), "w") as f:
                    f.write(hwtype + "\n")
            return networks.link_kind(name, sysfs=d)

    def test_kinds(self):
        self.assertEqual(self.kind("wlp3s0", wireless=True), "wifi")
        self.assertEqual(self.kind("wlan0", phy=True), "wifi")
        self.assertEqual(self.kind("enp4s0"), "ethernet")
        self.assertEqual(self.kind("eth0", hwtype="1"), "ethernet")
        self.assertEqual(self.kind("wg0-mullvad"), "vpn")
        self.assertEqual(self.kind("tailscale0"), "vpn")
        self.assertEqual(self.kind("utun3", hwtype="65534"), "vpn")                # tunnel sans nom évocateur : repéré par son type
        self.assertEqual(self.kind("docker0"), "virtuel")
        self.assertEqual(self.kind("virbr0"), "virtuel")
        self.assertEqual(self.kind("br-1a2b3c"), "virtuel")

    def test_unknown_interface_defaults_to_ethernet(self):
        self.assertEqual(networks.link_kind("inconnue0", sysfs="/nonexistent"), "ethernet")

    def test_interfaces_expose_their_kind(self):
        with mock.patch.object(networks, "_run", fake_run), mock.patch.object(networks, "link_kind", lambda i, **k: {"wlp3s0": "wifi", "eth0.20": "ethernet"}.get(i, "vpn")):
            kinds = {i["iface"]: i["kind"] for i in networks.interfaces()}
        self.assertEqual(kinds, {"wlp3s0": "wifi", "eth0.20": "ethernet"})


class LocalNetworkTests(unittest.TestCase):
    OUT = {"route default": "default via 192.168.1.1 dev wlp3s0 proto dhcp\n",
           "route default dev eth1": "",
           "route default dev wlp3s0": "default via 192.168.1.1 proto dhcp\n",
           "addr wlp3s0": "2: wlp3s0    inet 192.168.1.13/24 brd 192.168.1.255\n",
           "addr eth1": "3: eth1    inet 10.5.0.9/16 brd 10.5.255.255\n",
           "addr tun0": ""}

    def fake(self, cmd):
        key = ("route default" + (" dev " + cmd[-1] if "dev" in cmd else "")) if "route" in cmd else "addr " + cmd[-1]
        return self.OUT.get(key, "")

    def local(self, iface=None):
        from panther import scanner
        with mock.patch.object(networks, "_run", self.fake), mock.patch.object(networks, "link_kind", lambda i, **k: "ethernet"):
            return scanner.local_network(iface)

    def test_automatic_uses_default_route(self):
        n = self.local()
        self.assertEqual((n["iface"], n["cidr"], n["gateway"]), ("wlp3s0", "192.168.1.0/24", "192.168.1.1"))

    def test_chosen_interface_without_gateway_and_wide_prefix_is_bounded_to_a_24(self):
        n = self.local("eth1")
        self.assertEqual((n["iface"], n["gateway"], n["cidr"]), ("eth1", "", "10.5.0.0/24"))   # /16 ramené à /24

    def test_chosen_interface_with_gateway(self):
        self.assertEqual(self.local("wlp3s0")["gateway"], "192.168.1.1")

    def test_interface_without_ip_gives_a_clear_error(self):
        with self.assertRaises(RuntimeError) as cm:
            self.local("tun0")
        self.assertIn("tun0", str(cm.exception))

    def test_no_default_route_gives_a_clear_error(self):
        from panther import scanner
        with mock.patch.object(networks, "_run", lambda cmd: ""):
            with self.assertRaises(RuntimeError):
                scanner.local_network()


if __name__ == "__main__":
    unittest.main()
