import unittest

from panther import layout

NET = "192.168.1.0/24"


def dev(ip, name="", typ="unknown", net=NET, **kw):
    d = {"ip": ip, "mac": "aa:00:00:00:00:%02x" % int(ip.split(".")[-1]), "hostname": name or ip, "type": typ,
         "network": net, "online": True, "is_self": False, "is_gateway": False}
    d.update(kw)
    return d


def ids(t, kind=None):
    return [n["id"] for n in t.nodes.values() if kind is None or n["kind"] == kind]


class TreeTests(unittest.TestCase):
    def setUp(self):
        self.gw = dev("192.168.1.1", "box", "router", is_gateway=True)
        self.me = dev("192.168.1.13", "debian", "desktop", is_self=True)
        self.tv = dev("192.168.1.10", "tv", "tv")

    def tree(self, devices, **kw):
        return layout.build_tree(devices, NET, **kw)

    def parent_name(self, t, d):
        p = t.parent[layout.dkey(d)]
        return t.nodes[p]["dev"]["hostname"] if t.nodes[p]["dev"] else t.nodes[p]["label"]

    def test_flat_network_hangs_off_the_gateway_under_internet(self):
        t = self.tree([self.me, self.gw, self.tv])
        self.assertEqual(t.roots, ["virt:internet"])
        self.assertEqual(self.parent_name(t, self.gw), "Internet")
        self.assertEqual({self.parent_name(t, d) for d in (self.me, self.tv)}, {"box"})

    def test_devices_are_attached_to_the_switch_named_by_snmp(self):
        sw = dev("192.168.1.2", "sw-salon", "switch")
        a = dev("192.168.1.20", "nas", "nas", switch="sw-salon", switch_port="Gi1/0/3")
        b = dev("192.168.1.21", "cam", "camera", switch="autre-switch")           # switch inconnu : retombe sur la box
        t = self.tree([self.me, self.gw, sw, a, b])
        self.assertEqual(self.parent_name(t, sw), "box")
        self.assertEqual(self.parent_name(t, a), "sw-salon")
        self.assertEqual(t.nodes[layout.dkey(a)]["port"], "Gi1/0/3")
        self.assertEqual(self.parent_name(t, b), "box")

    def test_snmp_system_name_can_differ_from_network_name(self):
        sw = dev("192.168.1.2", "switch-2", "switch")
        a = dev("192.168.1.20", "nas", switch="CORE-SW")
        t = self.tree([self.me, self.gw, sw, a], snmp_info=[{"host": "192.168.1.2", "name": "core-sw"}])
        self.assertEqual(self.parent_name(t, a), "switch-2")

    def test_this_machine_goes_under_its_lldp_neighbour_switch(self):
        sw = dev("192.168.1.2", "sw-bureau", "switch")
        t = self.tree([self.me, self.gw, sw], neighbors=[{"proto": "LLDP", "name": "sw-bureau", "mgmt_ip": "192.168.1.2"}])
        self.assertEqual(self.parent_name(t, self.me), "sw-bureau")

    def test_without_gateway_this_machine_is_the_root(self):
        t = self.tree([self.me, self.tv])
        self.assertEqual(t.roots, [layout.dkey(self.me)])
        self.assertEqual(self.parent_name(t, self.tv), "debian")

    def test_routed_network_follows_traceroute_path_with_gaps_and_shared_hops(self):
        d1 = dev("10.0.7.20", "imprimante", "printer", net="10.0.7.0/24")
        d2 = dev("10.0.8.5", "nas2", "nas", net="10.0.8.0/24")
        paths = {"10.0.7.0/24": ["192.168.1.1", "192.168.1.254", None, "10.0.7.20"],
                 "10.0.8.0/24": ["192.168.1.1", "192.168.1.254", "10.0.8.5"]}
        nets = [{"cidr": NET, "kind": "local"}, {"cidr": "10.0.7.0/24", "vlan": 7}, {"cidr": "10.0.8.0/24"}]
        t = self.tree([self.me, self.gw, d1, d2], networks_info=nets, paths=paths)
        hops = ids(t, "hop")
        self.assertEqual(hops, ["virt:hop:192.168.1.254"])                          # partagé entre les deux réseaux
        self.assertEqual(ids(t, "gap"), ["virt:gap:10.0.7.0/24:1"])
        self.assertEqual(t.nodes["virt:net:10.0.7.0/24"]["label"], "10.0.7.0/24 · VLAN 7")
        self.assertEqual(t.parent["virt:net:10.0.7.0/24"], "virt:gap:10.0.7.0/24:1")
        self.assertEqual(t.parent["virt:net:10.0.8.0/24"], "virt:hop:192.168.1.254")
        self.assertEqual(self.parent_name(t, d1), "10.0.7.0/24 · VLAN 7")
        self.assertNotIn("virt:hop:10.0.7.20", t.nodes)                             # la cible n'est pas un « saut »

    def test_router_on_the_path_that_is_also_a_scanned_device_is_not_duplicated(self):
        r = dev("192.168.1.254", "routeur-vlan", "router")
        d = dev("10.0.7.20", "x", net="10.0.7.0/24")
        t = self.tree([self.me, self.gw, r, d], networks_info=[{"cidr": "10.0.7.0/24"}],
                      paths={"10.0.7.0/24": ["192.168.1.1", "192.168.1.254", "10.0.7.20"]})
        self.assertEqual(ids(t, "hop"), [])
        self.assertEqual(self.parent_name(t, d), "10.0.7.0/24")
        self.assertEqual(len([n for n in t.nodes.values() if n["dev"] is r]), 1)

    def test_network_without_answer_is_still_drawn_as_empty(self):
        t = self.tree([self.me, self.gw], networks_info=[{"cidr": "172.16.5.0/24"}], paths={"172.16.5.0/24": ["192.168.1.1", None]})
        n = t.nodes["virt:net:172.16.5.0/24"]
        self.assertEqual((n["sub"], n["dashed"]), ("aucun appareil", True))

    def test_offline_devices_stay_in_the_tree(self):
        off = dev("192.168.1.30", "vieux", online=False)
        t = self.tree([self.me, self.gw, off])
        self.assertIn(layout.dkey(off), t.nodes)

    def test_ancestors_give_the_path_to_the_internet(self):
        sw = dev("192.168.1.2", "sw", "switch"); a = dev("192.168.1.20", "nas", switch="sw")
        t = self.tree([self.me, self.gw, sw, a])
        self.assertEqual(t.ancestors(layout.dkey(a)), [layout.dkey(sw), layout.dkey(self.gw), "virt:internet"])

    def test_empty_input(self):
        t = self.tree([])
        self.assertEqual((t.nodes, t.roots), ({}, []))
        self.assertEqual(layout.hierarchical_positions(t), {})


class PositionTests(unittest.TestCase):
    def tree(self, n_leaves, with_switch=False):
        gw = dev("192.168.1.1", "box", "router", is_gateway=True)
        devs = [gw] + [dev("192.168.1.%d" % (20 + i), "d%d" % i) for i in range(n_leaves)]
        if with_switch:
            devs.append(dev("192.168.1.2", "sw", "switch"))
            for d in devs:
                if d["hostname"].startswith("d") and int(d["hostname"][1:]) % 2:
                    d["switch"] = "sw"
        return layout.build_tree(devs, NET)

    def test_parent_is_centered_above_its_children_and_levels_go_down(self):
        t = self.tree(4)
        p = layout.hierarchical_positions(t)
        gw = "aa:00:00:00:00:01"
        kids = [p[k] for k in t.children[gw]]
        self.assertAlmostEqual(p[gw][0], (min(x for x, _ in kids) + max(x for x, _ in kids)) / 2)
        self.assertLess(p["virt:internet"][1], p[gw][1])
        self.assertLess(p[gw][1], min(y for _, y in kids))

    def test_no_two_nodes_overlap_whatever_the_size(self):
        for n, sw in ((1, False), (7, False), (30, False), (30, True), (100, True)):
            p = layout.hierarchical_positions(self.tree(n, sw))
            pts = list(p.values())
            self.assertEqual(len({(round(x), round(y)) for x, y in pts}), len(pts), (n, sw))
            for i, a in enumerate(pts):                                  # écart minimal entre deux nœuds
                for b in pts[i + 1:]:
                    self.assertTrue(abs(a[0] - b[0]) >= 100 or abs(a[1] - b[1]) >= 100, (n, sw, a, b))

    def test_many_leaves_wrap_into_a_grid_instead_of_one_huge_row(self):
        p = layout.hierarchical_positions(self.tree(30), max_cols=8)
        xs = [x for k, (x, y) in p.items() if not k.startswith("virt")]
        self.assertLessEqual(max(xs) - min(xs), 8 * 150)
        self.assertEqual(len({y for k, (x, y) in p.items() if not k.startswith("virt")}), 5)   # box + 4 rangées

    def test_layout_is_deterministic_and_centered(self):
        t = self.tree(12, True)
        a, b = layout.hierarchical_positions(t), layout.hierarchical_positions(t)
        self.assertEqual(a, b)
        xs = [x for x, _ in a.values()]
        self.assertAlmostEqual((min(xs) + max(xs)) / 2, 0)


if __name__ == "__main__":
    unittest.main()
