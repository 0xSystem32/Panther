import math
import unittest

from panther import layout


def dev(ip, kind, **kw):
    d = {"ip": ip, "mac": "aa:00:00:00:00:%02x" % int(ip.split(".")[-1]), "type": kind, "hostname": "h" + ip.split(".")[-1]}
    d.update(kw)
    return d


class TypeClusterTests(unittest.TestCase):
    def devices(self, spec):
        out, n = [], 1
        for kind, count in spec.items():
            for _ in range(count):
                out.append(dev(f"10.0.0.{n}", kind)); n += 1
        return out

    def test_every_device_gets_a_position_and_every_type_a_cluster(self):
        ds = self.devices({"phone": 3, "camera": 2, "printer": 1})
        pos, clusters = layout.type_clusters(ds)
        self.assertEqual(len(pos), 6)
        self.assertEqual({c["kind"]: c["count"] for c in clusters}, {"phone": 3, "camera": 2, "printer": 1})
        self.assertEqual([c["kind"] for c in clusters], ["phone", "camera", "printer"])         # les plus nombreux d'abord

    def test_devices_stay_inside_their_cluster(self):
        ds = self.devices({"phone": 14, "tv": 2})
        pos, clusters = layout.type_clusters(ds)
        for c in clusters:
            for d in ds:
                if d["type"] == c["kind"]:
                    x, y = pos[d["mac"]]
                    self.assertLessEqual(math.hypot(x - c["x"], y - c["y"]), c["r"] - 50, d["ip"])   # le nœud (rayon ~36) reste dans l'amas

    def test_clusters_never_overlap(self):
        ds = self.devices({"phone": 20, "tv": 7, "camera": 3, "printer": 1, "nas": 1, "iot": 12, "desktop": 5})
        _pos, cl = layout.type_clusters(ds)
        for i, a in enumerate(cl):
            for b in cl[i + 1:]:
                self.assertGreaterEqual(math.hypot(a["x"] - b["x"], a["y"] - b["y"]), a["r"] + b["r"], (a["kind"], b["kind"]))

    def test_nodes_of_a_big_cluster_do_not_touch(self):
        ds = self.devices({"iot": 40})
        pos, _ = layout.type_clusters(ds)
        pts = list(pos.values())
        closest = min(math.hypot(a[0] - b[0], a[1] - b[1]) for i, a in enumerate(pts) for b in pts[i + 1:])
        self.assertGreater(closest, 70)                                                              # assez d'espace pour le rond + le nom

    def test_layout_is_centred_and_deterministic(self):
        ds = self.devices({"phone": 5, "tv": 3, "camera": 2, "nas": 1})
        a = layout.type_clusters(ds)
        b = layout.type_clusters(list(reversed(ds)))
        self.assertEqual(a, b)                                                                       # l'ordre d'arrivée des appareils ne change rien
        _p, cl = a
        left, right = min(c["x"] - c["r"] for c in cl), max(c["x"] + c["r"] for c in cl)
        top, bottom = min(c["y"] - c["r"] for c in cl), max(c["y"] + c["r"] for c in cl)
        self.assertAlmostEqual(left + right, 0, places=6); self.assertAlmostEqual(top + bottom, 0, places=6)

    def test_shape_is_roughly_landscape_not_a_single_line(self):
        ds = self.devices({k: 1 for k in ("phone", "tv", "camera", "nas", "iot", "desktop", "laptop", "printer", "router", "switch")})
        _p, cl = layout.type_clusters(ds)
        width = max(c["x"] + c["r"] for c in cl) - min(c["x"] - c["r"] for c in cl)
        height = max(c["y"] + c["r"] for c in cl) - min(c["y"] - c["r"] for c in cl)
        self.assertLess(width / height, 3.2)
        self.assertGreater(height, 200)

    def test_virtual_nodes_empty_input_and_missing_type(self):
        self.assertEqual(layout.type_clusters([]), ({}, []))
        ds = [dev("10.0.0.1", "phone", virtual=True), {"ip": "10.0.0.2", "mac": "aa:00:00:00:00:02", "hostname": "x"}]
        pos, cl = layout.type_clusters(ds)
        self.assertEqual((list(pos), [c["kind"] for c in cl]), (["aa:00:00:00:00:02"], ["unknown"]))

    def test_a_single_device_sits_at_the_cluster_centre(self):
        pos, cl = layout.type_clusters([dev("10.0.0.1", "nas")])
        self.assertEqual(pos["aa:00:00:00:00:01"], (cl[0]["x"], cl[0]["y"]))


if __name__ == "__main__":
    unittest.main()
