import os
import tempfile
import unittest

from panther import store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        store.PATH = os.path.join(self.tmp.name, "Panther", "devices.json")
        self.dev = dict(ip="192.168.1.9", mac="aa:bb:cc:00:11:22", hostname="device-9", type="unknown",
                        confidence=0, reasons=["aucun indice exploitable"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_override_applies_and_persists(self):
        store.set_override(self.dev, "Imprimante bureau", "printer")
        store.apply(self.dev)
        self.assertEqual((self.dev["hostname"], self.dev["type"], self.dev["confidence"]), ("Imprimante bureau", "printer", 100))
        self.assertTrue(self.dev["custom"])
        fresh = dict(ip="192.168.1.77", mac="AA:BB:CC:00:11:22", hostname="x", type="unknown")  # même MAC, IP différente
        store.apply(fresh)
        self.assertEqual(fresh["type"], "printer")

    def test_apply_is_idempotent_and_reversible(self):
        store.set_override(self.dev, "Salon", "tv")
        store.apply(self.dev); store.apply(self.dev)
        self.assertEqual(self.dev["auto_type"], "unknown")
        store.set_override(self.dev)  # vide = retour à l'automatique
        store.apply(self.dev)
        self.assertEqual((self.dev["hostname"], self.dev["type"], self.dev["custom"]), ("device-9", "unknown", False))

    def test_invalid_type_ignored(self):
        store.set_override(self.dev, None, "<script>")
        store.apply(self.dev)
        self.assertEqual(self.dev["type"], "unknown")

    def test_corrupt_file_is_tolerated(self):
        os.makedirs(os.path.dirname(store.PATH))
        with open(store.PATH, "w") as f:
            f.write("{pas du json")
        self.assertEqual(store.load(), {})
        store.apply(self.dev)

    def test_key_falls_back_to_ip_without_mac(self):
        d = dict(ip="10.0.0.5", mac="", hostname="h", type="unknown")
        store.set_override(d, "Test")
        store.apply(d)
        self.assertEqual(d["hostname"], "Test")


if __name__ == "__main__":
    unittest.main()
