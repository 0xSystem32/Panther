import unittest

from panther import identity


def dev(**kw):
    d = {"ip": "192.168.1.30", "mac": "00:1a:2b:00:00:01", "hostname": "", "type": "phone", "vendor": "Samsung Electronics Co.,Ltd", "model": "", "custom": False}
    d.update(kw)
    return d


class AnonymousTests(unittest.TestCase):
    def test_empty_ip_or_generic_names_are_anonymous(self):
        for name in ("", "192.168.1.30", "device-32", "Device_3fa9", "android-1a2b3c4d", "unknown", "ESP-8266"):
            self.assertTrue(identity.is_anonymous(dev(hostname=name)), name)

    def test_real_names_are_not(self):
        for name in ("salon-tv", "salon-tv", "iPhone-de-Marie", "debian"):
            self.assertFalse(identity.is_anonymous(dev(hostname=name)), name)

    def test_chosen_names_this_machine_and_virtual_nodes_are_never_suggested(self):
        self.assertFalse(identity.is_anonymous(dev(custom=True)))
        self.assertFalse(identity.is_anonymous(dev(is_self=True)))
        self.assertFalse(identity.is_anonymous(dev(virtual=True)))


class SuggestTests(unittest.TestCase):
    def test_type_and_short_vendor(self):
        self.assertEqual(identity.suggest_name(dev()), "Téléphone Samsung")

    def test_model_wins(self):
        self.assertEqual(identity.suggest_name(dev(model="iPhone 13 Pro", vendor="Apple, Inc.")), "iPhone 13 Pro")

    def test_random_mac_hides_the_vendor_but_keeps_the_type(self):
        self.assertEqual(identity.suggest_name(dev(mac="02:11:22:33:44:55")), "Téléphone")

    def test_unknown_type_with_vendor_uses_vendor_only(self):
        self.assertEqual(identity.suggest_name(dev(type="unknown", vendor="Hikvision Co., Ltd")), "Hikvision")

    def test_nothing_to_say_gives_an_empty_suggestion(self):
        self.assertEqual(identity.suggest_name(dev(type="unknown", vendor="", mac="02:11:22:33:44:55")), "")

    def test_names_stay_unique(self):
        self.assertEqual(identity.suggest_name(dev(), taken=["téléphone samsung"]), "Téléphone Samsung 2")
        self.assertEqual(identity.suggest_name(dev(), taken=["Téléphone Samsung", "Téléphone Samsung 2"]), "Téléphone Samsung 3")


class AutoNameTests(unittest.TestCase):
    def test_names_are_applied_stably_and_uniquely(self):
        a = dev(ip="192.168.1.31", mac="00:1a:2b:00:00:02", hostname="device-1")
        b = dev(ip="192.168.1.30", mac="00:1a:2b:00:00:01", hostname="")
        c = dev(ip="192.168.1.32", mac="00:1a:2b:00:00:03", hostname="salon", type="tv")
        identity.apply_suggested_names([a, b, c])
        self.assertEqual((b["hostname"], a["hostname"], c["hostname"]), ("Téléphone Samsung", "Téléphone Samsung 2", "salon"))
        self.assertEqual(a["auto_hostname"], "device-1")
        self.assertTrue(a["name_suggested"] and "name_suggested" not in c)

    def test_nothing_to_say_leaves_the_device_alone(self):
        d = dev(type="unknown", vendor="", mac="02:11:22:33:44:55", hostname="")
        identity.apply_suggested_names([d])
        self.assertEqual(d["hostname"], "")


if __name__ == "__main__":
    unittest.main()
