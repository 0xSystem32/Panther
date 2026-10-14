import time
import unittest
from unittest import mock

from panther import scanner


class ResolveNamesTests(unittest.TestCase):
    def patch(self, dns=None, nb=None, mdns=None):
        return [mock.patch.object(scanner, "_dns_name", dns or (lambda ip: "")),
                mock.patch.object(scanner, "netbios_name", nb or (lambda ip: "")),
                mock.patch.object(scanner, "mdns_name", mdns or (lambda ip: ""))]

    def resolve(self, timeout=1.5, **kw):
        ps = self.patch(**kw)
        for p in ps:
            p.start()
        try:
            t = time.time()
            return scanner.resolve_names("192.168.1.9", timeout), time.time() - t
        finally:
            for p in ps:
                p.stop()

    def test_all_three_answers_are_returned(self):
        res, _ = self.resolve(dns=lambda ip: "pc", nb=lambda ip: "PC-NB", mdns=lambda ip: "pc-mdns")
        self.assertEqual(res, ("pc", "PC-NB", "pc-mdns"))

    def test_lookups_run_in_parallel_not_one_after_another(self):
        slow = lambda ip: time.sleep(0.4) or "x"
        res, dt = self.resolve(dns=slow, nb=slow, mdns=slow)
        self.assertEqual(res, ("x", "x", "x"))
        self.assertLess(dt, 0.9)                                                 # 3 × 0.4 s en série = 1,2 s

    def test_a_silent_host_costs_at_most_the_timeout(self):
        hang = lambda ip: time.sleep(5)
        res, dt = self.resolve(timeout=0.5, dns=hang, nb=hang, mdns=lambda ip: "rapide")
        self.assertEqual(res, ("", "", "rapide"))                                # les réponses rapides sont conservées
        self.assertLess(dt, 1.2)

    def test_a_crashing_resolver_does_not_break_the_others(self):
        def boom(ip):
            raise OSError("réseau coupé")
        res, _ = self.resolve(dns=boom, nb=lambda ip: "ok")
        self.assertEqual(res, ("", "ok", ""))

    def test_dns_name_keeps_only_the_short_host_name_and_survives_errors(self):
        with mock.patch.object(scanner.socket, "gethostbyaddr", lambda ip: ("pc.lan.example", [], [ip])):
            self.assertEqual(scanner._dns_name("1.2.3.4"), "pc")
        def fail(ip):
            raise scanner.socket.herror(1, "Unknown host")
        with mock.patch.object(scanner.socket, "gethostbyaddr", fail):
            self.assertEqual(scanner._dns_name("1.2.3.4"), "")

    def test_every_profile_has_a_names_timeout_growing_with_depth(self):
        t = [scanner.PROFILES[k]["names_timeout"] for k in ("rapide", "normal", "approfondi")]
        self.assertEqual(t, sorted(t))


if __name__ == "__main__":
    unittest.main()
