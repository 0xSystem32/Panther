import socket
import threading
import time
import unittest
from unittest import mock

from panther import scanner

PROFILE = {"arp_rounds": 2, "arp_wait": 1.2, "arp_max": 7.0}


class Clock:
    """Horloge simulée : `sleep` avance le temps, aucun test n'attend vraiment."""

    def __init__(self):
        self.t = 0.0

    def sleep(self, s):
        self.t += s

    def __call__(self):
        return self.t


def run(script, hosts, profile=PROFILE, cancel=None):
    """`script(t)` retourne l'état des voisins à l'instant t (secondes simulées)."""
    clk, nudged = Clock(), []
    with mock.patch.object(scanner, "udp_nudge", nudged.append):
        res = scanner.arp_discover("eth0", hosts, profile, cancel or threading.Event(), sleep=clk.sleep,
                                   neighbors=lambda: script(clk.t), clock=clk)
    return res, nudged, clk.t


class NeighborParsingTests(unittest.TestCase):
    OUT = """192.168.1.1 dev wlp3s0 lladdr aa:bb:cc:11:22:33 router REACHABLE
192.168.1.27 dev wlp3s0 lladdr 02:11:22:33:44:01 STALE
192.168.1.40 dev wlp3s0 FAILED
192.168.1.41 dev wlp3s0  INCOMPLETE
192.168.1.50 dev wlp3s0 lladdr aa:bb:cc:dd:ee:ff DELAY
n'importe quoi
"""

    def test_states_and_macs(self):
        with mock.patch.object(scanner.networks, "_run", lambda cmd: self.OUT):
            n = scanner.arp_neighbors("wlp3s0")
        self.assertEqual(n["192.168.1.1"], ("aa:bb:cc:11:22:33", "REACHABLE"))
        self.assertEqual(n["192.168.1.27"][1], "STALE")
        self.assertEqual(n["192.168.1.40"], ("", "FAILED"))
        self.assertEqual(n["192.168.1.41"][1], "INCOMPLETE")
        self.assertEqual(n["192.168.1.50"][1], "DELAY")
        self.assertEqual(len(n), 5)                                                    # la ligne absurde est ignorée

    def test_unusable_ip_command_gives_empty_result(self):
        with mock.patch.object(scanner.networks, "_run", lambda cmd: ""):
            self.assertEqual(scanner.arp_neighbors("eth0"), {})


class ArpDiscoverTests(unittest.TestCase):
    HOSTS = ["192.168.1.%d" % i for i in range(1, 6)]

    def test_reachable_hosts_are_found_quickly_and_absent_ones_are_not(self):
        (alive, maybes, ok), nudged, t = run(lambda t: {"192.168.1.1": ("aa", "REACHABLE"), "192.168.1.3": ("cc", "REACHABLE"),
                                                       "192.168.1.4": ("", "FAILED")}, self.HOSTS)
        self.assertEqual((alive, maybes, ok), ({"192.168.1.1": "aa", "192.168.1.3": "cc"}, [], True))
        self.assertLess(t, 5)                                                          # quelques secondes, pas une minute

    def test_second_round_only_retries_hosts_not_yet_found(self):
        def script(t):                                                                  # .2 ne répond qu'au 2e tour (veille Wi-Fi)
            d = {"192.168.1.1": ("aa", "REACHABLE")}
            if t > 1.5:
                d["192.168.1.2"] = ("bb", "REACHABLE")
            return d
        (alive, _, _), nudged, _ = run(script, self.HOSTS)
        self.assertEqual(sorted(alive), ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(len(nudged), len(self.HOSTS) + (len(self.HOSTS) - 1))        # tour 1 : tous ; tour 2 : tous sauf .1

    def test_stale_entry_is_waited_for_then_confirmed_not_trusted(self):
        def script(t):                                                                  # STALE -> DELAY -> REACHABLE après 5,5 s
            st = "REACHABLE" if t >= 5.5 else "DELAY" if t >= 0.5 else "STALE"
            return {"192.168.1.1": ("aa", st)}
        (alive, maybes, _), _, t = run(script, self.HOSTS[:2])
        self.assertEqual((alive, maybes), ({"192.168.1.1": "aa"}, []))
        self.assertGreaterEqual(t, 5.5)

    def test_stale_entry_of_a_device_that_left_is_never_reported_alive(self):
        (alive, maybes, _), _, t = run(lambda t: {"192.168.1.1": ("aa", "PROBE" if t < 6 else "STALE")}, self.HOSTS[:2])
        self.assertEqual(alive, {})
        self.assertEqual(maybes, ["192.168.1.1"])                                      # à trancher par une sonde, pas supposé présent
        self.assertLessEqual(t, 2 * PROFILE["arp_max"] + 1)                            # l'attente reste bornée

    def test_quick_profile_does_one_round_and_a_short_wait(self):
        quick = scanner.PROFILES["rapide"]
        (alive, _, _), nudged, t = run(lambda t: {"192.168.1.1": ("aa", "REACHABLE")}, self.HOSTS, quick)
        self.assertEqual(len(nudged), len(self.HOSTS))                                  # un seul tour
        self.assertLessEqual(t, quick["arp_max"])

    def test_cancel_stops_immediately(self):
        c = threading.Event(); c.set()
        (alive, _, ok), nudged, t = run(lambda t: {}, self.HOSTS, cancel=c)
        self.assertEqual((alive, nudged, t, ok), ({}, [], 0.0, False))

    def test_no_neighbour_table_at_all_means_fall_back_to_tcp(self):
        (_, _, ok), _, _ = run(lambda t: {}, self.HOSTS)
        self.assertFalse(ok)

    def test_only_hosts_of_the_scanned_network_are_considered(self):
        (alive, _, _), _, _ = run(lambda t: {"192.168.1.1": ("aa", "REACHABLE"), "10.9.9.9": ("zz", "REACHABLE")}, self.HOSTS)
        self.assertEqual(list(alive), ["192.168.1.1"])

    def test_every_profile_defines_the_arp_settings(self):
        for name, p in scanner.PROFILES.items():
            if p.get("passive"):  # écoute seule : aucune sonde, donc aucun réglage ARP actif
                self.assertEqual((p["arp_rounds"], p["arp_wait"]), (0, 0), name); continue
            self.assertTrue(p["arp_rounds"] >= 1 and p["arp_wait"] > 0 and p["arp_max"] >= p["arp_wait"], name)
        self.assertLess(scanner.PROFILES["rapide"]["arp_max"], scanner.PROFILES["normal"]["arp_max"])


if __name__ == "__main__":
    unittest.main()


class ProbeAliveTests(unittest.TestCase):
    """`probe_alive` sonde tous les ports à la fois : un port ouvert OU refusé prouve que l'hôte est là."""

    def listener(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(5)
        self.addCleanup(s.close)
        return s.getsockname()[1]

    def free_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_open_port_means_alive(self):
        self.assertTrue(scanner.probe_alive("127.0.0.1", 0.5, (self.free_port(), self.listener())))

    def test_refused_port_means_alive(self):
        self.assertTrue(scanner.probe_alive("127.0.0.1", 0.5, (self.free_port(),)))

    def test_no_ports_means_not_alive(self):
        self.assertFalse(scanner.probe_alive("127.0.0.1", 0.2, ()))

    def test_silent_host_costs_one_timeout_not_one_per_port(self):
        # 192.0.2.0/24 (TEST-NET-1) ne répond jamais ; selon le réseau le noyau refuse tout de suite (injoignable) ou laisse expirer.
        t0 = time.monotonic()
        alive = scanner.probe_alive("192.0.2.77", 0.5, tuple(range(2000, 2012)))
        self.assertFalse(alive)
        self.assertLess(time.monotonic() - t0, 2.5)  # 12 ports × 0,5 s = 6 s si on les sondait un par un
