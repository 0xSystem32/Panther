import socket
import threading
import unittest

from panther import snmp


class FakeAgent(threading.Thread):
    """Agent SNMP v2c minimal en lecture, sur 127.0.0.1, avec une communauté « public »."""

    def __init__(self, data, community="public"):
        super().__init__(daemon=True)
        self.data = dict(sorted(((snmp.oid_tuple(k), v) for k, v in data.items())))
        self.community = community
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop = False

    @staticmethod
    def _val(v):
        if v is snmp.EOM:
            return b"\x82\x00"
        return snmp.enc_int(v) if isinstance(v, int) else snmp.enc_str(v)

    def run(self):
        while not self.stop:
            try:
                pkt, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            tag, body, _ = snmp.parse_tlv(pkt, 0)
            _, _, off = snmp.parse_tlv(body, 0)
            _, comm, off = snmp.parse_tlv(body, off)
            if comm.decode() != self.community:
                continue  # communauté fausse : silence, comme un vrai agent
            ptype, rid, _, vbs = snmp.parse_message(pkt)
            out = []
            for oid, _ in vbs:
                t = snmp.oid_tuple(oid)
                if ptype == snmp.GET:
                    out.append((oid, self.data.get(t, snmp.EOM)))
                else:
                    nxt = [(k, v) for k, v in self.data.items() if k > t][:20 if ptype == snmp.GETBULK else 1]
                    out += [(".".join(map(str, k)), v) for k, v in nxt] or [(oid, snmp.EOM)]
            vb = b"".join(snmp.enc_seq(snmp.enc_oid(o) + self._val(v)) for o, v in out)
            pdu = snmp.enc_seq(snmp.enc_int(rid) + snmp.enc_int(0) + snmp.enc_int(0) + snmp.enc_seq(vb), tag=snmp.RESPONSE)
            self.sock.sendto(snmp.enc_seq(snmp.enc_int(1) + snmp.enc_str(comm) + pdu), addr)


def switch_data():
    d = {"1.3.6.1.2.1.1.5.0": b"core-sw", "1.3.6.1.2.1.1.1.0": b"Switch de test",
         "1.3.6.1.2.1.17.7.1.4.3.1.1.20": b"CAMERAS",
         "1.3.6.1.2.1.17.1.4.1.2.3": 10003, "1.3.6.1.2.1.31.1.1.1.1.10003": b"Gi1/0/3",
         "1.3.6.1.2.1.17.7.1.2.2.1.2.20.170.187.204.0.17.34": 3}
    for i in range(1, 46):  # plus de 20 lignes : force plusieurs tours de GETBULK
        d[f"1.3.6.1.2.1.4.22.1.2.5.192.168.20.{i}"] = bytes([0xAA, 0xBB, 0xCC, 0, 0, i])
    return d


class BerTests(unittest.TestCase):
    def test_oid_roundtrip_with_large_subids(self):
        for oid in ("1.3.6.1.2.1.1.5.0", "1.3.6.1.4.1.311.1.2000.16384"):
            tag, body, _ = snmp.parse_tlv(snmp.enc_oid(oid), 0)
            self.assertEqual(snmp.dec_oid(body), oid)

    def test_negative_and_large_integers(self):
        for v in (0, 127, 128, 255, 65536, -1, -129):
            tag, body, _ = snmp.parse_tlv(snmp.enc_int(v), 0)
            self.assertEqual(snmp.dec_value(tag, body), v)

    def test_truncated_and_garbage_raise_snmperror(self):
        for bad in (b"", b"\x30", b"\x30\x05\x01", b"\x30\x84\xff\xff\xff\xff", b"\xff" * 10):
            with self.assertRaises(snmp.SnmpError):
                snmp.parse_message(bad)


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.agent = FakeAgent(switch_data())
        self.agent.start()

    def tearDown(self):
        self.agent.stop = True
        self.agent.join(1)
        self.agent.sock.close()

    def test_get(self):
        r = snmp.get("127.0.0.1", "public", ["1.3.6.1.2.1.1.5.0"], port=self.agent.port, timeout=0.5)
        self.assertEqual(r["1.3.6.1.2.1.1.5.0"], b"core-sw")

    def test_walk_stops_at_subtree_end_and_pages(self):
        rows = snmp.walk("127.0.0.1", "public", "1.3.6.1.2.1.4.22.1.2", port=self.agent.port, timeout=0.5)
        self.assertEqual(len(rows), 45)

    def test_read_tables(self):
        t = snmp.read_tables("127.0.0.1", "public", port=self.agent.port, timeout=0.5)
        self.assertEqual(t["name"], "core-sw")
        self.assertEqual(t["arp"]["192.168.20.7"], "aa:bb:cc:00:00:07")
        self.assertEqual(len(t["arp"]), 45)
        self.assertEqual(t["fdb"]["aa:bb:cc:00:11:22"], {"vlan": 20, "port": "Gi1/0/3"})
        self.assertEqual(t["vlans"][20], "CAMERAS")

    def test_wrong_community_is_a_clear_error(self):
        with self.assertRaises(snmp.SnmpError) as cm:
            snmp.get("127.0.0.1", "mauvaise", ["1.3.6.1.2.1.1.5.0"], port=self.agent.port, timeout=0.15)
        self.assertIn("communauté", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
