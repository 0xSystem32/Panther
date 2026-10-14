import struct
import unittest

from panther import topology

SRC = bytes.fromhex("aabbcc001122")


def lldp_tlv(t, v):
    return struct.pack(">H", (t << 9) | len(v)) + v


class TracerouteTests(unittest.TestCase):
    def test_parse(self):
        text = ("traceroute to 10.0.7.20 (10.0.7.20), 8 hops max, 60 byte packets\n"
                " 1  192.168.1.1  0.4 ms\n 2  192.168.1.254  1.2 ms\n 3  *\n 4  10.0.7.20  2.0 ms\n")
        self.assertEqual(topology.parse_traceroute(text), ["192.168.1.1", "192.168.1.254", None, "10.0.7.20"])


class LldpTests(unittest.TestCase):
    def frame(self):
        tlvs = (lldp_tlv(1, b"\x04" + bytes.fromhex("001122334455")) + lldp_tlv(2, b"\x05Gi1/0/3")
                + lldp_tlv(3, struct.pack(">H", 120)) + lldp_tlv(5, b"core-sw")
                + lldp_tlv(8, bytes([5, 1]) + bytes([192, 168, 1, 254]) + b"\x02" + struct.pack(">I", 1) + b"\x00")
                + lldp_tlv(127, b"\x00\x80\xc2\x01" + struct.pack(">H", 20))
                + lldp_tlv(127, b"\x00\x80\xc2\x03" + struct.pack(">H", 20) + bytes([7]) + b"CAMERAS")
                + lldp_tlv(0, b""))
        return bytes.fromhex("0180c200000e") + SRC + b"\x88\xcc" + tlvs

    def test_lldp_frame(self):
        n = topology.parse_frame(self.frame())
        self.assertEqual((n["proto"], n["name"], n["port"], n["mgmt_ip"], n["vlan"]),
                         ("LLDP", "core-sw", "Gi1/0/3", "192.168.1.254", 20))
        self.assertEqual(n["chassis"], "00:11:22:33:44:55")
        self.assertEqual(n["vlan_names"], {20: "CAMERAS"})
        self.assertEqual(n["src"], "aa:bb:cc:00:11:22")

    def test_vlan_tagged_frame(self):
        f = self.frame()
        tagged = f[:12] + b"\x81\x00\x00\x14" + f[12:]
        self.assertEqual(topology.parse_frame(tagged)["name"], "core-sw")

    def test_cdp_frame(self):
        def t(typ, v):
            return struct.pack(">HH", typ, len(v) + 4) + v
        cdp = (bytes([2, 180, 0, 0]) + t(1, b"sw1") + t(3, b"Gi0/1") + t(6, b"cisco WS-C2960")
               + t(10, struct.pack(">H", 10)) + t(2, struct.pack(">I", 1) + bytes([1, 1, 0xCC]) + struct.pack(">H", 4) + bytes([10, 0, 0, 2])))
        payload = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + cdp
        frame = topology.CDP_DST + SRC + struct.pack(">H", len(payload)) + payload
        n = topology.parse_frame(frame)
        self.assertEqual((n["proto"], n["name"], n["port"], n["platform"], n["vlan"], n["mgmt_ip"]),
                         ("CDP", "sw1", "Gi0/1", "cisco WS-C2960", 10, "10.0.0.2"))

    def test_garbage_frames_never_crash(self):
        for bad in (b"", b"\x00" * 10, b"\xff" * 60, bytes.fromhex("0180c200000e") + SRC + b"\x88\xcc" + b"\xff\xff\x01"):
            topology.parse_frame(bad)  # ne doit pas lever d'exception

    def test_other_traffic_ignored(self):
        self.assertIsNone(topology.parse_frame(b"\xff" * 6 + SRC + b"\x08\x00" + b"\x00" * 40))


if __name__ == "__main__":
    unittest.main()
