import socket
import threading
import unittest

from panther import snmp, snmpv3
from tests import test_snmp

ENGINE = bytes.fromhex("80001f8880e9b104617361")
USER = snmpv3.V3User("lecteur", "motdepasse-long", "sha1")


class FakeV3Agent(threading.Thread):
    """Agent SNMP v3 authNoPriv minimal : répond à la découverte, vérifie la signature, signe ses réponses."""

    def __init__(self, data, user=USER, forge=False, silent_on_bad_auth=False, host="127.0.0.1", port=0):
        super().__init__(daemon=True)
        self.data = dict(sorted((snmp.oid_tuple(k), v) for k, v in data.items()))
        self.user, self.forge, self.silent = user, forge, silent_on_bad_auth
        self.key = snmpv3.localize(snmpv3.password_to_key(user.password, user.proto), ENGINE, user.proto)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.sock.bind((host, port)); self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop, self.seen = False, []

    def report(self, mid, oid):
        vb = snmp.enc_seq(snmp.enc_oid(oid) + snmp.enc_int(1))
        pdu = snmp.enc_seq(snmp.enc_int(0) + snmp.enc_int(0) + snmp.enc_int(0) + snmp.enc_seq(vb), tag=snmpv3.REPORT)
        scoped = snmp.enc_seq(snmp.enc_str(ENGINE) + snmp.enc_str(b"") + pdu)
        return snmpv3.build_message(mid, 0x00, snmpv3._usm(ENGINE, 3, 1000, "", b""), scoped)

    def respond(self, msg, out):
        vb = b"".join(snmp.enc_seq(snmp.enc_oid(o) + (snmp.enc_int(v) if isinstance(v, int) else snmp.enc_str(v))) for o, v in out)
        pdu = snmp.enc_seq(snmp.enc_int(msg["req_id"]) + snmp.enc_int(0) + snmp.enc_int(0) + snmp.enc_seq(vb), tag=snmp.RESPONSE)
        scoped = snmp.enc_seq(snmp.enc_str(ENGINE) + snmp.enc_str(b"") + pdu)
        n = snmpv3.PROTOCOLS[self.user.proto][1]
        zero = snmpv3.build_message(msg["msg_id"], 0x01, snmpv3._usm(ENGINE, 3, 1000, self.user.name, b"\x00" * n), scoped)
        one = snmpv3.build_message(msg["msg_id"], 0x01, snmpv3._usm(ENGINE, 3, 1000, self.user.name, b"\x01" * n), scoped)
        start = next(i for i, (a, b) in enumerate(zip(zero, one, strict=True)) if a != b)
        sig = snmpv3.digest(self.key if not self.forge else b"autre-cle" * 2, self.user.proto, zero)
        return zero[:start] + sig + zero[start + n:]

    def run(self):
        while not self.stop:
            try:
                pkt, addr = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
            try:
                msg = snmpv3.parse_message(pkt)
            except Exception:
                continue
            self.seen.append(msg)
            if not msg["engine_id"]:                                    # découverte
                self.sock.sendto(self.report(msg["msg_id"], "1.3.6.1.6.3.15.1.1.4.0"), addr)
                continue
            if msg["user"] != self.user.name:
                self.sock.sendto(self.report(msg["msg_id"], "1.3.6.1.6.3.15.1.1.3.0"), addr)
                continue
            if not snmpv3.verify(pkt, msg, self.key, self.user.proto):
                if not self.silent:
                    self.sock.sendto(self.report(msg["msg_id"], "1.3.6.1.6.3.15.1.1.5.0"), addr)
                continue
            out = []
            for oid, _ in msg["varbinds"]:
                t = snmp.oid_tuple(oid)
                if msg["pdu_type"] == snmp.GET:
                    out.append((oid, self.data[t]) if t in self.data else (oid, b""))
                else:
                    nxt = [(k, v) for k, v in self.data.items() if k > t][:20 if msg["pdu_type"] == snmp.GETBULK else 1]
                    out += [(".".join(map(str, k)), v) for k, v in nxt]
            self.sock.sendto(self.respond(msg, out), addr)


class KeyDerivationTests(unittest.TestCase):
    """Vecteurs de test du RFC 3414, annexe A.3."""
    EID = bytes.fromhex("000000000000000000000002")

    def test_md5_key_localisation(self):
        ku = snmpv3.password_to_key("maplesyrup", "md5")
        self.assertEqual(ku.hex(), "9faf3283884e92834ebc9847d8edd963")
        self.assertEqual(snmpv3.localize(ku, self.EID, "md5").hex(), "526f5eed9fcce26f8964c2930787d82b")

    def test_sha1_key_localisation(self):
        ku = snmpv3.password_to_key("maplesyrup", "sha1")
        self.assertEqual(ku.hex(), "9fb5cc0381497b3793528939ff788d5d79145211")
        self.assertEqual(snmpv3.localize(ku, self.EID, "sha1").hex(), "6695febc9288e36282235fc7151f128497b38f3f")

    def test_user_is_validated_and_never_prints_its_password(self):
        for bad in (("", "motdepasse-long", "sha1"), ("u", "court", "sha1"), ("u", "motdepasse-long", "rot13")):
            with self.assertRaises(ValueError):
                snmpv3.V3User(*bad)
        self.assertNotIn("motdepasse", repr(USER)); self.assertNotIn("motdepasse", str(USER))

    def test_digest_lengths(self):
        self.assertEqual([len(snmpv3.digest(b"k" * 16, p, b"x")) for p in ("md5", "sha1", "sha256")], [12, 12, 24])


class MessageTests(unittest.TestCase):
    def test_request_signature_is_inserted_at_the_right_place_and_verifies(self):
        key = snmpv3.localize(snmpv3.password_to_key(USER.password, USER.proto), ENGINE, USER.proto)
        pkt = snmpv3.build_request(USER, key, (ENGINE, 3, 1000), 77, snmp.GET, 5, ["1.3.6.1.2.1.1.5.0"])
        msg = snmpv3.parse_message(pkt)
        self.assertEqual((msg["msg_id"], msg["engine_id"], msg["user"], msg["pdu_type"], msg["req_id"]), (77, ENGINE, "lecteur", snmp.GET, 5))
        self.assertTrue(snmpv3.verify(pkt, msg, key, "sha1"))
        for i in range(len(pkt)):                                          # un octet modifié n'importe où : la signature ne passe plus
            bad = bytearray(pkt); bad[i] ^= 0x01
            try:
                m = snmpv3.parse_message(bytes(bad))
            except (snmp.SnmpError, IndexError, ValueError):
                continue
            self.assertFalse(snmpv3.verify(bytes(bad), m, key, "sha1"), f"octet {i}")

    def test_discovery_message_is_unauthenticated_and_parses(self):
        msg = snmpv3.parse_message(snmpv3.build_discovery(9, 4))
        self.assertEqual((msg["flags"], msg["engine_id"], msg["user"]), (0x04, b"", ""))

    def test_garbage_is_a_clear_error(self):
        for bad in (b"", b"\x30", b"\x30\x03\x02\x01\x03", b"\xff" * 40, snmp.build_request(snmp.GET, "public", 1, ["1.3.6.1.2.1.1.1.0"])):
            with self.assertRaises((snmp.SnmpError, IndexError, ValueError)):
                snmpv3.parse_message(bad)


class ClientTests(unittest.TestCase):
    def start(self, **kw):
        agent = FakeV3Agent(test_snmp.switch_data(), **kw)
        agent.start()
        self.addCleanup(lambda: (setattr(agent, "stop", True), agent.join(1), agent.sock.close()))
        return agent

    def test_get_and_full_table_read_over_v3(self):
        a = self.start()
        info = snmp.get("127.0.0.1", USER, ["1.3.6.1.2.1.1.5.0"], port=a.port, timeout=1.0)
        self.assertEqual(info["1.3.6.1.2.1.1.5.0"], b"core-sw")
        res = snmp.read_tables("127.0.0.1", USER, port=a.port, timeout=1.0)
        self.assertEqual(res["name"], "core-sw")
        self.assertEqual(len(res["arp"]), 45)                                # plusieurs tours de GETBULK, tous signés
        self.assertTrue(all(m["flags"] & 1 for m in a.seen if m["engine_id"]))   # toute requête après la découverte est authentifiée

    def test_sha256_and_md5_users(self):
        for proto in ("sha256", "md5"):
            user = snmpv3.V3User("lecteur", "motdepasse-long", proto)
            a = self.start(user=user)
            self.assertEqual(snmp.get("127.0.0.1", user, ["1.3.6.1.2.1.1.5.0"], port=a.port, timeout=1.0)["1.3.6.1.2.1.1.5.0"], b"core-sw", proto)

    def test_wrong_password_unknown_user_and_wrong_algorithm_give_clear_errors(self):
        a = self.start()
        cases = {"mauvais mot de passe": snmpv3.V3User("lecteur", "autre-motdepasse", "sha1"),
                 "utilisateur inconnu": snmpv3.V3User("intrus", "motdepasse-long", "sha1"),
                 "mauvais algorithme": snmpv3.V3User("lecteur", "motdepasse-long", "md5")}
        for label, user in cases.items():
            with self.assertRaises(snmp.SnmpError, msg=label) as e:
                snmp.get("127.0.0.1", user, ["1.3.6.1.2.1.1.5.0"], port=a.port, timeout=0.5)
            self.assertIn("SNMP v3", str(e.exception), label)

    def test_a_response_with_a_forged_signature_is_never_accepted(self):
        a = self.start(forge=True)
        with self.assertRaises(snmp.SnmpError) as e:
            snmp.get("127.0.0.1", USER, ["1.3.6.1.2.1.1.5.0"], port=a.port, timeout=0.3)
        self.assertIn("pas de réponse", str(e.exception))                    # ignorée comme du bruit, pas lue

    def test_silent_agent(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0))
        self.addCleanup(s.close)
        with self.assertRaises(snmp.SnmpError):
            snmp.get("127.0.0.1", USER, ["1.3.6.1.2.1.1.5.0"], port=s.getsockname()[1], timeout=0.2)

    def test_v2c_still_works_unchanged(self):
        agent = test_snmp.FakeAgent(test_snmp.switch_data()); agent.start()
        self.addCleanup(lambda: (setattr(agent, "stop", True), agent.join(1), agent.sock.close()))
        self.assertEqual(snmp.get("127.0.0.1", "public", ["1.3.6.1.2.1.1.5.0"], port=agent.port, timeout=1.0)["1.3.6.1.2.1.1.5.0"], b"core-sw")


if __name__ == "__main__":
    unittest.main()
