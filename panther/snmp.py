"""Client SNMP v2c minimal en lecture seule (stdlib uniquement).

Sert à interroger un routeur ou un switch *que l'utilisateur désigne* : sa table ARP donne les
adresses MAC des hôtes d'autres VLAN, sa table de transmission (FDB) donne le port et le VLAN.
Aucune écriture (pas de SET), aucune devinette de communauté.
"""
import ipaddress
import socket
import struct
import random

GET, GETNEXT, RESPONSE, GETBULK = 0xA0, 0xA1, 0xA2, 0xA5
EOM = object()  # endOfMibView / noSuchObject / noSuchInstance


class SnmpError(Exception):
    pass


# ------------------------------------------------------------------ BER
def _len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, content):
    return bytes([tag]) + _len(len(content)) + content


def enc_int(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return _tlv(0x02, v.to_bytes(n, "big", signed=True))


def enc_str(b):
    return _tlv(0x04, b)


def enc_null():
    return b"\x05\x00"


def enc_oid(oid):
    parts = [int(x) for x in oid.strip(".").split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, out)


def enc_seq(content, tag=0x30):
    return _tlv(tag, content)


def parse_tlv(data, off):
    """-> (tag, contenu, offset suivant). Lève SnmpError si le paquet est tronqué."""
    try:
        tag = data[off]
        n = data[off + 1]
        off += 2
        if n & 0x80:
            k = n & 0x7F
            if k == 0 or k > 4:
                raise SnmpError("longueur BER invalide")
            n = int.from_bytes(data[off: off + k], "big")
            off += k
        if off + n > len(data):
            raise SnmpError("paquet tronqué")
        return tag, data[off: off + n], off + n
    except IndexError:
        raise SnmpError("paquet tronqué") from None


def dec_oid(b):
    if not b:
        return ""
    parts = [b[0] // 40, b[0] % 40]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def dec_value(tag, b):
    if tag in (0x02, 0x41, 0x42, 0x43, 0x46):
        return int.from_bytes(b, "big", signed=(tag == 0x02))
    if tag == 0x04:
        return bytes(b)
    if tag == 0x06:
        return dec_oid(b)
    if tag == 0x40 and len(b) == 4:
        return str(ipaddress.ip_address(bytes(b)))
    if tag in (0x80, 0x81, 0x82):
        return EOM
    return None


def oid_tuple(oid):
    return tuple(int(x) for x in oid.split("."))


# ------------------------------------------------------------------ messages
def build_request(pdu_type, community, req_id, oids, nonrep=0, maxrep=0):
    vbs = b"".join(enc_seq(enc_oid(o) + enc_null()) for o in oids)
    pdu = enc_seq(enc_int(req_id) + enc_int(nonrep) + enc_int(maxrep) + enc_seq(vbs), tag=pdu_type)
    return enc_seq(enc_int(1) + enc_str(community.encode()) + pdu)


def parse_message(data):
    """-> (pdu_type, req_id, error_status, [(oid, valeur)])."""
    tag, body, _ = parse_tlv(data, 0)
    if tag != 0x30:
        raise SnmpError("message SNMP invalide")
    _, _, off = parse_tlv(body, 0)            # version
    _, _, off = parse_tlv(body, off)          # communauté
    ptag, pdu, _ = parse_tlv(body, off)
    _, rid, o = parse_tlv(pdu, 0)
    _, err, o = parse_tlv(pdu, o)
    _, _, o = parse_tlv(pdu, o)               # error-index / max-repetitions
    _, vbl, _ = parse_tlv(pdu, o)
    out, o = [], 0
    while o < len(vbl):
        _, vb, o = parse_tlv(vbl, o)
        _, oid_b, p = parse_tlv(vb, 0)
        vt, vv, _ = parse_tlv(vb, p)
        out.append((dec_oid(oid_b), dec_value(vt, vv)))
    return ptag, int.from_bytes(rid, "big", signed=True), int.from_bytes(err, "big"), out


# ------------------------------------------------------------------ client
def _exchange(host, community, pdu_type, oids, port, timeout, retries=2, nonrep=0, maxrep=0):
    req_id = random.randint(1, 2 ** 30)
    pkt = build_request(pdu_type, community, req_id, oids, nonrep, maxrep)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        for _ in range(retries + 1):
            s.sendto(pkt, (host, port))
            try:
                while True:
                    data, addr = s.recvfrom(65535)
                    if addr[0] != host:
                        continue
                    ptag, rid, err, vbs = parse_message(data)
                    if ptag == RESPONSE and rid == req_id:
                        if err:
                            raise SnmpError(f"erreur SNMP {err}")
                        return vbs
            except socket.timeout:
                continue
        raise SnmpError("pas de réponse (communauté incorrecte, SNMP désactivé ou filtré)")
    finally:
        s.close()


def get(host, community, oids, port=161, timeout=2.0):
    return dict(_exchange(host, community, GET, oids, port, timeout))


def walk(host, community, base, port=161, timeout=2.0, max_rows=20000):
    """Parcourt un sous-arbre (GETBULK). -> [(oid, valeur)] dans l'ordre."""
    out, last, base_t = [], base, oid_tuple(base)
    while len(out) < max_rows:
        vbs = _exchange(host, community, GETBULK, [last], port, timeout, nonrep=0, maxrep=20)
        progressed = False
        for oid, val in vbs:
            if val is EOM or oid_tuple(oid)[:len(base_t)] != base_t:
                return out
            if oid_tuple(oid) <= oid_tuple(last):
                return out  # l'agent ne progresse plus : on s'arrête (anti-boucle)
            out.append((oid, val))
            last, progressed = oid, True
        if not progressed:
            break
    return out


# ------------------------------------------------------------------ tables utiles
def _mac(b):
    return ":".join(f"{x:02x}" for x in b) if isinstance(b, (bytes, bytearray)) and len(b) == 6 else ""


def _suffix(oid, base):
    return [int(x) for x in oid[len(base) + 1:].split(".")]


def read_tables(host, community, port=161, timeout=2.0):
    """Lit nom, ARP, FDB et VLAN d'un équipement.
    -> {name, descr, arp:{ip: mac}, fdb:{mac: {vlan, port}}, vlans:{id: nom}}"""
    kw = dict(port=port, timeout=timeout)
    info = get(host, community, ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0"], **kw)  # lève SnmpError si muet
    txt = lambda v: v.decode("utf-8", "ignore") if isinstance(v, bytes) else ""
    res = {"name": txt(info.get("1.3.6.1.2.1.1.5.0")), "descr": txt(info.get("1.3.6.1.2.1.1.1.0"))[:120],
           "arp": {}, "fdb": {}, "vlans": {}}

    def safe(base):
        try:
            return walk(host, community, base, **kw)
        except SnmpError:
            return []
    arp_base = "1.3.6.1.2.1.4.22.1.2"
    for oid, v in safe(arp_base):
        sfx = _suffix(oid, arp_base)
        if len(sfx) == 5 and _mac(v):
            res["arp"][".".join(map(str, sfx[1:]))] = _mac(v)
    for oid, v in safe("1.3.6.1.2.1.17.7.1.4.3.1.1"):
        res["vlans"][_suffix(oid, "1.3.6.1.2.1.17.7.1.4.3.1.1")[-1]] = txt(v)
    port_if = {_suffix(o, "1.3.6.1.2.1.17.1.4.1.2")[-1]: v for o, v in safe("1.3.6.1.2.1.17.1.4.1.2")}
    names = {_suffix(o, "1.3.6.1.2.1.31.1.1.1.1")[-1]: txt(v) for o, v in safe("1.3.6.1.2.1.31.1.1.1.1")}
    if not names:
        names = {_suffix(o, "1.3.6.1.2.1.2.2.1.2")[-1]: txt(v) for o, v in safe("1.3.6.1.2.1.2.2.1.2")}

    def port_name(bp):
        idx = port_if.get(bp)
        return names.get(idx) or f"port {bp}"
    q_base = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    rows = safe(q_base)
    if rows:
        for oid, v in rows:
            sfx = _suffix(oid, q_base)
            if len(sfx) == 7 and isinstance(v, int):
                res["fdb"][_mac(bytes(sfx[1:]))] = {"vlan": sfx[0], "port": port_name(v)}
    else:
        b_base = "1.3.6.1.2.1.17.4.3.1.2"
        for oid, v in safe(b_base):
            sfx = _suffix(oid, b_base)
            if len(sfx) == 6 and isinstance(v, int):
                res["fdb"][_mac(bytes(sfx))] = {"vlan": None, "port": port_name(v)}
    return res
