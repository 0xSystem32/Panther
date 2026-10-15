"""Lecture d'un certificat HTTPS (X.509 / DER) sans bibliothèque externe, pour en tirer des indices : un NAS ou une caméra
y inscrit souvent sa marque ou son modèle. Réutilise le décodeur BER/DER de `snmp.py`.

Le certificat vient d'un appareil non fiable : toute lecture est bornée et une erreur de format donne simplement {}.
"""
import re
import time

from . import snmp

OID_NAMES = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C"}
OID_SAN = "2.5.29.17"
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_NOISE = re.compile(r"^(localhost(\.localdomain)?|\*|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]{12,})$", re.I)


def _string(tag, content):
    """Chaîne ASN.1 -> texte (UTF8, Printable, IA5, T61, BMP, Universal), nettoyé et borné."""
    codec = {0x0C: "utf-8", 0x13: "ascii", 0x16: "ascii", 0x14: "latin-1", 0x1E: "utf-16-be", 0x1C: "utf-32-be"}.get(tag)
    if not codec:
        return ""
    return _CTRL.sub(" ", bytes(content[:400]).decode(codec, "ignore")).strip()[:100]


def _name(der):
    """Name (SEQUENCE de SET de SEQUENCE{OID, valeur}) -> {"CN": ..., "O": ..., "OU": ..., "C": ...}."""
    out, (_, body, _) = {}, snmp.parse_tlv(der, 0)
    off = 0
    while off < len(body):
        _, rdn, off = snmp.parse_tlv(body, off)
        o2 = 0
        while o2 < len(rdn):
            _, atv, o2 = snmp.parse_tlv(rdn, o2)
            _, oid_b, p = snmp.parse_tlv(atv, 0)
            vtag, val, _ = snmp.parse_tlv(atv, p)
            key, text = OID_NAMES.get(snmp.dec_oid(oid_b)), _string(vtag, val)
            if key and text and key not in out:  # une valeur vide ou d'un type inconnu ne masque pas une valeur valide qui suit
                out[key] = text
    return out


def _time(tag, content):
    """UTCTime (0x17, AAMMJJhhmmssZ) ou GeneralizedTime (0x18, AAAAMMJJhhmmssZ) -> secondes epoch, ou None."""
    t = bytes(content).decode("ascii", "ignore")
    m = re.match(r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$", t) if tag == 0x17 else re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$", t)
    if not m:
        return None
    y, *rest = (int(x) for x in m.groups())
    if tag == 0x17:
        y += 2000 if y < 50 else 1900
    try:
        import calendar
        return calendar.timegm((y, *rest))
    except (ValueError, OverflowError):
        return None


def _san(ext_value):
    """Noms DNS de l'extension subjectAltName."""
    out: list = []
    (_, seq, _) = snmp.parse_tlv(ext_value, 0)
    off = 0
    while off < len(seq) and len(out) < 10:
        tag, val, off = snmp.parse_tlv(seq, off)
        if tag == 0x82:  # dNSName
            name = _CTRL.sub(" ", bytes(val[:200]).decode("ascii", "ignore")).strip()
            if name:
                out.append(name[:100])
    return out


def parse_cert(der, now=None):
    """DER -> {subject, issuer, self_signed, san, not_before, not_after, expired} ; {} si illisible."""
    try:
        _, cert, _ = snmp.parse_tlv(der, 0)
        _, tbs, _ = snmp.parse_tlv(cert, 0)
        off = 0
        tag, first, off = snmp.parse_tlv(tbs, off)
        if tag == 0xA0:                                   # version [0] (absente dans les v1)
            _, _, off = snmp.parse_tlv(tbs, off)          # numéro de série
        _, _, off = snmp.parse_tlv(tbs, off)              # algorithme de signature
        i0 = off
        _, _, off = snmp.parse_tlv(tbs, off)
        issuer = _name(tbs[i0:off])
        _, validity, off = snmp.parse_tlv(tbs, off)
        t1, v1, p = snmp.parse_tlv(validity, 0)
        t2, v2, _ = snmp.parse_tlv(validity, p)
        s0 = off
        _, _, off = snmp.parse_tlv(tbs, off)
        subject = _name(tbs[s0:off])
        san = []
        _, _, off = snmp.parse_tlv(tbs, off)              # subjectPublicKeyInfo
        while off < len(tbs):                              # extensions [3]
            tg, ext, off = snmp.parse_tlv(tbs, off)
            if tg != 0xA3:
                continue
            _, exts, _ = snmp.parse_tlv(ext, 0)
            o = 0
            while o < len(exts):
                _, one, o = snmp.parse_tlv(exts, o)
                _, oid_b, p = snmp.parse_tlv(one, 0)
                nxt_tag, nxt, p2 = snmp.parse_tlv(one, p)
                if nxt_tag == 0x01:                        # critical BOOLEAN : la valeur suit
                    nxt_tag, nxt, p2 = snmp.parse_tlv(one, p2)
                if snmp.dec_oid(oid_b) == OID_SAN and nxt_tag == 0x04:
                    san = _san(nxt)
    except (snmp.SnmpError, IndexError, ValueError, TypeError):
        return {}
    nb, na = _time(t1, v1), _time(t2, v2)
    now = time.time() if now is None else now

    def day(ts):
        return time.strftime("%Y-%m-%d", time.gmtime(ts)) if ts else ""
    return {"subject": subject, "issuer": issuer, "self_signed": bool(subject) and subject == issuer, "san": san,
            "not_before": day(nb), "not_after": day(na), "expired": bool(na and na < now)}


def indicators(info):
    """Texte utile à la classification : sans les valeurs « bruit » (localhost, UUID, adresses IP)."""
    parts = []
    for k in ("O", "OU", "CN"):
        v = (info.get("subject") or {}).get(k, "")
        if v and not _NOISE.match(v):
            parts.append(v)
    if not info.get("self_signed"):
        v = (info.get("issuer") or {}).get("O", "")
        if v and not _NOISE.match(v):
            parts.append(v)
    parts += [s for s in info.get("san", []) if not _NOISE.match(s)][:3]
    return " ".join(dict.fromkeys(parts))


def summary(info):
    """Résumé compact stocké dans l'appareil (JSON-compatible)."""
    if not info:
        return {}
    s = info.get("subject") or {}
    return {"cn": s.get("CN", ""), "o": s.get("O", ""), "ou": s.get("OU", ""), "issuer": (info.get("issuer") or {}).get("O") or (info.get("issuer") or {}).get("CN", ""),
            "self_signed": info.get("self_signed", False), "san": info.get("san", []), "not_after": info.get("not_after", ""),
            "expired": info.get("expired", False), "indicators": indicators(info)}
