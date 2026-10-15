"""SNMP v3, niveau authNoPriv (authentification, sans chiffrement), en lecture seule et stdlib uniquement.

* Algorithmes d'authentification : HMAC-MD5-96, HMAC-SHA-96 et HMAC-SHA-256 (24 octets, RFC 7860).
* Pas de chiffrement (authPriv) : la bibliothèque standard n'a ni AES ni DES. Les requêtes sont authentifiées et les réponses vérifiées,
  mais leur contenu circule en clair (adresses MAC et ports d'un switch) : à réserver à un réseau d'administration de confiance.
* Les clés sont dérivées du mot de passe (RFC 3414 §2.6 et A.2) et localisées pour le moteur de l'agent ; le mot de passe n'est jamais
  envoyé. Une réponse dont l'authentification est fausse est ignorée, jamais lue.
"""
import hashlib
import hmac
import random
import socket
from dataclasses import dataclass

from . import snmp
from .i18n import N_, tr
from .snmp import SnmpError, enc_int, enc_seq, enc_str, parse_tlv

PROTOCOLS = {"md5": (hashlib.md5, 12), "sha1": (hashlib.sha1, 12), "sha256": (hashlib.sha256, 24)}
REPORT = 0xA8
# usmStats* (RFC 3414) : motif d'un refus de l'agent, renvoyé dans un Report
USM_ERRORS = {"1.3.6.1.6.3.15.1.1.1.0": N_("niveau de sécurité non pris en charge"), "1.3.6.1.6.3.15.1.1.2.0": N_("hors de la fenêtre de temps"),
              "1.3.6.1.6.3.15.1.1.3.0": N_("utilisateur inconnu"), "1.3.6.1.6.3.15.1.1.4.0": N_("moteur inconnu"),
              "1.3.6.1.6.3.15.1.1.5.0": N_("authentification refusée (mot de passe ou algorithme incorrect)"),
              "1.3.6.1.6.3.15.1.1.6.0": N_("déchiffrement refusé")}


@dataclass(frozen=True)
class V3User:
    name: str
    password: str
    proto: str = "sha1"

    def __post_init__(self):
        if self.proto not in PROTOCOLS:
            raise ValueError(f"algorithme inconnu : {self.proto}")
        if not self.name or len(self.password) < 8:  # RFC 3414 : 8 caractères au moins
            raise ValueError("utilisateur vide ou mot de passe de moins de 8 caractères")

    def __repr__(self):  # le mot de passe ne doit jamais finir dans un journal ou une trace
        return f"V3User(name={self.name!r}, proto={self.proto!r})"


def credential(src):
    """Source SNMP de l'application -> ce que `snmp` attend : une communauté (v2c) ou un `V3User` (v3). Lève ValueError si elle est incomplète.
    v2c : {"host", "community"} ; v3 : {"host", "user", "auth_proto", "auth_password"}."""
    if src.get("user"):
        return V3User(str(src["user"]), str(src.get("auth_password") or ""), str(src.get("auth_proto") or "sha1"))
    return str(src.get("community") or "public")


# ------------------------------------------------------------------ clés (RFC 3414)
def password_to_key(password, proto):
    """Mot de passe -> clé (Ku) : le mot de passe répété jusqu'à 1 048 576 octets, puis haché (RFC 3414 A.2.1 / A.2.2)."""
    pw = password.encode("utf-8")
    return PROTOCOLS[proto][0]((pw * (1048576 // len(pw) + 1))[:1048576]).digest()


def localize(ku, engine_id, proto):
    """Clé liée à un moteur précis : un mot de passe volé sur un agent ne sert pas sur un autre."""
    return PROTOCOLS[proto][0](ku + engine_id + ku).digest()


def digest(key, proto, message):
    return hmac.new(key, message, PROTOCOLS[proto][0]).digest()[:PROTOCOLS[proto][1]]


# ------------------------------------------------------------------ messages
def _usm(engine_id, boots, time_, user, auth):
    return enc_seq(enc_str(engine_id) + enc_int(boots) + enc_int(time_) + enc_str(user.encode()) + enc_str(auth) + enc_str(b""))


def build_message(msg_id, flags, usm_params_for, scoped):
    return enc_seq(enc_int(3) + enc_seq(enc_int(msg_id) + enc_int(65507) + enc_str(bytes([flags])) + enc_int(3)) + enc_str(usm_params_for) + scoped)


def scoped_pdu(engine_id, pdu_type, req_id, oids, nonrep=0, maxrep=0):
    vbs = b"".join(enc_seq(snmp.enc_oid(o) + snmp.enc_null()) for o in oids)
    pdu = enc_seq(enc_int(req_id) + enc_int(nonrep) + enc_int(maxrep) + enc_seq(vbs), tag=pdu_type)
    return enc_seq(enc_str(engine_id) + enc_str(b"") + pdu)


def build_request(user, key, engine, msg_id, pdu_type, req_id, oids, nonrep=0, maxrep=0):
    """Requête authentifiée (authNoPriv, réponse attendue). `engine` = (engine_id, boots, time). La signature couvre le message entier."""
    engine_id, boots, time_ = engine
    n = PROTOCOLS[user.proto][1]
    scoped = scoped_pdu(engine_id, pdu_type, req_id, oids, nonrep, maxrep)
    zero = build_message(msg_id, 0x05, _usm(engine_id, boots, time_, user.name, b"\x00" * n), scoped)
    one = build_message(msg_id, 0x05, _usm(engine_id, boots, time_, user.name, b"\x01" * n), scoped)
    start = next(i for i, (a, b) in enumerate(zip(zero, one, strict=True)) if a != b)  # où la signature s'insère
    sig = digest(key, user.proto, zero)
    return zero[:start] + sig + zero[start + n:]


def build_discovery(msg_id, req_id):
    """Requête sans authentification ni moteur connu : l'agent répond par un Report qui donne son moteur, ses redémarrages et son horloge."""
    scoped = scoped_pdu(b"", snmp.GET, req_id, [])
    return build_message(msg_id, 0x04, _usm(b"", 0, 0, "", b""), scoped)


def parse_message(data):
    """-> dict {msg_id, flags, engine_id, boots, time, user, auth, auth_offset, pdu_type, req_id, error, varbinds}. Lève SnmpError."""
    tag, body, _ = parse_tlv(data, 0)
    if tag != 0x30:
        raise SnmpError(tr("message SNMP invalide"))
    body_start = len(data) - len(body)  # début du contenu de la séquence extérieure (en-tête de longueur variable)
    _, ver, o = parse_tlv(body, 0)
    if int.from_bytes(ver, "big") != 3:
        raise SnmpError(tr("message SNMP invalide"))
    _, glob, o = parse_tlv(body, o)
    _, mid, g = parse_tlv(glob, 0)
    _, _, g = parse_tlv(glob, g)
    _, flags, g = parse_tlv(glob, g)
    sec_tag, sec_content, o2 = parse_tlv(body, o)
    sec_start = body_start + o2 - len(sec_content)
    _, usm, _ = parse_tlv(sec_content, 0)
    _, eid, p = parse_tlv(usm, 0)
    _, boots, p = parse_tlv(usm, p)
    _, time_, p = parse_tlv(usm, p)
    _, name, p = parse_tlv(usm, p)
    usm_start = sec_start + (len(sec_content) - len(usm))
    atag, auth, p2 = parse_tlv(usm, p)
    auth_offset = usm_start + p2 - len(auth)
    _, _, p = parse_tlv(usm, p2)  # privParams
    st, scoped, _ = parse_tlv(body, o2)
    if sec_tag != 0x04 or st != 0x30:
        raise SnmpError(tr("message SNMP invalide"))
    _, _, q = parse_tlv(scoped, 0)    # contextEngineID
    _, _, q = parse_tlv(scoped, q)    # contextName
    ptag, pdu, _ = parse_tlv(scoped, q)
    _, rid, r = parse_tlv(pdu, 0)
    _, err, r = parse_tlv(pdu, r)
    _, _, r = parse_tlv(pdu, r)
    _, vbl, _ = parse_tlv(pdu, r)
    vbs, r = [], 0
    while r < len(vbl):
        _, vb, r = parse_tlv(vbl, r)
        _, oid_b, p3 = parse_tlv(vb, 0)
        vt, vv, _ = parse_tlv(vb, p3)
        vbs.append((snmp.dec_oid(oid_b), snmp.dec_value(vt, vv)))
    return {"msg_id": int.from_bytes(mid, "big"), "flags": flags[0] if flags else 0, "engine_id": bytes(eid), "boots": int.from_bytes(boots, "big"),
            "time": int.from_bytes(time_, "big"), "user": bytes(name).decode("utf-8", "ignore"), "auth": bytes(auth), "auth_offset": auth_offset,
            "pdu_type": ptag, "req_id": int.from_bytes(rid, "big", signed=True), "error": int.from_bytes(err, "big"), "varbinds": vbs}


def verify(data, msg, key, proto):
    """Vrai si la signature du message reçu est correcte (comparaison en temps constant)."""
    n = PROTOCOLS[proto][1]
    if len(msg["auth"]) != n or not msg["flags"] & 0x01:
        return False
    zeroed = data[:msg["auth_offset"]] + b"\x00" * n + data[msg["auth_offset"] + n:]
    return hmac.compare_digest(digest(key, proto, zeroed), msg["auth"])


def refusal(varbinds):
    """Texte du motif d'un Report de l'agent, ou None."""
    for oid, _v in varbinds:
        if oid in USM_ERRORS:
            return tr(USM_ERRORS[oid])
    return None


# ------------------------------------------------------------------ client
def exchange(host, user, pdu_type, oids, port=161, timeout=2.0, retries=2, nonrep=0, maxrep=0):
    """Même contrat que `snmp._exchange` : -> [(oid, valeur)] ou SnmpError. Découverte du moteur, puis requête signée, réponse vérifiée."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)

    def ask(pkt, accept):
        for _ in range(retries + 1):
            s.sendto(pkt, (host, port))
            try:
                while True:
                    data, addr = s.recvfrom(65535)
                    if addr[0] != host:
                        continue
                    try:
                        msg = parse_message(data)
                    except (SnmpError, IndexError, ValueError):
                        continue
                    out = accept(data, msg)
                    if out is not None:
                        return out
            except TimeoutError:
                continue
        raise SnmpError(tr("pas de réponse (utilisateur ou mot de passe incorrect, SNMP v3 désactivé ou filtré)"))
    try:
        mid, rid = random.randint(1, 2 ** 30), random.randint(1, 2 ** 30)
        found = ask(build_discovery(mid, rid), lambda d, m: m if m["msg_id"] == mid and m["engine_id"] else None)
        engine = (found["engine_id"], found["boots"], found["time"])
        key = localize(password_to_key(user.password, user.proto), engine[0], user.proto)
        mid, rid = random.randint(1, 2 ** 30), random.randint(1, 2 ** 30)
        pkt = build_request(user, key, engine, mid, pdu_type, rid, oids, nonrep, maxrep)

        def accept(data, m):
            if m["msg_id"] != mid:
                return None
            if m["pdu_type"] == REPORT:  # refus de l'agent : non signé, donc informatif seulement
                why = refusal(m["varbinds"])
                if why:
                    raise SnmpError(tr("SNMP v3 : {why}", why=why))
                return None
            if not verify(data, m, key, user.proto):
                return None  # fausse signature : jamais lue
            if m["req_id"] != rid or m["pdu_type"] != snmp.RESPONSE:
                return None
            if m["error"]:
                raise SnmpError(tr("erreur SNMP {err}", err=m["error"]))
            return m["varbinds"]
        return ask(pkt, accept)
    finally:
        s.close()
