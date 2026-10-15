"""Profils de scan enregistrés : plages, profondeur, interface, hôtes SNMP et options, sous un nom.

Module pur (stdlib). Un profil ne contient AUCUN secret : les hôtes SNMP y figurent sans leur communauté, qui reste dans le trousseau
(`secrets`) et est relue à l'application du profil. Les profils sont enregistrés dans les réglages de l'application ; `clean` traite
cette donnée comme non fiable (types, tailles, plages valides, doublons).
"""
import ipaddress
import re

from . import networks

DEPTHS = ("presence", "rapide", "normal", "approfondi")
MAX_PROFILES, MAX_NAME, MAX_TARGETS, MAX_SNMP = 20, 40, 16, 8
_IFACE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")


def clean_name(name):
    return " ".join(str(name or "").split())[:MAX_NAME]


def make(name, targets=(), depth="normal", iface="", snmp_hosts=(), security=False, passive=False):
    """Profil propre, ou ValueError si le nom est vide. Les plages invalides ou publiques sont écartées en silence (le scan les refuserait)."""
    name = clean_name(name)
    if not name:
        raise ValueError("nom de profil vide")
    cidrs = []
    for t in list(targets)[:MAX_TARGETS * 2]:
        try:
            c = str(networks.validate_cidr(str(t)))
        except ValueError:
            continue
        if c not in cidrs:
            cidrs.append(c)
    hosts = []
    for h in list(snmp_hosts)[:MAX_SNMP * 2]:
        try:
            ip = ipaddress.ip_address(str(h).strip())
        except ValueError:
            continue
        if ip.is_private and str(ip) not in hosts:
            hosts.append(str(ip))
    iface = str(iface or "")
    return {"name": name, "targets": cidrs[:MAX_TARGETS], "depth": depth if depth in DEPTHS else "normal",
            "iface": iface if _IFACE.match(iface) else "", "snmp": hosts[:MAX_SNMP], "security": bool(security) and not passive,
            "passive": bool(passive)}


def clean(raw):
    """Liste brute (JSON des réglages) -> liste de profils valides, sans doublon de nom (insensible à la casse)."""
    out, seen = [], set()
    for p in raw if isinstance(raw, list) else []:
        if not isinstance(p, dict):
            continue
        try:
            prof = make(p.get("name"), p.get("targets") if isinstance(p.get("targets"), list) else [], p.get("depth", "normal"), p.get("iface", ""),
                        p.get("snmp") if isinstance(p.get("snmp"), list) else [], p.get("security", False), p.get("passive", False))
        except ValueError:
            continue
        if prof["name"].lower() not in seen:
            seen.add(prof["name"].lower())
            out.append(prof)
    return out[:MAX_PROFILES]


def upsert(profiles, profile):
    """Ajoute le profil, ou remplace celui du même nom (casse ignorée). Au-delà de MAX_PROFILES : ValueError."""
    rest = [p for p in profiles if p["name"].lower() != profile["name"].lower()]
    if len(rest) >= MAX_PROFILES:
        raise ValueError("trop de profils")
    return rest + [profile]


def remove(profiles, name):
    return [p for p in profiles if p["name"].lower() != clean_name(name).lower()]
