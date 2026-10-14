"""Noms d'hôte annoncés lors des baux DHCP, quand cette machine est aussi le serveur DHCP (dnsmasq, Pi-hole, isc-dhcp).

Sur un poste client, ces fichiers n'existent pas : cette source est alors simplement vide. Lecture seule, texte non fiable.
"""
import re

PATHS = ("/var/lib/misc/dnsmasq.leases", "/var/lib/dnsmasq/dnsmasq.leases", "/etc/pihole/dhcp.leases", "/var/lib/dhcp/dhcpd.leases")
MAX_BYTES = 4 * 1024 * 1024
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,62}$")


def parse_dnsmasq(text):
    """Lignes « expiration mac ip nom identifiant » -> {mac: nom} (le nom « * » signifie : aucun)."""
    out = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 4 and _MAC.match(p[1].lower()) and p[3] != "*" and _NAME.match(p[3]):
            out[p[1].lower()] = p[3]
    return out


def parse_isc(text):
    """Blocs « lease ip { hardware ethernet mac; client-hostname "nom"; } » -> {mac: nom} (le dernier bail l'emporte)."""
    out = {}
    for block in re.findall(r"lease\s+[\d.]+\s*\{(.*?)\}", text, re.S):
        mac = re.search(r"hardware ethernet\s+([0-9a-fA-F:]{17})\s*;", block)
        name = re.search(r'client-hostname\s+"([^"]+)"\s*;', block)
        if mac and name and _MAC.match(mac.group(1).lower()) and _NAME.match(name.group(1)):
            out[mac.group(1).lower()] = name.group(1)
    return out


def read_leases(paths=PATHS):
    out = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read(MAX_BYTES)
        except OSError:
            continue
        out.update(parse_isc(text) if "lease " in text and "{" in text else parse_dnsmasq(text))
    return out
