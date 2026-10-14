"""Réseaux et VLAN : détection des plages joignables, validation des cibles de scan.

Panther ne scanne que des réseaux privés (RFC 1918) de taille raisonnable.
"""
import ipaddress
import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

MAX_HOSTS = 4096  # /20


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def validate_cidr(text):
    """Texte -> ip_network, ou ValueError avec un message clair en français."""
    text = (text or "").strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"« {text} » n'est pas une plage valide (exemple : 192.168.20.0/24).") from None
    if net.version != 4:
        raise ValueError("Seul l'IPv4 est géré pour le moment.")
    if not net.is_private or net.is_loopback and net.prefixlen < 24:
        raise ValueError("Plage publique refusée : Panther ne scanne que des réseaux privés "
                         "(10.x, 172.16-31.x, 192.168.x).")
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(f"Plage trop grande ({net.num_addresses} adresses, maximum {MAX_HOSTS} : /20).")
    return net


def vlan_ids():
    """{interface: id VLAN 802.1Q} pour les sous-interfaces VLAN locales."""
    out = {}
    for line in _run(["ip", "-d", "-o", "link", "show"]).splitlines():
        m = re.match(r"\d+:\s+([^:@\s]+)", line)
        v = re.search(r"vlan protocol 802\.1Q id (\d+)", line)
        if m and v:
            out[m.group(1)] = int(v.group(1))
    return out


LINK_LABELS = {"wifi": "Wi-Fi", "ethernet": "Ethernet", "vpn": "VPN", "virtuel": "virtuelle"}


def link_kind(iface, sysfs="/sys/class/net"):
    """Nature d'une interface : wifi, ethernet, vpn ou virtuel (docker, machines virtuelles…)."""
    base = os.path.join(sysfs, iface)
    if os.path.isdir(os.path.join(base, "wireless")) or os.path.isdir(os.path.join(base, "phy80211")):
        return "wifi"
    try:
        with open(os.path.join(base, "type")) as f:
            if f.read().strip() == "65534":  # ARPHRD_NONE : tunnels (tun, wireguard…)
                return "vpn"
    except OSError:
        pass
    if re.match(r"(wg|tun|tap|ppp|tailscale|zt|mullvad|proton|nordlynx|ipsec)", iface):
        return "vpn"
    if re.match(r"(docker|veth|virbr|br-|vmnet|vboxnet|lxc|lxd|cni|flannel|podman)", iface):
        return "virtuel"
    return "ethernet"


def interfaces():
    """Réseaux directement connectés : [{iface, ip, cidr}] (hors loopback et /32 type VPN)."""
    res = []
    for line in _run(["ip", "-4", "-o", "addr", "show"]).splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\S+)", line)
        if not m or m.group(1) == "lo":
            continue
        try:
            itf = ipaddress.ip_interface(m.group(2))
        except ValueError:
            continue
        if itf.network.prefixlen >= 32 or not itf.ip.is_private:
            continue
        res.append({"iface": m.group(1), "ip": str(itf.ip), "cidr": str(itf.network), "kind": link_kind(m.group(1))})
    return res


def routes():
    """Routes statiques/apprises vers d'autres réseaux : [{cidr, via, iface}]."""
    res = []
    for line in _run(["ip", "-4", "route", "show"]).splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+/\d+)\s+via\s+(\S+)\s+dev\s+(\S+)", line)
        if m:
            try:
                validate_cidr(m.group(1))
            except ValueError:
                continue
            res.append({"cidr": m.group(1), "via": m.group(2), "iface": m.group(3)})
    return res


def known_networks(local_cidr=None):
    """Réseaux connus du système : connecté (local), autres interfaces, routes vers d'autres VLAN."""
    vlans = vlan_ids()
    nets, seen = [], set()

    def add(cidr, kind, **kw):
        if cidr not in seen:
            seen.add(cidr)
            nets.append({"cidr": cidr, "kind": kind, "vlan": vlans.get(kw.get("iface", "")), **kw})
    for it in interfaces():
        add(it["cidr"], "local" if it["cidr"] == local_cidr else "interface", iface=it["iface"], ip=it["ip"])
    for r in routes():
        add(r["cidr"], "routé", iface=r["iface"], via=r["via"])
    return nets


def describe(net):
    """Libellé lisible : '192.168.20.0/24 · VLAN 20 · via 192.168.1.254'."""
    parts = [net["cidr"]]
    if net.get("vlan"):
        parts.append(f"VLAN {net['vlan']}")
    if net.get("via"):
        parts.append(f"via {net['via']}")
    if net.get("hops") == 0:
        parts.append("interface de votre routeur")
    elif net.get("hops"):
        parts.append(f"~{net['hops']} saut(s)")
    return "  ·  ".join(parts)


def _alive(ip, ports=(80, 443, 53, 22), timeout=0.5):
    """Vrai si un hôte répond (connexion acceptée ou refusée). Les erreurs « réseau injoignable »
    ou les silences ne comptent pas."""
    for p in ports:
        s = socket.socket()
        s.settimeout(timeout)
        try:
            r = s.connect_ex((ip, p))
        except OSError:
            r = -1
        finally:
            s.close()
        if r in (0, 111):
            return True
    return False


def hops_from_ttl(ttl):
    """Nombre de routeurs traversés d'après le TTL reçu (0 = l'équipement répond lui-même)."""
    for initial in (64, 128, 255):
        if ttl <= initial:
            return initial - ttl
    return None


def ping_hops(ip):
    out = _run(["ping", "-c1", "-W1", ip])
    m = re.search(r"ttl=(\d+)", out, re.I)
    return hops_from_ttl(int(m.group(1))) if m else None


def candidate_gateways():
    """Passerelles probables d'autres VLAN : x.1 et x.254 des plages 192.168.X.0/24 et 10.0.X.0/24."""
    c = []
    for x in range(256):
        for last in (1, 254):
            c.append((f"192.168.{x}.{last}", f"192.168.{x}.0/24"))
            c.append((f"10.0.{x}.{last}", f"10.0.{x}.0/24"))
    return c


def discover_reachable(exclude=(), progress=None):
    """Sonde les passerelles probables et renvoie les réseaux joignables non encore connus."""
    excl = [ipaddress.ip_network(e) for e in exclude]
    cands = [(ip, cidr) for ip, cidr in candidate_gateways()
             if not any(ipaddress.ip_address(ip) in e for e in excl)]
    found, done = {}, [0]

    def probe(item):
        ip, cidr = item
        ok = _alive(ip)
        done[0] += 1
        if progress:
            progress(done[0], len(cands))
        return ok
    with ThreadPoolExecutor(96) as ex:
        for item, ok in zip(cands, ex.map(probe, cands)):
            if ok:
                found.setdefault(item[1], item[0])
    return [{"cidr": c, "kind": "découvert", "via": ip, "vlan": None, "hops": ping_hops(ip)}
            for c, ip in sorted(found.items())]
