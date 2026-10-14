"""Découverte passive/active de services : SSDP/UPnP et mDNS/Bonjour (stdlib uniquement).

Ces protocoles font parler les appareils qui filtrent le TCP : une imprimante annonce
`_ipp._tcp`, une TV `_googlecast._tcp`, un iPhone `_companion-link._tcp`, etc.
"""
import logging
import re
import select
import socket
import struct
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("panther.discovery")
SSDP_ADDR = ("239.255.255.250", 1900)
MDNS_ADDR = ("224.0.0.251", 5353)

MDNS_SERVICES = [
    "_services._dns-sd._udp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp",
    "_scanner._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_companion-link._tcp",
    "_apple-mobdev2._tcp", "_hap._tcp", "_homekit._tcp", "_spotify-connect._tcp", "_smb._tcp",
    "_afpovertcp._tcp", "_workstation._tcp", "_device-info._tcp", "_rfb._tcp", "_sonos._tcp",
    "_http._tcp", "_ssh._tcp", "_daap._tcp", "_androidtvremote2._tcp", "_amzn-wplay._tcp",
]


# ------------------------------------------------------------------ SSDP / UPnP
def _parse_ssdp(data):
    lines = data.decode("latin-1", "ignore").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def _xml_field(text, tag):
    m = re.search(rf"<{tag}>\s*([^<]{{1,120}}?)\s*</{tag}>", text, re.I)
    return m.group(1) if m else ""


def _fetch_description(ip, location):
    """Lit la description UPnP. Regex plutôt qu'un parseur XML : le contenu vient d'un
    appareil non fiable (pas d'entités XML à craindre) et on ne suit que l'IP sondée."""
    try:
        u = urllib.parse.urlparse(location)
        if u.scheme != "http" or u.hostname != ip:
            return {}
        with urllib.request.urlopen(location, timeout=2) as r:
            text = r.read(65536).decode("utf-8", "ignore")
    except Exception:  # noqa: BLE001
        return {}
    return {"friendly": _xml_field(text, "friendlyName"),
            "manufacturer": _xml_field(text, "manufacturer"),
            "model": _xml_field(text, "modelName"),
            "dtype": _xml_field(text, "deviceType")}


def ssdp_scan(timeout=3.0, iface_ip=None):
    """Retourne {ip: {server, st:[...], friendly, manufacturer, model, dtype}}."""
    msg = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           b"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(0.5)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    if iface_ip:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
    found, locations = {}, {}
    try:
        for _ in range(2):
            s.sendto(msg, SSDP_ADDR)
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, (ip, _) = s.recvfrom(65535)
            except socket.timeout:
                continue
            h = _parse_ssdp(data)
            d = found.setdefault(ip, {"server": "", "st": []})
            d["server"] = d["server"] or h.get("server", "")
            if h.get("st") and h["st"] not in d["st"]:
                d["st"].append(h["st"])
            if h.get("location"):
                locations.setdefault(ip, h["location"])
    except OSError as e:
        log.warning("SSDP indisponible (multicast bloqué ?) : %s", e)
    finally:
        s.close()
    with ThreadPoolExecutor(8) as ex:
        for ip, desc in zip(locations, ex.map(lambda i: _fetch_description(i, locations[i]), locations)):
            found[ip].update(desc)
    return found


# ------------------------------------------------------------------ mDNS / Bonjour
def _dns_name(data, off):
    labels, end, hops = [], None, 0
    while True:
        if off >= len(data):
            raise ValueError("nom tronqué")
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            hops += 1
            if hops > 20:
                raise ValueError("boucle de compression")
            continue
        labels.append(data[off + 1: off + 1 + n].decode("utf-8", "ignore"))
        off += 1 + n
    return ".".join(labels), (end if end is not None else off)


def parse_dns(data):
    """Retourne une liste (nom, type, valeur) pour les enregistrements PTR/SRV/TXT."""
    out = []
    try:
        _, _, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        off = 12
        for _ in range(qd):
            _, off = _dns_name(data, off)
            off += 4
        for _ in range(an + ns + ar):
            name, off = _dns_name(data, off)
            t, _, _, rdlen = struct.unpack(">HHIH", data[off: off + 10])
            off += 10
            rd_off, off = off, off + rdlen
            if t == 12:
                out.append((name, "PTR", _dns_name(data, rd_off)[0]))
            elif t == 33:
                out.append((name, "SRV", _dns_name(data, rd_off + 6)[0]))
            elif t == 16:
                txt, i, rd = {}, 0, data[rd_off: rd_off + rdlen]
                while i < len(rd):
                    ln = rd[i]
                    kv = rd[i + 1: i + 1 + ln].decode("utf-8", "ignore")
                    k, _, v = kv.partition("=")
                    if k:
                        txt[k.lower()] = v
                    i += 1 + ln
                out.append((name, "TXT", txt))
    except (ValueError, struct.error, IndexError):
        pass
    return out


def _split_service(name):
    """'Salon._airplay._tcp.local' -> ('Salon', '_airplay._tcp')."""
    labels = name.split(".")
    for i, lab in enumerate(labels):
        if lab.startswith("_"):
            return ".".join(labels[:i]), ".".join(l for l in labels[i:] if l != "local")
    return name, ""


def collect_mdns(packets):
    """Agrège les réponses [(ip, bytes)] -> {ip: {services, names, txt, host}}."""
    info = {}
    for ip, data in packets:
        d = info.setdefault(ip, {"services": set(), "names": set(), "txt": {}, "host": ""})
        for name, kind, val in parse_dns(data):
            if kind == "PTR":
                if name.startswith("_services._dns-sd"):
                    d["services"].add(val.replace(".local", ""))
                else:
                    inst, svc = _split_service(val)
                    if svc:
                        d["services"].add(svc)
                    if inst:
                        d["names"].add(inst)
            elif kind == "SRV":
                inst, svc = _split_service(name)
                if svc:
                    d["services"].add(svc)
                if inst:
                    d["names"].add(inst)
                d["host"] = d["host"] or val.removesuffix(".local")
            elif kind == "TXT":
                for k, v in val.items():
                    d["txt"].setdefault(k, v)
    return {ip: d for ip, d in info.items() if d["services"] or d["host"] or d["names"]}


def _mdns_query(services):
    pkt = struct.pack(">HHHHHH", 0, 0, len(services), 0, 0, 0)
    for svc in services:
        for lab in (svc + ".local").split("."):
            pkt += bytes([len(lab)]) + lab.encode()
        pkt += b"\x00" + struct.pack(">HH", 12, 0x8001)  # PTR, classe IN + bit « réponse unicast »
    return pkt


def mdns_scan(timeout=4.0, iface_ip=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    if iface_ip:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
    packets = []
    try:
        for i in range(0, len(MDNS_SERVICES), 8):
            s.sendto(_mdns_query(MDNS_SERVICES[i: i + 8]), MDNS_ADDR)
        end = time.time() + timeout
        while time.time() < end:
            if select.select([s], [], [], 0.3)[0]:
                data, (ip, _) = s.recvfrom(9000)
                packets.append((ip, data))
    except OSError as e:
        log.warning("mDNS indisponible (multicast bloqué ?) : %s", e)
    finally:
        s.close()
    return collect_mdns(packets)


def scan_all(iface_ip=None, ssdp_timeout=3.5, mdns_timeout=4.0):
    """SSDP et mDNS en parallèle. Retourne (ssdp, mdns)."""
    with ThreadPoolExecutor(2) as ex:
        a = ex.submit(ssdp_scan, ssdp_timeout, iface_ip)
        b = ex.submit(mdns_scan, mdns_timeout, iface_ip)
        return a.result(), b.result()
