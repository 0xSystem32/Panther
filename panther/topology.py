"""Topologie : traceroute vers les autres réseaux et voisins LLDP/CDP (switch, port, VLAN).

L'écoute LLDP/CDP demande un socket brut : root ou la capacité `cap_net_raw`. Sans cela, Panther
l'indique clairement au lieu d'échouer en silence. Si `lldpd` est installé, on l'interroge à la place.
"""
import ipaddress
import json
import logging
import re
import select
import socket
import struct
import subprocess
import time
from typing import Any

log = logging.getLogger("panther.topology")
CDP_DST = bytes.fromhex("01000ccccccc")


# ------------------------------------------------------------------ traceroute
def parse_traceroute(text):
    """Sortie de `traceroute -n` -> liste d'IP (None pour un saut muet)."""
    hops = []
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if not m:
            continue
        ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", m.group(2))
        hops.append(ip.group(1) if ip else None)
    return hops


def traceroute(ip, max_hops=8):
    """Chemin vers `ip` (sans root). None si l'outil `traceroute` est absent."""
    try:
        out = subprocess.run(["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(max_hops), ip],
                             capture_output=True, text=True, timeout=max_hops * 2 + 3).stdout
    except FileNotFoundError:
        return None
    except subprocess.SubprocessError:
        return []
    return parse_traceroute(out)


# ------------------------------------------------------------------ LLDP / CDP
def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _text(b):
    return bytes(b).decode("utf-8", "ignore").strip("\x00 ")


def _id(subtype, b):
    return _mac(b) if subtype in (3, 4) and len(b) == 6 else _text(b)


def parse_lldp(p):
    n: dict[str, Any] = {"proto": "LLDP"}
    off = 0
    while off + 2 <= len(p):
        hdr = struct.unpack(">H", p[off: off + 2])[0]
        t, ln = hdr >> 9, hdr & 0x1FF
        v = p[off + 2: off + 2 + ln]
        off += 2 + ln
        if t == 0:
            break
        if t == 1 and v:
            n["chassis"] = _id(v[0], v[1:])
        elif t == 2 and v:
            n["port"] = _id(v[0], v[1:])
        elif t == 3 and len(v) >= 2:
            n["ttl"] = struct.unpack(">H", v[:2])[0]
        elif t == 4:
            n["port_desc"] = _text(v)
        elif t == 5:
            n["name"] = _text(v)
        elif t == 6:
            n["descr"] = _text(v)[:120]
        elif t == 8 and len(v) >= 7 and v[1] == 1 and v[0] >= 5:
            n["mgmt_ip"] = str(ipaddress.ip_address(bytes(v[2:6])))
        elif t == 127 and len(v) >= 4 and v[:3] == b"\x00\x80\xc2":
            if v[3] == 1 and len(v) >= 6:
                n["vlan"] = struct.unpack(">H", v[4:6])[0]
            elif v[3] == 3 and len(v) >= 7:
                n.setdefault("vlan_names", {})[struct.unpack(">H", v[4:6])[0]] = _text(v[7:7 + v[6]])
    return n


def parse_cdp(p):
    n: dict[str, Any] = {"proto": "CDP"}
    off = 4  # version, ttl, checksum
    while off + 4 <= len(p):
        t, ln = struct.unpack(">HH", p[off: off + 4])
        if ln < 4:
            break
        v = p[off + 4: off + ln]
        off += ln
        if t == 1:
            n["name"] = _text(v)
        elif t == 3:
            n["port"] = _text(v)
        elif t == 5:
            n["descr"] = _text(v).replace("\n", " ")[:120]
        elif t == 6:
            n["platform"] = _text(v)
        elif t == 10 and len(v) >= 2:
            n["vlan"] = struct.unpack(">H", v[:2])[0]
        elif t == 2 and len(v) >= 4:
            cnt, i = struct.unpack(">I", v[:4])[0], 4
            for _ in range(min(cnt, 8)):
                if i + 2 > len(v):
                    break
                ptype, plen = v[i], v[i + 1]
                proto = v[i + 2: i + 2 + plen]
                i += 2 + plen
                if i + 2 > len(v):
                    break
                alen = struct.unpack(">H", v[i: i + 2])[0]
                addr = v[i + 2: i + 2 + alen]
                i += 2 + alen
                if ptype == 1 and proto == b"\xcc" and alen == 4 and "mgmt_ip" not in n:
                    n["mgmt_ip"] = str(ipaddress.ip_address(bytes(addr)))
    return n


def parse_frame(frame):
    """Trame Ethernet brute -> dict voisin (avec 'src') ou None."""
    if len(frame) < 18:
        return None
    dst, src, et = frame[:6], frame[6:12], struct.unpack(">H", frame[12:14])[0]
    off = 14
    if et == 0x8100 and len(frame) >= 18:
        et, off = struct.unpack(">H", frame[16:18])[0], 18
    try:
        if et == 0x88CC:
            n = parse_lldp(frame[off:])
        elif dst == CDP_DST and et <= 1500 and frame[off: off + 8] == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00":
            n = parse_cdp(frame[off + 8:])
        else:
            return None
    except (struct.error, ValueError, IndexError):
        return None
    n["src"] = _mac(src)
    return n


def sniff_neighbors(iface, seconds=35):
    """Écoute LLDP/CDP. -> (statut, voisins). statut : ok | refusé | indisponible."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((iface, 0))
    except PermissionError:
        return "refusé", []
    except OSError:
        return "indisponible", []
    found, end = {}, time.time() + seconds
    try:
        while time.time() < end:
            if select.select([s], [], [], 0.5)[0]:
                n = parse_frame(s.recv(2048))
                if n:
                    found[(n["proto"], n["src"])] = n
                    if len(found) >= 16:
                        break
    finally:
        s.close()
    return "ok", list(found.values())


def lldpd_neighbors():
    """Voisins via le démon `lldpd` s'il est installé. None si absent."""
    try:
        out = subprocess.run(["lldpcli", "-f", "json", "show", "neighbors"], capture_output=True,
                             text=True, timeout=5).stdout
        data = json.loads(out).get("lldp", {}).get("interface", [])
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if isinstance(data, dict):
        data = [data]
    res = []
    for item in data:
        for ifname, d in item.items():
            chassis = d.get("chassis", {})
            name = next(iter(chassis), "") if isinstance(chassis, dict) and "id" not in chassis else ""
            res.append({"proto": "LLDP", "name": name, "port": (d.get("port", {}).get("id", {}) or {}).get("value", ""),
                        "local_port": ifname, "src": ""})
    return res


def discover_neighbors(iface, seconds=35):
    """-> {"status": ok|refusé|indisponible, "neighbors": [...]}."""
    via = lldpd_neighbors()
    if via is not None:
        return {"status": "ok", "neighbors": via}
    status, nb = sniff_neighbors(iface, seconds)
    if status != "ok":
        log.info("Écoute LLDP/CDP sur %s : %s (installer lldpd ou accorder cap_net_raw)", iface, status)
    return {"status": status, "neighbors": nb}
