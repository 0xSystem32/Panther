"""Moteur de scan réseau maison (stdlib uniquement, sans root).

Découverte : sondes TCP + table ARP du noyau. Enrichissement : DNS inverse,
NetBIOS, mDNS, scan de ports, bannières, TTL, empreinte OS, classification.
"""
import errno
import glob
import html
import ipaddress
import logging
import re
import selectors
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from . import certs, dhcp, discovery, fingerprint, models, networks, security, snmp, snmpv3, store, topology
from .i18n import tr

log = logging.getLogger("panther.scanner")
DISCOVERY_PORTS = (80, 443, 22, 445, 53, 8080, 62078, 5353, 139, 9100)
SCAN_PORTS = (21, 22, 23, 53, 80, 110, 135, 139, 143, 443, 445, 515, 554, 631, 993,
              1900, 3306, 3389, 5000, 5001, 5432, 5555, 6379, 8008, 8009, 8060,
              8080, 8443, 9100, 62078)
QUICK_PORTS = (22, 53, 80, 135, 139, 443, 445, 554, 631, 8009, 9100, 62078)
DEEP_PORTS = SCAN_PORTS + (25, 111, 389, 873, 1433, 1883, 2049, 3000, 5060, 5900, 7547, 8000, 8081,
                           8883, 8888, 9000, 10000, 32400, 34567, 37777)
# Profondeur du scan : rapide (quelques secondes), normal, approfondi (plus lent, plus complet)
PROFILES: dict[str, dict[str, Any]] = {
    "rapide": dict(light=False, arp_rounds=1, arp_wait=1.2, arp_max=2.5, disc_ports=(80, 443, 22, 445, 62078), disc_timeout=0.3, routed_timeout=0.5, second_pass=False,
                   second_timeout=0, scan_ports=QUICK_PORTS, port_timeout=0.6, banners=False, names_timeout=1.0,
                   ssdp=2.0, mdns=2.0, lldp=10),
    "normal": dict(light=False, arp_rounds=2, arp_wait=1.2, arp_max=7.0, disc_ports=DISCOVERY_PORTS, disc_timeout=0.4, routed_timeout=0.7, second_pass=True,
                   second_timeout=1.0, scan_ports=SCAN_PORTS, port_timeout=1.0, banners=True, names_timeout=1.5,
                   ssdp=3.5, mdns=4.0, lldp=30),
    "approfondi": dict(light=False, arp_rounds=3, arp_wait=2.0, arp_max=9.0, disc_ports=DISCOVERY_PORTS + (21, 23, 135, 554, 631, 3389, 5000, 8009), disc_timeout=0.8,
                       routed_timeout=1.2, second_pass=True, second_timeout=2.0, scan_ports=DEEP_PORTS,
                       port_timeout=1.5, banners=True, names_timeout=2.5, ssdp=6.0, mdns=7.0, lldp=45),
}
# Scan de présence : qui est là ? (ARP uniquement) ; les détails des appareils déjà connus sont repris du dernier scan complet
PROFILES["presence"] = dict(light=True, arp_rounds=1, arp_wait=1.2, arp_max=7.0, disc_ports=(80, 443, 22, 445, 62078), disc_timeout=0.3,
                            routed_timeout=0.5, second_pass=False, second_timeout=0, scan_ports=(), port_timeout=0.6, banners=False,
                            names_timeout=1.0, ssdp=0, mdns=0, lldp=0)
# Écoute seule : aucune sonde envoyée (ni ARP forcé, ni TCP, ni SSDP/mDNS, ni noms, ni SNMP, ni traceroute). On lit seulement ce que le
# noyau sait déjà (table des voisins), les baux DHCP locaux et le dernier scan complet.
PROFILES["ecoute"] = dict(light=True, passive=True, arp_rounds=0, arp_wait=0, arp_max=0, disc_ports=(), disc_timeout=0, routed_timeout=0,
                          second_pass=False, second_timeout=0, scan_ports=(), port_timeout=0, banners=False, names_timeout=0,
                          ssdp=0, mdns=0, lldp=0)
PORT_NAMES = {2323: "Telnet-alt", 2375: "Docker", 5984: "CouchDB", 8554: "RTSP-alt", 9200: "Elasticsearch",
              11211: "Memcached", 27017: "MongoDB", 25: "SMTP", 111: "RPC", 389: "LDAP", 873: "rsync", 1433: "MSSQL", 1883: "MQTT", 2049: "NFS",
              3000: "HTTP-dev", 5060: "SIP", 5900: "VNC", 7547: "TR-069", 8000: "HTTP-alt", 8081: "HTTP-alt",
              8883: "MQTTS", 8888: "HTTP-alt", 9000: "HTTP-alt", 10000: "Webmin", 32400: "Plex",
              34567: "DVR", 37777: "Dahua", 21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 110: "POP3",
              135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
              515: "LPD", 554: "RTSP", 631: "IPP", 993: "IMAPS", 1900: "UPnP",
              3306: "MySQL", 3389: "RDP", 5000: "Synology/UPnP", 5432: "PostgreSQL",
              5555: "ADB", 6379: "Redis", 8008: "Cast", 8009: "Cast", 8060: "Roku",
              8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "JetDirect", 62078: "iOS sync"}


def local_network(iface=None):
    """Interface, IP, réseau et passerelle. Sans `iface` : celle de la route par défaut."""
    if not sys.platform.startswith("linux"):
        raise RuntimeError(tr("Le scan réseau n'est géré que sous Linux pour le moment (le mode --demo fonctionne partout)."))
    if iface is None:
        m = re.search(r"default via (\S+) dev (\S+)", networks._run(["ip", "-4", "route", "show", "default"]))
        if not m:
            raise RuntimeError(tr("Aucune route par défaut : êtes-vous connecté à un réseau ?"))
        gw, dev = m.groups()
    else:
        dev = iface
        m = re.search(r"default via (\S+)", networks._run(["ip", "-4", "route", "show", "default", "dev", dev]))
        gw = m.group(1) if m else ""  # une interface secondaire n'a pas forcément de passerelle
    m = re.search(r"inet (\S+)", networks._run(["ip", "-4", "-o", "addr", "show", "dev", dev]))
    if not m:
        raise RuntimeError(tr("L'interface {dev} n'a pas d'adresse IPv4 : choisissez-en une autre.", dev=dev))
    itf = ipaddress.ip_interface(m.group(1))
    net = itf.network
    if net.prefixlen < 24:  # on borne à un /24 pour garder un scan rapide
        net = ipaddress.ip_network(f"{itf.ip}/24", strict=False)
    return {"iface": dev, "ip": str(itf.ip), "cidr": str(net), "gateway": gw, "kind": networks.link_kind(dev)}


def read_arp():
    table = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 4 and p[2] == "0x2" and p[3] != "00:00:00:00:00:00":
                    table[p[0]] = p[3].lower()
    except OSError:
        log.debug("Table ARP illisible", exc_info=True)
    return table


_NEIGH_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)(?: dev \S+)?(?: lladdr (\S+))?(?: router)?(?: proxy)?\s+([A-Z]+)\s*$")


def arp_neighbors(iface):
    """Voisins connus du noyau : {ip: (mac, état)}. États : REACHABLE (confirmé), STALE/DELAY/PROBE (à revérifier),
    INCOMPLETE/FAILED (n'a pas répondu)."""
    out = {}
    for line in networks._run(["ip", "-4", "neigh", "show", "dev", iface]).splitlines():
        m = _NEIGH_RE.match(line.strip())
        if m:
            out[m.group(1)] = ((m.group(2) or "").lower(), m.group(3))
    return out


def arp_discover(iface, hosts, profile, cancel, progress=None, sleep=time.sleep, neighbors=None, clock=time.time):
    """Découverte du réseau local par ARP : un paquet UDP anodin par adresse force le noyau à résoudre l'ARP ;
    tout appareil allumé répond à l'ARP, même s'il filtre le TCP. Les entrées anciennes (STALE) sont revérifiées
    par le noyau lui-même : on attend leur confirmation plutôt que de croire un cache périmé.
    -> (vivants {ip: mac}, incertains [ip], ok). `ok` est faux si `ip neigh` est inutilisable (repli sur le TCP)."""
    neighbors = neighbors or (lambda: arp_neighbors(iface))
    hostset, alive, pending, seen_any, last = set(hosts), {}, list(hosts), False, {}
    for rnd in range(profile["arp_rounds"]):
        if cancel.is_set() or not pending:
            break
        for ip in pending:
            udp_nudge(ip)
        start = clock()
        while not cancel.is_set():
            sleep(0.25)
            last = {ip: v for ip, v in neighbors().items() if ip in hostset}
            seen_any = seen_any or bool(last)
            alive.update({ip: mac for ip, (mac, st) in last.items() if st == "REACHABLE"})
            elapsed = clock() - start
            transitioning = any(st in ("DELAY", "PROBE") and ip not in alive for ip, (_m, st) in last.items())
            # on attend au moins `arp_wait` s, puis tant que le noyau revérifie des entrées anciennes (borné par `arp_max`)
            if elapsed >= profile["arp_wait"] and (not transitioning or elapsed >= profile["arp_max"]):
                break
        if progress:
            progress(int(55 * (rnd + 1) / max(profile["arp_rounds"], 1)))
        pending = [h for h in hosts if h not in alive]
    maybes = [ip for ip, (_m, st) in last.items() if ip not in alive and st in ("STALE", "DELAY", "PROBE")]
    return alive, maybes, seen_any


_NEIGH6 = re.compile(r"^([0-9a-fA-F:]+)(?: dev \S+)?(?: lladdr (\S+))?(?: router)?(?: proxy)?\s+([A-Z]+)\s*$")


def parse_ipv6_neighbors(text, limit=4):
    """Sortie de `ip -6 neigh show` -> {mac: [adresses IPv6]} (globales d'abord, 4 au plus par appareil). Les entrées sans réponse
    (FAILED, INCOMPLETE), sans MAC ou multicast sont ignorées ; le texte vient d'une commande locale mais reste borné et validé."""
    out: dict = {}
    for line in text.splitlines()[:2000]:
        m = _NEIGH6.match(line.strip())
        if not m or not m.group(2) or m.group(3) in ("FAILED", "INCOMPLETE"):
            continue
        try:
            addr = ipaddress.IPv6Address(m.group(1))
        except ValueError:
            continue
        if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
            continue
        out.setdefault(m.group(2).lower(), []).append(str(addr))
    return {mac: sorted(set(a), key=lambda x: (x.startswith("fe80"), x))[:limit] for mac, a in out.items()}


def ipv6_neighbors(iface):
    """Voisins IPv6 connus du noyau : {mac: [adresses]}. Lecture seule."""
    return parse_ipv6_neighbors(networks._run(["ip", "-6", "neigh", "show", "dev", iface]))


def ipv6_nudge(iface, timeout=3):
    """Un seul ping vers « tous les nœuds » (ff02::1) : les appareils IPv6 répondent et entrent dans la table des voisins du noyau."""
    try:
        subprocess.run(["ping", "-6", "-c1", "-W1", f"ff02::1%{iface}"], capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        log.debug("Ping IPv6 multicast impossible", exc_info=True)


def tcp_open(ip, port, timeout=0.6):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        r = s.connect_ex((ip, port))
        return r == 0, r == 111  # (ouvert, refusé => hôte vivant)
    except OSError:
        return False, False
    finally:
        s.close()


def udp_nudge(ip):
    """Paquets UDP anodins : obligent le noyau à résoudre l'ARP même si TCP est filtré."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for port in (137, 5353, 1900):
            s.sendto(b"\x00", (ip, port))
    except OSError:
        pass
    finally:
        s.close()


def probe_alive(ip, timeout=0.4, ports=DISCOVERY_PORTS):
    """Hôte vivant ? Tous les ports sont sondés EN MÊME TEMPS : un hôte muet coûte un délai, pas un délai par port
    (254 adresses d'un VLAN routé : ~15 s au lieu de plus de 2 minutes)."""
    udp_nudge(ip)
    pending = {}
    sel = selectors.DefaultSelector()
    try:
        for p in ports:
            s = socket.socket()
            s.setblocking(False)
            try:
                r = s.connect_ex((ip, p))
            except OSError:
                s.close()
                continue
            if r in (0, errno.ECONNREFUSED):
                s.close()
                return True
            if r not in (errno.EINPROGRESS, errno.EWOULDBLOCK):
                s.close()
                continue
            sel.register(s, selectors.EVENT_WRITE, s)
            pending[s] = p
        deadline = time.monotonic() + timeout
        while pending:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            for key, _ in sel.select(left):
                sock = key.data
                if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) in (0, errno.ECONNREFUSED):
                    return True
                sel.unregister(sock)
                sock.close()
                del pending[sock]
        return False
    finally:
        for s in pending:
            s.close()
        sel.close()


def scan_ports(ip, ports, timeout):
    """Ports TCP ouverts, sondés en parallèle (douze à la fois par appareil)."""
    if not ports:
        return []
    with ThreadPoolExecutor(min(12, len(ports))) as ex:
        res = list(ex.map(lambda p: tcp_open(ip, p, timeout)[0], ports))
    return [p for p, ok in zip(ports, res) if ok]


_rtt_cache: dict = {}  # ip -> latence (ms) lue par ping_ttl ; consommée par _inspect (même schéma que _nb_info)
_rtt_lock = threading.Lock()


def ping_ttl(ip):
    """TTL de la réponse à un ping ; la latence (ms) du même ping est gardée pour `_inspect` (aucune sonde de plus)."""
    try:
        out = subprocess.run(["ping", "-c1", "-W1", ip], capture_output=True,
                             text=True, timeout=3).stdout
        t = re.search(r"time[=<]([\d.]+)\s*ms", out, re.I)
        if t:
            with _rtt_lock:
                _rtt_cache[ip] = float(t.group(1))
        m = re.search(r"ttl=(\d+)", out, re.I)
        return int(m.group(1)) if m else None
    except Exception:
        return None


_nb_info: dict = {}
_nb_lock = threading.Lock()


def parse_nbstat(data):
    """Réponse NBSTAT -> {name, workgroup, file_server}. Bornes vérifiées : la réponse vient d'un appareil non fiable."""
    if len(data) < 57:
        return {}
    count = data[56]
    names, off = [], 57
    for _ in range(min(count, 32)):
        entry = data[off:off + 18]
        if len(entry) < 18:
            break
        text = entry[:15].decode("ascii", "ignore").strip()
        names.append((text, entry[15], bool(entry[16] & 0x80)))  # (nom, suffixe, groupe ?)
        off += 18
    uniq = [n for n, suf, grp in names if suf == 0x00 and not grp and n]
    group = [n for n, suf, grp in names if suf == 0x00 and grp and n]
    return {"name": uniq[0] if uniq else "", "workgroup": group[0] if group else "", "file_server": any(suf == 0x20 for _n, suf, _g in names)}


def netbios_name(ip):
    """Nom NetBIOS de l'appareil ; le groupe de travail et le rôle « serveur de fichiers » sont gardés dans `_nb_info`."""
    pkt = (b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.8)
    try:
        s.sendto(pkt, (ip, 137))
        info = parse_nbstat(s.recv(1024))
        if info:
            with _nb_lock:
                _nb_info[ip] = info
            return info["name"]
    except OSError:
        pass
    finally:
        s.close()
    return ""


def mdns_name(ip):
    """Requête PTR mDNS unicast sur <ip>.in-addr.arpa."""
    name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"
    pkt = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + q + struct.pack(">HH", 12, 0x8001)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.8)
    try:
        s.sendto(pkt, (ip, 5353))
        data = s.recv(2048)
        m = re.findall(rb"([\w\-]{2,40})\x05local", data)
        if m:
            return m[-1].decode("ascii", "ignore")
    except OSError:
        pass
    finally:
        s.close()
    return ""


def _dns_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except OSError:
        return ""


def resolve_names(ip, timeout=1.5):
    """DNS inverse, NetBIOS et mDNS en parallèle, plafonnés : un appareil muet coûte `timeout` secondes au total
    (avant, les trois requêtes s'additionnaient et le DNS inverse pouvait durer bien plus).
    -> (dns, netbios, mdns). Une résolution trop lente est abandonnée (son thread se termine seul)."""
    out = {}

    def task(key, fn):
        try:
            out[key] = fn(ip) or ""
        except Exception:
            out[key] = ""
    threads = [threading.Thread(target=task, args=(k, f), daemon=True)
               for k, f in (("dns", _dns_name), ("nb", netbios_name), ("mdns", mdns_name))]
    for t in threads:
        t.start()
    end = time.time() + timeout
    for t in threads:
        t.join(max(0.0, end - time.time()))
    return out.get("dns", ""), out.get("nb", ""), out.get("mdns", "")


_cert_cache: dict = {}  # (ip, port) -> résumé du certificat lu par grab_banner ; consommé par _inspect (même schéma que _nb_info)
_cert_lock = threading.Lock()
HTTP_PORTS = (80, 8000, 8008, 8080, 8081, 5000)
TLS_PORTS = (443, 5001, 8443)
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(text, limit=100):
    """Texte venu du réseau : sans caractères de contrôle, entités HTML décodées, longueur bornée."""
    return _CTRL.sub(" ", html.unescape(text)).strip()[:limit]


def http_summary(head, body):
    """« Serveur | titre de la page | realm » à partir d'une réponse HTTP (texte non fiable, jamais interprété)."""
    server = re.search(r"^Server:[ \t]*(.+)$", head, re.I | re.M)
    realm = re.search(r'^WWW-Authenticate:[^\r\n]*?realm="?([^"\r\n]+)', head, re.I | re.M)  # souvent le modèle exact (caméra, routeur)
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    parts = [_clean(m.group(1), 60) for m in (server, title) if m] + ([_clean("realm " + realm.group(1), 60)] if realm else [])
    return " | ".join(p for p in parts if p)


def tls_certificate_in(stream):
    """Premier certificat (DER) d'un message Certificate TLS ≤ 1.2 contenu dans `stream` (octets reçus du serveur), ou None s'il n'est pas
    (encore) complet. Analyse bornée : les octets viennent d'un appareil non fiable."""
    hs, o = b"", 0
    while o + 5 <= len(stream) and len(hs) < 65536:        # enregistrements : type, version, longueur
        rtype, rlen = stream[o], int.from_bytes(stream[o + 3:o + 5], "big")
        if o + 5 + rlen > len(stream):
            break
        if rtype == 22:                                    # handshake
            hs += stream[o + 5:o + 5 + rlen]
        o += 5 + rlen
    p = 0
    while p + 4 <= len(hs):
        mtype, mlen = hs[p], int.from_bytes(hs[p + 1:p + 4], "big")
        body = hs[p + 4:p + 4 + mlen]
        if mtype == 11 and len(body) == mlen and len(body) >= 6:
            clen = int.from_bytes(body[3:6], "big")
            return bytes(body[6:6 + clen]) if 0 < clen <= len(body) - 6 else None
        p += 4 + mlen
    return None


def peek_certificate(ip, port, timeout=1.5):
    """Certificat présenté par un serveur TLS, lu dans sa première réponse SANS terminer la poignée de main. Utile aux appareils qui exigent
    un certificat client (ex. décodeurs d'opérateur) : ils coupent la connexion après avoir envoyé le leur, et la lecture normale échoue.
    Limité à TLS 1.2 (en 1.3 le certificat est chiffré). Rien n'est envoyé hormis le message d'ouverture. -> DER ou None."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing)
    got = b""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            end = time.time() + timeout
            while len(got) < 65536 and time.time() < end:
                try:
                    tls.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLError:
                    return tls_certificate_in(got)
                data = outgoing.read()
                if data:
                    s.sendall(data)
                chunk = s.recv(16384)
                if not chunk:
                    break
                got += chunk
                cert = tls_certificate_in(got)
                if cert:
                    return cert
                incoming.write(chunk)
    except (OSError, ValueError):
        return tls_certificate_in(got) if got else None
    return tls_certificate_in(got)


def grab_banner(ip, port, timeout=1.5):
    """Bannière d'un service : première ligne (SSH, FTP) ou résumé HTTP/HTTPS. Aucune authentification n'est tentée.
    Le certificat HTTPS n'est volontairement pas vérifié : les appareils du réseau local sont presque toujours auto-signés
    et on ne fait que lire leur page d'accueil."""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            try:
                s = ctx.wrap_socket(s)
            except OSError:  # poignée de main refusée (certificat client exigé…) : le certificat du serveur a pourtant pu être envoyé
                der = peek_certificate(ip, port, timeout)
                info = certs.summary(certs.parse_cert(der)) if der else {}
                if info:
                    with _cert_lock:
                        _cert_cache[(ip, port)] = info
                return ""
            try:  # certificat présenté, même non vérifié : sert d'indice (marque, modèle) et de contrôle d'expiration
                info = certs.summary(certs.parse_cert(s.getpeercert(binary_form=True) or b""))
            except (ValueError, OSError):
                info = {}
            if info:
                with _cert_lock:
                    _cert_cache[(ip, port)] = info
        web = port in HTTP_PORTS or port in TLS_PORTS
        if web:
            s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Panther\r\nAccept: text/html\r\n\r\n".encode())
        data, end = b"", time.time() + timeout
        while len(data) < 8192 and time.time() < end:  # la page arrive souvent en plusieurs morceaux
            try:
                chunk = s.recv(2048)
            except TimeoutError:
                break
            if not chunk:
                break
            data += chunk
            if not web:
                break
        text = data.decode("latin-1", "ignore")
        if not web:
            return _clean(text.strip().splitlines()[0]) if text.strip() else ""
        head, _, body = text.partition("\r\n\r\n")
        return http_summary(head, body)
    except OSError:  # inclut ssl.SSLError et les délais dépassés
        return ""
    finally:
        s.close()


def reclassify(dev, overrides=None, aliases=None):
    """Recalcule le type d'un appareil déjà analysé (après un changement de règles), en gardant les réglages manuels."""
    store.apply(dev, {})  # retour aux valeurs automatiques
    dev["type"], dev["confidence"], dev["reasons"] = fingerprint.classify_detail(dev)
    store.apply(dev, store.load() if overrides is None else overrides, aliases)
    return dev


class Scanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.profile = PROFILES["normal"]
        self.security = False
        self.iface = None
        self.known = {}
        self.aliases = {}
        self.own: dict = {}  # adresses de cette machine sur les interfaces rattachées (VLAN…) : ip -> interface
        self.reset()

    def reset(self):
        self.state: dict[str, Any] = {"status": "idle", "progress": 0, "network": None,
                      "devices": {}, "networks": [], "neighbors": [], "neighbors_status": "", "paths": {},
                      "warnings": [], "snmp": [], "depth": "normal", "security": False, "started": None, "finished": None, "error": None}

    def snapshot(self):
        with self.lock:
            s = dict(self.state)
            s["devices"] = list(self.state["devices"].values())
            return s

    def start(self, targets=None, snmp_sources=None, depth="normal", security=False, iface=None, known=None, aliases=None):
        """Lance un scan : réseau local + éventuelles plages supplémentaires (VLAN, sous-réseaux routés)."""
        with self.lock:
            if self.state["status"] == "scanning":
                return False
            self.reset()
            self.state["status"] = "scanning"
            self.state["started"] = time.time()
            self.state["depth"] = depth if depth in PROFILES else "normal"
            self.state["security"] = self.security = bool(security) and self.state["depth"] != "ecoute"  # l'écoute seule n'envoie rien
            self.iface = iface or None
            self.known = dict(known or {})
            self.aliases = dict(aliases or {})
            self.cancel = threading.Event()
            self.profile = PROFILES[self.state["depth"]]
        threading.Thread(target=self._run, args=(list(targets or []), list(snmp_sources or [])), daemon=True).start()
        return True

    def stop(self):
        """Demande l'arrêt : les appareils déjà trouvés sont conservés (statut « stopped »)."""
        with self.lock:
            if self.state["status"] != "scanning":
                return False
            self.cancel.set()
            return True

    def _set(self, **kw):
        with self.lock:
            self.state.update(kw)

    def _run(self, targets, snmp_sources):
        try:
            self.overrides = store.load()
            net = local_network(self.iface)
            net["vlan"] = networks.vlan_ids().get(net["iface"])
            local = ipaddress.ip_network(net["cidr"])
            extra_nets: list = []
            early_warnings: list = []
            for t in ([] if self.profile.get("passive") else targets):  # écoute seule : pas de plages routées (il faudrait les sonder)
                try:
                    n = networks.validate_cidr(t)  # refuse les plages publiques ou trop grandes
                except ValueError as e:
                    early_warnings.append(tr("Plage ignorée : {e}", e=e))
                    continue
                if not n.overlaps(local) and all(not n.overlaps(e) for e in extra_nets):
                    extra_nets.append(n)
            all_nets = [local] + extra_nets
            attached = self._attached(extra_nets, net["iface"])  # plages portées par une autre interface (VLAN étiqueté…) : ARP possible
            self.own = {a["ip"]: a["iface"] for a in attached.values()}
            hosts = [str(h) for n in all_nets for h in (n.hosts() if n.num_addresses > 2 else n)]
            if len(hosts) > 2 * networks.MAX_HOSTS:
                raise RuntimeError(tr("Trop d'adresses à scanner ({hosts_count}) : réduisez les plages.", hosts_count=len(hosts)))
            self._set(network=net, networks=[
                {"cidr": str(local), "kind": "local", "vlan": net["vlan"]}]
                + [{"cidr": str(n), "kind": "interface", "vlan": attached[str(n)]["vlan"]} if str(n) in attached
                   else {"cidr": str(n), "kind": "routé", "vlan": None} for n in extra_nets])

            nb = {}
            P = self.profile
            lldp = threading.Thread(target=lambda: nb.update(topology.discover_neighbors(net["iface"], P["lldp"])), daemon=True)
            if P["lldp"]:
                lldp.start()  # écoute LLDP/CDP en parallèle du scan (pas en mode présence)

            def net_of(ip):
                a = ipaddress.ip_address(ip)
                return next((str(n) for n in all_nets if a in n), str(local))

            found, done = set(), [0]
            local_hosts = [h for h in hosts if ipaddress.ip_address(h) in local]
            on_link = {h for h in hosts if any(ipaddress.ip_address(h) in ipaddress.ip_network(c) for c in attached)}
            routed_hosts = [h for h in hosts if h not in set(local_hosts) and h not in on_link]
            arp = {}

            def tcp_pass(pool, timeout_of, patient):
                """Découverte par connexions TCP : réseaux routés (pas d'ARP) ou repli si `ip neigh` est inutilisable."""
                def disc(ip):
                    if self.cancel.is_set():
                        return
                    if ip == net["ip"] or ip in self.own or probe_alive(ip, timeout_of(ip), P["disc_ports"]):
                        found.add(ip)
                    done[0] += 1
                    self._set(progress=int(done[0] / max(len(hosts), 1) * 55))
                with ThreadPoolExecutor(96) as ex:
                    list(ex.map(disc, pool))
                silent = [h for h in pool if h not in found] if patient and P["second_pass"] and not self.cancel.is_set() else []
                with ThreadPoolExecutor(48) as ex:
                    for ip, ok in zip(silent, ex.map(lambda i: not self.cancel.is_set() and probe_alive(
                            i, P["second_timeout"], P["disc_ports"]), silent)):
                        if ok:
                            found.add(ip)

            if P.get("passive"):
                alive, maybes, arp_ok = {}, [], True  # on ne provoque rien : seule la table du noyau compte (lue plus bas)
                self._set(progress=55)
            else:
                alive, maybes, arp_ok = arp_discover(net["iface"], local_hosts, P, self.cancel, lambda p: self._set(progress=p))
            if arp_ok:
                arp.update(alive)
                found |= set(alive)
                # entrées anciennes jamais confirmées dans le délai : une sonde TCP rapide tranche
                with ThreadPoolExecutor(32) as ex:
                    for ip, ok in zip(maybes, ex.map(lambda i: not self.cancel.is_set() and probe_alive(
                            i, P["disc_timeout"], P["disc_ports"]), maybes)):
                        if ok:
                            found.add(ip)
            else:
                tcp_pass(local_hosts, lambda ip: P["disc_timeout"], patient=True)
            if attached and not P.get("passive"):
                self._discover_attached(attached, on_link, arp, found, tcp_pass)
            if routed_hosts:
                tcp_pass(routed_hosts, lambda ip: P["routed_timeout"], patient=True)
            time.sleep(0.2)
            arp.update({ip: mac for ip, mac in read_arp().items() if ip not in arp})
            for ip in arp:  # hôtes vus en ARP même si rien d'autre n'a répondu
                if ipaddress.ip_address(ip) in local:
                    found.add(ip)
            found.add(net["ip"])
            found |= set(self.own)
            self._set(progress=62)
            snmp_arp, fdb, warnings, snmp_info = ({}, {}, [], []) if P.get("passive") else self._read_snmp(snmp_sources, all_nets, found)
            warnings = early_warnings + warnings
            # en mode présence, SSDP/mDNS ne servent que s'il y a un appareil inconnu à identifier
            unknown_local = [ip for ip in found if ip != net["ip"] and self.aliases.get(arp.get(ip, ""), arp.get(ip, "")) not in self.known and ipaddress.ip_address(ip) in local]
            if self.cancel.is_set() or P.get("passive") or (P["light"] and not unknown_local):
                ssdp: dict = {}
                mdns: dict = {}
                wsd: dict = {}
            else:
                full = PROFILES["normal"] if P["light"] else P
                res = discovery.scan_all(net["ip"], full["ssdp"], full["mdns"])  # multicast : réseau local
                ssdp, mdns, wsd = res[0], res[1], (res[2] if len(res) > 2 else {})
            for ip in list(ssdp) + list(mdns) + list(wsd):  # hôtes qui filtrent TCP mais annoncent des services
                try:
                    if ipaddress.ip_address(ip) in local:
                        found.add(ip)
                except ValueError:
                    pass
            if not P["light"]:
                ipv6_nudge(net["iface"])  # scan complet : un ping multicast fait connaître les adresses IPv6 des appareils
            extra = {"ssdp": ssdp, "mdns": mdns, "wsd": wsd, "snmp_arp": snmp_arp, "leases": dhcp.read_leases(),
                     "ipv6": ipv6_neighbors(net["iface"])}
            ips = sorted(found, key=lambda i: ipaddress.ip_address(i))
            routed_nets = [n_ for n_ in extra_nets if str(n_) not in attached]
            paths = {} if P.get("passive") else self._trace_paths(routed_nets, found)
            for n_ in extra_nets:
                if not any(ipaddress.ip_address(i) in n_ for i in found):
                    hint = tr(" Dernier saut atteint : {hop}.", hop=[h for h in paths.get(str(n_), []) if h][-1]) if any(paths.get(str(n_), [])) else ""
                    warnings.append(tr("Réseau {n} : aucun hôte n'a répondu (routage entre VLAN ou pare-feu ?).{hint}", n=n_, hint=hint))
            n = [0]

            def enrich(ip):
                if self.cancel.is_set():
                    return
                try:
                    dev = self._inspect(ip, net, arp, extra)
                except Exception as e:
                    log.warning("Analyse de %s impossible", ip, exc_info=True)
                    warnings.append(tr("Analyse de {ip} impossible : {e}", ip=ip, e=e))
                    n[0] += 1
                    return
                dev["network"] = net_of(ip)
                dev["vlan"] = net["vlan"] if dev["network"] == str(local) else attached.get(dev["network"], {}).get("vlan")
                dev["path"] = paths.get(dev["network"], [])
                f = fdb.get(dev["mac"])
                if f:  # position dans le switch (lue par SNMP)
                    dev["switch"], dev["switch_port"] = f.get("switch", ""), f["port"]
                    dev["vlan"] = f["vlan"] or dev["vlan"]
                with self.lock:
                    self.state["devices"][ip] = dev
                n[0] += 1
                self._set(progress=65 + int(n[0] / len(ips) * 35))

            with ThreadPoolExecutor(16) as ex:
                list(ex.map(enrich, ips))
            if self.cancel.is_set():
                self._set(status="stopped", progress=100, finished=time.time(), warnings=warnings, paths=paths)
                return
            if P["lldp"]:
                lldp.join(timeout=P["lldp"] + 5)
            self._apply_switch_hints(list(self.state["devices"].values()), snmp_info, nb.get("neighbors", []))
            self._set(status="done", progress=100, finished=time.time(), paths=paths, warnings=warnings,
                      snmp=snmp_info, neighbors=nb.get("neighbors", []), neighbors_status=nb.get("status", ""))
        except Exception as e:
            log.exception("Le scan a échoué")
            self._set(status="error", error=str(e))

    @staticmethod
    def _attached(extra_nets, main_iface):
        """Plages supplémentaires que cette machine porte déjà sur une autre interface : {cidr: {iface, ip, vlan}}."""
        by_cidr = {it["cidr"]: it for it in networks.interfaces() if it["iface"] != main_iface}
        vlans = networks.vlan_ids()
        return {str(n): {"iface": by_cidr[str(n)]["iface"], "ip": by_cidr[str(n)]["ip"], "vlan": vlans.get(by_cidr[str(n)]["iface"])}
                for n in extra_nets if str(n) in by_cidr}

    def _discover_attached(self, attached, hosts, arp, found, tcp_pass):
        """Découverte par ARP sur chaque interface rattachée (adresses MAC, donc constructeur et type), en parallèle."""
        P = self.profile

        def one(item):
            cidr, at = item
            net_ = ipaddress.ip_network(cidr)
            pool = [h for h in hosts if ipaddress.ip_address(h) in net_]
            alive, maybes, ok = arp_discover(at["iface"], pool, P, self.cancel)
            return pool, alive, maybes, ok
        with ThreadPoolExecutor(len(attached)) as ex:
            results = list(ex.map(one, attached.items()))
        for pool, alive, maybes, ok in results:
            if ok:
                arp.update(alive)
                found.update(alive)
                with ThreadPoolExecutor(32) as ex:
                    for ip, up in zip(maybes, ex.map(lambda i: not self.cancel.is_set() and probe_alive(i, P["disc_timeout"], P["disc_ports"]), maybes)):
                        if up:
                            found.add(ip)
            else:
                tcp_pass(pool, lambda ip: P["routed_timeout"], patient=True)

    def _read_snmp(self, sources, all_nets, found):
        """Interroge les routeurs/switchs désignés par l'utilisateur. Retourne ARP, FDB, avertissements."""
        arp: dict = {}
        fdb: dict = {}
        warnings: list = []
        info: list = []
        for src in sources:
            host = src.get("host", "")
            try:
                if not ipaddress.ip_address(host).is_private:
                    raise ValueError(tr("adresse non privée"))
                comm = snmpv3.credential(src)  # communauté v2c ou utilisateur v3
                t = snmp.read_tables(host, comm, port=src.get("port", 161))
            except (snmp.SnmpError, ValueError, OSError) as e:
                log.warning("SNMP %s : %s", host, e)
                warnings.append(tr("SNMP {host} : {e}", host=host, e=e))
                continue
            info.append({"host": host, "name": t["name"], "arp": len(t["arp"]), "fdb": len(t["fdb"])})
            for ip, mac in t["arp"].items():
                arp.setdefault(ip, mac)
                if any(ipaddress.ip_address(ip) in n for n in all_nets):
                    found.add(ip)  # hôte vu par le routeur, même s'il filtre nos sondes
            for mac, f in t["fdb"].items():
                fdb.setdefault(mac, {**f, "switch": t["name"] or host})
        return arp, fdb, warnings, info

    def _apply_switch_hints(self, devices, snmp_info, neighbors):
        """Un équipement dont on a lu la table de ports (SNMP) ou qui annonce LLDP/CDP est un switch."""
        hosts = {i["host"] for i in snmp_info if i.get("fdb")} | {n["mgmt_ip"] for n in neighbors if n.get("mgmt_ip")}
        for d in devices:
            if d["ip"] in hosts and not d.get("is_self") and not d.get("is_switch"):
                d["is_switch"] = True
                store.apply(d, {})  # revient aux valeurs automatiques avant de reclasser
                d["type"], d["confidence"], d["reasons"] = fingerprint.classify_detail(d)
                store.apply(d, self.overrides, self.aliases)

    def _trace_paths(self, extra_nets, found):
        """Chemin (routeurs traversés) vers chaque réseau supplémentaire."""
        def trace(n):
            alive = sorted((i for i in found if ipaddress.ip_address(i) in n), key=ipaddress.ip_address)
            target = alive[0] if alive else str(next(iter(n.hosts()), n.network_address))
            return str(n), topology.traceroute(target) or []
        if not extra_nets:
            return {}
        with ThreadPoolExecutor(4) as ex:
            return dict(ex.map(trace, extra_nets))

    def _known_device(self, ip, net, mac, rec):
        """Appareil déjà connu, vu par ARP : ses détails viennent du dernier scan complet (rien n'est renvoyé sur le réseau)."""
        ports = list(rec.get("ports") or [])
        dev = {"ip": ip, "mac": mac, "vendor": rec.get("vendor", ""), "hostname": rec.get("name", ""), "ports": ports,
               "services": [PORT_NAMES.get(p, str(p)) for p in ports], "banners": {}, "ttl": None,
               "is_gateway": ip == net["gateway"], "is_self": False, "random_mac": fingerprint.is_random_mac(mac), "online": True,
               "mdns_services": [], "mdns_names": [], "mdns_txt": {}, "ssdp": {}, "model": "", "os": rec.get("os", ""),
               "type": rec.get("type") or "unknown", "confidence": 70, "reasons": [tr("connu : détails du dernier scan complet")],
               "light": True, "security": None}
        if dev["is_gateway"]:
            dev["type"] = "router"
        store.apply(dev, self.overrides, self.aliases)
        return dev

    def _inspect(self, ip, net, arp, extra):
        my_iface = net["iface"] if ip == net["ip"] else self.own.get(ip)
        me = my_iface is not None
        mac = arp.get(ip, "") or extra.get("snmp_arp", {}).get(ip, "")
        if me:
            try:
                mac = open(f"/sys/class/net/{my_iface}/address").read().strip()
            except OSError:
                pass
        P = self.profile
        if P["light"]:
            rec = None if me else (self.known.get(self.aliases.get(mac, mac)) or self.known.get("ip:" + ip))
            if rec:
                dev = self._known_device(ip, net, mac, rec)
                dev["ipv6"] = extra.get("ipv6", {}).get(mac, []) if mac else []
                return dev
            if not P.get("passive"):
                P = PROFILES["normal"]  # appareil inconnu : analyse complète, comme un scan normal
        active = not me and not P.get("passive")  # écoute seule : rien n'est envoyé à l'appareil
        bg = ThreadPoolExecutor(2)  # noms et TTL se résolvent pendant le scan des ports, pas après
        f_names = bg.submit(resolve_names, ip, P["names_timeout"]) if active else None
        f_ttl = bg.submit(ping_ttl, ip) if active else None
        scan = tuple(P["scan_ports"]) + (tuple(p for p in security.EXTRA_PORTS if p not in P["scan_ports"]) if self.security else ())
        ports = scan_ports(ip, scan, P["port_timeout"]) if active else []
        banners = {}
        wanted = [p for p in ports if P["banners"] and (p == 22 or p in HTTP_PORTS or p in TLS_PORTS or (self.security and p == 21))]
        if wanted:
            with ThreadPoolExecutor(min(4, len(wanted))) as bx:
                for p, b in zip(wanted, bx.map(lambda p_: grab_banner(ip, p_), wanted)):
                    if b:
                        banners[p] = b
        with _cert_lock:  # certificats lus pendant la prise des bannières HTTPS
            found_certs = [_cert_cache.pop((ip, p)) for p in sorted(TLS_PORTS) if (ip, p) in _cert_cache]
        cert_info = found_certs[0] if found_certs else {}
        org = cert_info.get("o", "")
        cert_vendor = fingerprint.shorten_vendor(org) if org and not certs._NOISE.match(org) else ""  # dernier recours (réseau routé : pas de MAC)
        md = extra["mdns"].get(ip, {})
        ss = extra["ssdp"].get(ip, {})
        wd = extra.get("wsd", {}).get(ip, {})
        names = sorted(md.get("names", []))
        dns, nb_name, mdns_n = f_names.result() if (active and f_names) else ("", "", "")
        hostname = (dns or nb_name or md.get("host") or mdns_n or (names[0] if names else "") or ss.get("friendly", "")
                    or extra.get("leases", {}).get(mac, ""))
        with _nb_lock:
            netbios = _nb_info.pop(ip, {})
        with _rtt_lock:
            rtt = _rtt_cache.pop(ip, None)
        if me:
            hostname = socket.gethostname()
        ttl = 64 if me else (f_ttl.result() if (active and f_ttl) else None)
        bg.shutdown(wait=False)
        vendor = fingerprint.vendor_of(mac) or ss.get("manufacturer", "") or wd.get("name", "") or cert_vendor
        dev = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
               "ports": ports, "services": [PORT_NAMES.get(p, str(p)) for p in ports],
               "banners": {str(k): v for k, v in banners.items()}, "ttl": ttl,
               "is_gateway": ip == net["gateway"], "is_self": me,
               "random_mac": fingerprint.is_random_mac(mac), "online": True,
               "mdns_services": sorted(md.get("services", [])), "mdns_names": names,
               "mdns_txt": md.get("txt", {}), "ssdp": ss, "wsd": wd, "netbios": netbios, "cert": cert_info, "rtt": rtt,
               "ipv6": extra.get("ipv6", {}).get(mac, []) if mac else []}
        if not me and not active:
            dev["light"] = True  # détails non sondés : l'interface ne les présente pas comme vérifiés
        dev["http_info"] = " ".join(v for k, v in banners.items() if k in HTTP_PORTS or k in TLS_PORTS)[:300]
        model_text = fingerprint._model_text(dev)
        dev["model"] = (md.get("txt", {}).get("model") or md.get("txt", {}).get("md") or md.get("txt", {}).get("rpmd")
                        or md.get("txt", {}).get("ty") or ss.get("model", "") or wd.get("hardware", ""))
        friendly = models.friendly(dev["model"])
        dev["model_name"] = friendly["name"] if friendly else ""
        dev["os"] = tr("Linux (cette machine)") if me else fingerprint.guess_os(
            ttl, ports, vendor, hostname, banners, model_text)
        if me:
            dev["self_kind"] = "laptop" if glob.glob("/sys/class/power_supply/BAT*") else "desktop"
        dev["type"], dev["confidence"], dev["reasons"] = fingerprint.classify_detail(dev)
        if not vendor and dev["random_mac"]:
            dev["vendor"] = fingerprint.vendor_hint(mac)
        store.apply(dev, self.overrides, self.aliases)
        # analyse d'exposition (opt-in, lecture seule) : après le typage définitif de l'appareil
        dev["security"] = None if (me or not self.security or not active) else security.analyze(dev, security.active_probes(ip, ports))
        dev["mdns_txt"] = {k: v[:80] for k, v in list(dev["mdns_txt"].items())[:12]}
        return dev
