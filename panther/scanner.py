"""Moteur de scan réseau maison (stdlib uniquement, sans root).

Découverte : sondes TCP + table ARP du noyau. Enrichissement : DNS inverse,
NetBIOS, mDNS, scan de ports, bannières, TTL, empreinte OS, classification.
"""
import glob
import ipaddress
import logging
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import discovery
from . import networks
from . import security
from . import snmp
from . import topology
from . import fingerprint
from . import store

log = logging.getLogger("panther.scanner")
DISCOVERY_PORTS = (80, 443, 22, 445, 53, 8080, 62078, 5353, 139, 9100)
SCAN_PORTS = (21, 22, 23, 53, 80, 110, 135, 139, 143, 443, 445, 515, 554, 631, 993,
              1900, 3306, 3389, 5000, 5001, 5432, 5555, 6379, 8008, 8009, 8060,
              8080, 8443, 9100, 62078)
QUICK_PORTS = (22, 53, 80, 135, 139, 443, 445, 554, 631, 8009, 9100, 62078)
DEEP_PORTS = SCAN_PORTS + (25, 111, 389, 873, 1433, 1883, 2049, 3000, 5060, 5900, 7547, 8000, 8081,
                           8883, 8888, 9000, 10000, 32400, 34567, 37777)
# Profondeur du scan : rapide (quelques secondes), normal, approfondi (plus lent, plus complet)
PROFILES = {
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
    if iface is None:
        m = re.search(r"default via (\S+) dev (\S+)", networks._run(["ip", "-4", "route", "show", "default"]))
        if not m:
            raise RuntimeError("Aucune route par défaut : êtes-vous connecté à un réseau ?")
        gw, dev = m.groups()
    else:
        dev = iface
        m = re.search(r"default via (\S+)", networks._run(["ip", "-4", "route", "show", "default", "dev", dev]))
        gw = m.group(1) if m else ""  # une interface secondaire n'a pas forcément de passerelle
    m = re.search(r"inet (\S+)", networks._run(["ip", "-4", "-o", "addr", "show", "dev", dev]))
    if not m:
        raise RuntimeError(f"L'interface {dev} n'a pas d'adresse IPv4 : choisissez-en une autre.")
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
    udp_nudge(ip)
    for p in ports:
        opened, refused = tcp_open(ip, p, timeout)
        if opened or refused:
            return True
    return False


def scan_ports(ip, ports, timeout):
    """Ports TCP ouverts, sondés en parallèle (douze à la fois par appareil)."""
    if not ports:
        return []
    with ThreadPoolExecutor(min(12, len(ports))) as ex:
        res = list(ex.map(lambda p: tcp_open(ip, p, timeout)[0], ports))
    return [p for p, ok in zip(ports, res) if ok]


def ping_ttl(ip):
    try:
        out = subprocess.run(["ping", "-c1", "-W1", ip], capture_output=True,
                             text=True, timeout=3).stdout
        m = re.search(r"ttl=(\d+)", out, re.I)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def netbios_name(ip):
    pkt = (b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.8)
    try:
        s.sendto(pkt, (ip, 137))
        data = s.recv(1024)
        n = data[56]
        if n:
            return data[57:72].decode("ascii", "ignore").strip()
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
        except Exception:  # noqa: BLE001 - une résolution ratée ne doit jamais bloquer le scan
            out[key] = ""
    threads = [threading.Thread(target=task, args=(k, f), daemon=True)
               for k, f in (("dns", _dns_name), ("nb", netbios_name), ("mdns", mdns_name))]
    for t in threads:
        t.start()
    end = time.time() + timeout
    for t in threads:
        t.join(max(0.0, end - time.time()))
    return out.get("dns", ""), out.get("nb", ""), out.get("mdns", "")


def grab_banner(ip, port):
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect((ip, port))
        if port in (80, 8080, 8008):
            s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
        data = s.recv(1024).decode("latin-1", "ignore")
        if port in (21, 22):
            return data.strip().splitlines()[0] if data else ""
        m = re.search(r"Server:\s*(.+)", data, re.I)
        t = re.search(r"<title>(.*?)</title>", data, re.I | re.S)
        return " | ".join(x.group(1).strip()[:60] for x in (m, t) if x)
    except OSError:
        return ""
    finally:
        s.close()


class Scanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.profile = PROFILES["normal"]
        self.security = False
        self.iface = None
        self.known = {}
        self.aliases = {}
        self.reset()

    def reset(self):
        self.state = {"status": "idle", "progress": 0, "network": None,
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
            self.state["security"] = self.security = bool(security)
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
            extra_nets, early_warnings = [], []
            for t in targets:
                try:
                    n = networks.validate_cidr(t)  # refuse les plages publiques ou trop grandes
                except ValueError as e:
                    early_warnings.append(f"Plage ignorée : {e}")
                    continue
                if not n.overlaps(local) and all(not n.overlaps(e) for e in extra_nets):
                    extra_nets.append(n)
            all_nets = [local] + extra_nets
            hosts = [str(h) for n in all_nets for h in (n.hosts() if n.num_addresses > 2 else n)]
            if len(hosts) > 2 * networks.MAX_HOSTS:
                raise RuntimeError(f"Trop d'adresses à scanner ({len(hosts)}) : réduisez les plages.")
            self._set(network=net, networks=[
                {"cidr": str(local), "kind": "local", "vlan": net["vlan"]}]
                + [{"cidr": str(n), "kind": "routé", "vlan": None} for n in extra_nets])

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
            routed_hosts = [h for h in hosts if h not in set(local_hosts)]
            arp = {}

            def tcp_pass(pool, timeout_of, patient):
                """Découverte par connexions TCP : réseaux routés (pas d'ARP) ou repli si `ip neigh` est inutilisable."""
                def disc(ip):
                    if self.cancel.is_set():
                        return
                    if ip == net["ip"] or probe_alive(ip, timeout_of(ip), P["disc_ports"]):
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
            if routed_hosts:
                tcp_pass(routed_hosts, lambda ip: P["routed_timeout"], patient=True)
            time.sleep(0.2)
            arp.update({ip: mac for ip, mac in read_arp().items() if ip not in arp})
            for ip in arp:  # hôtes vus en ARP même si rien d'autre n'a répondu
                if ipaddress.ip_address(ip) in local:
                    found.add(ip)
            found.add(net["ip"])
            self._set(progress=62)
            snmp_arp, fdb, warnings, snmp_info = self._read_snmp(snmp_sources, all_nets, found)
            warnings = early_warnings + warnings
            # en mode présence, SSDP/mDNS ne servent que s'il y a un appareil inconnu à identifier
            unknown_local = [ip for ip in found if ip != net["ip"] and self.aliases.get(arp.get(ip, ""), arp.get(ip, "")) not in self.known and ipaddress.ip_address(ip) in local]
            if self.cancel.is_set() or (P["light"] and not unknown_local):
                ssdp, mdns = {}, {}
            else:
                full = PROFILES["normal"] if P["light"] else P
                ssdp, mdns = discovery.scan_all(net["ip"], full["ssdp"], full["mdns"])  # multicast : réseau local
            for ip in list(ssdp) + list(mdns):  # hôtes qui filtrent TCP mais annoncent des services
                try:
                    if ipaddress.ip_address(ip) in local:
                        found.add(ip)
                except ValueError:
                    pass
            extra = {"ssdp": ssdp, "mdns": mdns, "snmp_arp": snmp_arp}
            ips = sorted(found, key=lambda i: ipaddress.ip_address(i))
            paths = self._trace_paths(extra_nets, found)
            for n_ in extra_nets:
                if not any(ipaddress.ip_address(i) in n_ for i in found):
                    hint = f" Dernier saut atteint : {[h for h in paths.get(str(n_), []) if h][-1]}." if any(paths.get(str(n_), [])) else ""
                    warnings.append(f"Réseau {n_} : aucun hôte n'a répondu (routage entre VLAN ou pare-feu ?).{hint}")
            n = [0]

            def enrich(ip):
                if self.cancel.is_set():
                    return
                try:
                    dev = self._inspect(ip, net, arp, extra)
                except Exception as e:  # noqa: BLE001 - un appareil récalcitrant ne doit pas faire échouer tout le scan
                    log.warning("Analyse de %s impossible", ip, exc_info=True)
                    warnings.append(f"Analyse de {ip} impossible : {e}")
                    n[0] += 1
                    return
                dev["network"] = net_of(ip)
                dev["vlan"] = net["vlan"] if dev["network"] == str(local) else None
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
        except Exception as e:  # noqa: BLE001
            log.exception("Le scan a échoué")
            self._set(status="error", error=str(e))

    def _read_snmp(self, sources, all_nets, found):
        """Interroge les routeurs/switchs désignés par l'utilisateur. Retourne ARP, FDB, avertissements."""
        arp, fdb, warnings, info = {}, {}, [], []
        for src in sources:
            host, comm = src.get("host", ""), src.get("community", "public")
            try:
                if not ipaddress.ip_address(host).is_private:
                    raise ValueError("adresse non privée")
                t = snmp.read_tables(host, comm, port=src.get("port", 161))
            except (snmp.SnmpError, ValueError, OSError) as e:
                log.warning("SNMP %s : %s", host, e)
                warnings.append(f"SNMP {host} : {e}")
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
            target = alive[0] if alive else str(next(n.hosts(), n.network_address))
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
               "type": rec.get("type") or "unknown", "confidence": 70, "reasons": ["connu : détails du dernier scan complet"],
               "light": True, "security": None}
        if dev["is_gateway"]:
            dev["type"] = "router"
        store.apply(dev, self.overrides, self.aliases)
        return dev

    def _inspect(self, ip, net, arp, extra):
        me = ip == net["ip"]
        mac = arp.get(ip, "") or extra.get("snmp_arp", {}).get(ip, "")
        if me:
            try:
                mac = open(f"/sys/class/net/{net['iface']}/address").read().strip()
            except OSError:
                pass
        P = self.profile
        if P["light"]:
            rec = None if me else (self.known.get(self.aliases.get(mac, mac)) or self.known.get("ip:" + ip))
            if rec:
                return self._known_device(ip, net, mac, rec)
            P = PROFILES["normal"]  # appareil inconnu : analyse complète, comme un scan normal
        bg = ThreadPoolExecutor(2)  # noms et TTL se résolvent pendant le scan des ports, pas après
        f_names = None if me else bg.submit(resolve_names, ip, P["names_timeout"])
        f_ttl = None if me else bg.submit(ping_ttl, ip)
        scan = tuple(P["scan_ports"]) + (tuple(p for p in security.EXTRA_PORTS if p not in P["scan_ports"]) if self.security else ())
        ports = scan_ports(ip, scan, P["port_timeout"]) if not me else []
        banners = {}
        for p in ports if P["banners"] else []:
            if p in (22, 80, 8080, 8008) or (self.security and p == 21):
                b = grab_banner(ip, p)
                if b:
                    banners[p] = b
        md = extra["mdns"].get(ip, {})
        ss = extra["ssdp"].get(ip, {})
        names = sorted(md.get("names", []))
        dns, nb_name, mdns_n = ("", "", "") if me else f_names.result()
        hostname = dns or nb_name or md.get("host") or mdns_n or (names[0] if names else "") or ss.get("friendly", "")
        if me:
            hostname = socket.gethostname()
        ttl = 64 if me else f_ttl.result()
        bg.shutdown(wait=False)
        vendor = fingerprint.vendor_of(mac) or ss.get("manufacturer", "")
        dev = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
               "ports": ports, "services": [PORT_NAMES.get(p, str(p)) for p in ports],
               "banners": {str(k): v for k, v in banners.items()}, "ttl": ttl,
               "is_gateway": ip == net["gateway"], "is_self": me,
               "random_mac": fingerprint.is_random_mac(mac), "online": True,
               "mdns_services": sorted(md.get("services", [])), "mdns_names": names,
               "mdns_txt": md.get("txt", {}), "ssdp": ss}
        model_text = fingerprint._model_text(dev)
        dev["model"] = (md.get("txt", {}).get("model") or md.get("txt", {}).get("md")
                        or md.get("txt", {}).get("ty") or ss.get("model", ""))
        dev["os"] = "Linux (cette machine)" if me else fingerprint.guess_os(
            ttl, ports, vendor, hostname, banners, model_text)
        if me:
            dev["self_kind"] = "laptop" if glob.glob("/sys/class/power_supply/BAT*") else "desktop"
        dev["type"], dev["confidence"], dev["reasons"] = fingerprint.classify_detail(dev)
        if not vendor and dev["random_mac"]:
            dev["vendor"] = fingerprint.vendor_hint(mac)
        store.apply(dev, self.overrides, self.aliases)
        # analyse d'exposition (opt-in, lecture seule) : après le typage définitif de l'appareil
        dev["security"] = None if (me or not self.security) else security.analyze(dev, security.active_probes(ip, ports))
        dev["mdns_txt"] = {k: v[:80] for k, v in list(dev["mdns_txt"].items())[:12]}
        return dev
