"""Mode démonstration : un réseau FICTIF, pour essayer Panther sans rien scanner (`panther --demo`).

* aucun paquet n'est envoyé : `DemoScanner` remplace le moteur et « découvre » les appareils inventés ci-dessous ;
* les réglages, l'historique, les règles et le journal vivent dans un dossier temporaire supprimé à la fermeture :
  la vraie configuration n'est ni lue ni modifiée ;
* les actions qui sortiraient de la machine (réveil à distance, téléchargement IEEE) sont désactivées.
Ces appareils servent aussi à générer les captures du README (`tools/make_screenshots.py`).
"""
import math
import os
import shutil
import tempfile
import threading
import time
from typing import Any

from . import security
from .i18n import tr

NET, VLAN = "192.168.1.0/24", "192.168.20.0/24"
NETWORK: dict[str, Any] = {"iface": "wlp3s0", "ip": "192.168.1.13", "cidr": NET, "gateway": "192.168.1.1", "vlan": None, "kind": "wifi"}
NETS: list[dict[str, Any]] = [{"cidr": NET, "kind": "local", "vlan": None}, {"cidr": VLAN, "kind": "routé", "vlan": 20}]


def extra():
    """Chemins, voisins et sources SNMP du réseau fictif (le nom du switch est traduit à l'appel)."""
    return {"paths": {VLAN: ["192.168.1.1", "192.168.1.254", "192.168.20.10"]}, "neighbors": [], "warnings": [], "neighbors_status": "ok",
            "snmp": [{"host": "192.168.1.2", "name": tr("sw-salon"), "arp": 11, "fdb": 9}]}


DURATION = 7.0  # secondes d'un scan simulé


def dev(ip, name, typ, ports=(), net=NET, vendor="", **kw):
    d = {"ip": ip, "mac": "%02x:00:5e:%02x:%02x:%02x" % (0xa4, int(ip.split(".")[-2]), int(ip.split(".")[-1]), 7), "hostname": name,
         "type": typ, "vendor": vendor, "os": "Linux", "ports": list(ports), "services": [], "banners": {}, "ttl": 64, "is_gateway": False,
         "is_self": False, "random_mac": False, "online": True, "confidence": 85, "reasons": [tr("annonce mDNS"), tr("fabricant")], "model": "",
         "network": net, "vlan": None, "mdns_services": [], "mdns_names": [], "mdns_txt": {}, "ssdp": {}, "path": [], "security": None}
    d.update(kw)
    return d


def devices(step=99, sec=False, now=None):
    """Réseau fictif ; `step` limite le nombre d'appareils (pour simuler un scan qui progresse)."""
    now = time.time() if now is None else now
    d = [dev("192.168.1.13", tr("portable-demo"), "laptop", is_self=True, vendor="Intel", os=tr("Linux (cette machine)")),
         dev("192.168.1.1", "box", "router", [80, 443], is_gateway=True, vendor="Netgear"),
         dev("192.168.1.2", tr("sw-salon"), "switch", [80], vendor="TP-Link"),
         dev("192.168.1.10", tr("tv-salon"), "tv", [8009], vendor="Samsung", switch=tr("sw-salon"), switch_port="Gi1/0/2"),
         dev("192.168.1.11", "console", "console", vendor="Sony", switch=tr("sw-salon"), switch_port="Gi1/0/3"),
         dev("192.168.1.12", "nas", "nas", [445, 5000, 22], vendor="Synology", switch=tr("sw-salon"), switch_port="Gi1/0/4",
             banners={"22": "SSH-2.0-OpenSSH_9.2p1 Debian"}),
         dev("192.168.1.20", tr("imprimante"), "printer", [9100, 631, 80], vendor="Brother"),
         dev("192.168.1.27", tr("telephone-marie"), "phone", vendor="Apple", os="iOS / iPadOS"),
         dev("192.168.1.28", tr("tablette"), "tablet", vendor="Apple", os="iOS / iPadOS"),
         dev("192.168.1.30", tr("enceinte-cuisine"), "speaker", vendor="Amazon"),
         dev("192.168.1.31", tr("ampoule-salon"), "iot", vendor="Espressif (IoT)"),
         dev("192.168.1.50", "camera-garage", "camera", [80, 554, 23], vendor="Hikvision", banners={"80": "Boa/0.94.14rc21 | Login"}),
         dev("192.168.1.60", tr("ancien-pc"), "desktop", online=False, last_seen=now - 86400 * 2),
         dev("192.168.20.10", tr("cam-entree"), "camera", [554], net=VLAN, vendor="Reolink"),
         dev("192.168.20.11", tr("cam-jardin"), "camera", [554], net=VLAN, vendor="Reolink"),
         dev("192.168.20.20", tr("enregistreur"), "server", [80, 37777], net=VLAN, vendor="Dahua")]
    d = d[:step]
    for x in d:
        if sec and not x["is_self"] and x["online"]:
            probes = {554: "open"} if x["ip"] == "192.168.1.50" else {}
            x["security"] = security.analyze(x, probes)
    return d


def guest_pc():
    """Appareil qui apparaît lors du troisième scan des captures (RDP ouvert : une exposition à montrer)."""
    d = dev("192.168.1.70", tr("pc-invite"), "desktop", [3389], vendor="Dell")
    d["security"] = security.analyze(d)
    return d


def online_devices(sec=False):
    return [x for x in devices(sec=sec) if x["online"]]


class DemoScanner:
    """Même interface que `scanner.Scanner` (start / stop / snapshot), sans aucun accès réseau."""

    def __init__(self, duration=DURATION, clock=time.monotonic):
        self.duration, self.clock, self.lock = duration, clock, threading.Lock()
        self.t0 = self.stopped_at = None
        self.depth, self.security = "normal", False
        self.all = online_devices()

    def _elapsed(self):
        return 0.0 if self.t0 is None else (self.stopped_at if self.stopped_at is not None else self.clock() - self.t0)

    def start(self, targets=None, snmp_sources=None, depth="normal", security=False, iface=None, known=None, aliases=None):
        with self.lock:
            if self.t0 is not None and self.stopped_at is None and self.clock() - self.t0 < self.duration:
                return False
            self.t0, self.stopped_at, self.depth, self.security = self.clock(), None, depth, bool(security) and depth != "ecoute"
            self.all = online_devices(sec=self.security)
            return True

    def stop(self):
        with self.lock:
            if self.t0 is None or self.stopped_at is not None or self.clock() - self.t0 >= self.duration:
                return False
            self.stopped_at = self.clock() - self.t0
            return True

    def snapshot(self):
        with self.lock:
            idle = self.t0 is None
            e = self._elapsed()
            finished = not idle and (self.stopped_at is not None or e >= self.duration)
            frac = min(1.0, e / self.duration)
            # peu d'appareils pendant la découverte (60 %), puis tous au fil de l'analyse
            n = len(self.all) if finished and self.stopped_at is None else math.floor(len(self.all) * max(0.0, frac - 0.2) / 0.75)
            status = "idle" if idle else ("stopped" if self.stopped_at is not None else "done" if finished else "scanning")
            return {"status": status, "progress": 100 if status == "done" else int(frac * 100), "network": dict(NETWORK),
                    "devices": [dict(x) for x in self.all[:max(0, min(n, len(self.all)))]], "networks": [dict(x) for x in NETS],
                    "neighbors": [], "neighbors_status": "ok", "paths": extra()["paths"], "warnings": [],
                    "snmp": extra()["snmp"], "depth": self.depth, "security": self.security,
                    "started": None, "finished": None, "error": None}


def isolate():
    """Redirige toute la configuration vers un dossier temporaire. -> chemin (à supprimer avec `cleanup`)."""
    from PyQt6.QtCore import QSettings

    from . import alerts, history, ouiupdate, rules, secrets, store
    from . import log as plog
    tmp = tempfile.mkdtemp(prefix="panther-demo-")
    os.environ["XDG_CONFIG_HOME"] = tmp
    base = os.path.join(tmp, "Panther")
    os.makedirs(base, mode=0o700, exist_ok=True)
    history.PATH, store.PATH = os.path.join(base, "panther.db"), os.path.join(base, "devices.json")
    alerts.PATH, rules.PATH = os.path.join(base, "alerts.json"), os.path.join(base, "rules.json")
    secrets.PATH, plog.PATH = os.path.join(base, "secrets.json"), os.path.join(base, "panther.log")
    ouiupdate.USER_PATH = os.path.join(base, "oui.txt")
    secrets._tool = lambda: None  # jamais le vrai trousseau
    rules._cache.update(path=None, mtime=None)
    QSettings.setPath(QSettings.Format.NativeFormat, QSettings.Scope.UserScope, tmp)
    return tmp


def cleanup(tmp):
    shutil.rmtree(tmp, ignore_errors=True)


def seed_history(now=None):
    """Trois scans passés : référence, retour de la caméra, puis tout le monde (l'ancien PC a disparu)."""
    from . import history
    now = time.time() if now is None else now
    nets = [n["cidr"] for n in NETS]
    full = online_devices(sec=True)
    first = devices(sec=True, now=now)
    first = [x for x in first if x["ip"] not in ("192.168.1.50", "192.168.1.28")] + [x for x in devices(now=now) if x["ip"] == "192.168.1.60"]
    history.record_scan([dict(x, online=True) for x in first], now=now - 3 * 86400, networks=nets, depth="normal")
    history.record_scan([x for x in full if x["ip"] != "192.168.1.28"], now=now - 86400, networks=nets, depth="normal")
