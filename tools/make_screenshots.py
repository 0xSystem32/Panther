"""Génère les captures d'écran et le GIF de démonstration du README, à partir d'un réseau FICTIF.

    QT_QPA_PLATFORM=offscreen .venv/bin/python tools/make_screenshots.py

Aucune donnée réelle : les appareils ci-dessous sont inventés (rien n'est scanné, la configuration de
l'utilisateur n'est pas touchée). Le GIF demande `ffmpeg`, le rapport PDF en image demande `pdftoppm`.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

TMP = tempfile.mkdtemp()
os.environ["XDG_CONFIG_HOME"] = TMP
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from PyQt6.QtCore import QSettings  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from panther import compare, fingerprint, gui, history, reportpdf, security, store  # noqa: E402

OUT = os.path.join(ROOT, "docs", "img")
NET, VLAN = "192.168.1.0/24", "192.168.20.0/24"
app = QApplication([])
app.setStyle("Fusion")
QSettings.setPath(QSettings.Format.NativeFormat, QSettings.Scope.UserScope, TMP)
history.PATH, store.PATH = os.path.join(TMP, "panther.db"), os.path.join(TMP, "devices.json")
fingerprint.load_extra_oui(os.path.join(ROOT, "panther", "oui.txt"))
gui.T.update(gui.THEMES["dark"])
app.setStyleSheet(gui.make_style())


def dev(ip, name, typ, ports=(), net=NET, vendor="", **kw):
    d = {"ip": ip, "mac": "%02x:00:5e:%02x:%02x:%02x" % (0xa4, int(ip.split(".")[-2]), int(ip.split(".")[-1]), 7), "hostname": name,
         "type": typ, "vendor": vendor, "os": "Linux", "ports": list(ports), "services": [], "banners": {}, "ttl": 64, "is_gateway": False,
         "is_self": False, "random_mac": False, "online": True, "confidence": 85, "reasons": ["annonce mDNS", "fabricant"], "model": "",
         "network": net, "vlan": None, "mdns_services": [], "mdns_names": [], "mdns_txt": {}, "ssdp": {}, "path": [], "security": None}
    d.update(kw)
    return d


def demo(step=99, sec=False):
    """Réseau fictif ; `step` limite le nombre d'appareils (pour le GIF d'un scan qui progresse)."""
    d = [dev("192.168.1.13", "portable-demo", "laptop", is_self=True, vendor="Intel", os="Linux (cette machine)"),
         dev("192.168.1.1", "box", "router", [80, 443], is_gateway=True, vendor="Netgear"),
         dev("192.168.1.2", "sw-salon", "switch", [80], vendor="TP-Link"),
         dev("192.168.1.10", "tv-salon", "tv", [8009], vendor="Samsung", switch="sw-salon", switch_port="Gi1/0/2"),
         dev("192.168.1.11", "console", "console", vendor="Sony", switch="sw-salon", switch_port="Gi1/0/3"),
         dev("192.168.1.12", "nas", "nas", [445, 5000, 22], vendor="Synology", switch="sw-salon", switch_port="Gi1/0/4",
             banners={"22": "SSH-2.0-OpenSSH_9.2p1 Debian"}),
         dev("192.168.1.20", "imprimante", "printer", [9100, 631, 80], vendor="Brother"),
         dev("192.168.1.27", "telephone-marie", "phone", vendor="Apple", os="iOS / iPadOS"),
         dev("192.168.1.28", "tablette", "tablet", vendor="Apple", os="iOS / iPadOS"),
         dev("192.168.1.30", "enceinte-cuisine", "speaker", vendor="Amazon"),
         dev("192.168.1.31", "ampoule-salon", "iot", vendor="Espressif (IoT)"),
         dev("192.168.1.50", "camera-garage", "camera", [80, 554, 23], vendor="Hikvision", banners={"80": "Boa/0.94.14rc21 | Login"}),
         dev("192.168.1.60", "ancien-pc", "desktop", online=False, last_seen=time.time() - 86400 * 2),
         dev("192.168.20.10", "cam-entree", "camera", [554], net=VLAN, vendor="Reolink"),
         dev("192.168.20.11", "cam-jardin", "camera", [554], net=VLAN, vendor="Reolink"),
         dev("192.168.20.20", "enregistreur", "server", [80, 37777], net=VLAN, vendor="Dahua")]
    d = d[:step]
    for x in d:
        if sec and not x["is_self"] and x["online"]:
            probes = {554: "open"} if x["hostname"] == "camera-garage" else {}
            x["security"] = security.analyze(x, probes)
    return d


NETS = [{"cidr": NET, "kind": "local", "vlan": None}, {"cidr": VLAN, "kind": "routé", "vlan": 20}]
EXTRA = {"paths": {VLAN: ["192.168.1.1", "192.168.1.254", "192.168.20.10"]}, "neighbors": [], "warnings": [], "snmp": [
    {"host": "192.168.1.2", "name": "sw-salon", "arp": 11, "fdb": 9}], "neighbors_status": "ok"}


def window():
    w = gui.Main()
    w.notify = lambda *a: None
    w.resize(1240, 780)
    w.network = {"iface": "wlp3s0", "cidr": NET, "gateway": "192.168.1.1", "vlan": None, "kind": "wifi"}
    w.networks_info, w.scan_extra = NETS, EXTRA
    w.targets = [VLAN]
    w.update_netlabel()
    w.show()
    return w


def settle(w):
    for _ in range(3):
        app.processEvents()
    w.fit()
    app.processEvents()


def shot(w, name):
    settle(w)
    w.grab().save(os.path.join(OUT, name))
    print("  ", name)


def feed(w, devices):
    w.devices = devices
    w.rebuild()


w = window()
print("Captures :")
feed(w, demo(sec=True))
w.selected = None
shot(w, "carte-etoile.png")

w.set_layout("hierarchique")
w.selected = gui.dkey(w.devices[5])
w.nodes[w.selected].setSelected(True)
shot(w, "carte-hierarchique.png")
w.scene.clearSelection()
w.set_layout("etoile")

# --- historique : trois scans successifs (référence, changements, exposition)
w.security_on, w.security_consent = True, True


def record(devices, auto=False):
    for x in devices:
        store.apply(x)
    w.last_scan_auto = auto
    w.finish_scan({"devices": devices, "networks": NETS, "depth": "normal"}, 41)
    app.processEvents()
    time.sleep(0.05)


base = [x for x in demo(sec=True) if x["online"]]
record([x for x in base if x["hostname"] not in ("camera-garage", "tablette")])
record([x for x in base if x["hostname"] != "tablette"])
mod = [dict(x, ports=x["ports"] + [8060]) if x["hostname"] == "tv-salon" else x for x in base]
mod = [x for x in mod if x["hostname"] != "ampoule-salon"] + [dev("192.168.1.70", "pc-invite", "desktop", [3389], vendor="Dell")]
mod[-1]["security"] = security.analyze(mod[-1])
record(mod)
w.tabs.setCurrentIndex(1)
shot(w, "appareils.png")
w.tabs.setCurrentIndex(2)
shot(w, "journal.png")
w.tabs.setCurrentIndex(3)
shot(w, "securite.png")
w.tabs.setCurrentIndex(0)
w.selected = gui.dkey(next(d for d in w.devices if d["hostname"] == "camera-garage"))
w.nodes[w.selected].setSelected(True)
shot(w, "carte-details.png")

scans = history.list_scans()
dlg = gui.CompareDialog(scans, w)
dlg.a.setCurrentIndex(len(scans) - 1)
dlg.b.setCurrentIndex(0)
app.processEvents()
dlg.grab().save(os.path.join(OUT, "comparaison.png"))
print("   comparaison.png")

# --- rapport PDF (première page en image, si pdftoppm est disponible)
img = w.render_map_image()
changes = compare.compare(history.load_snapshot(scans[-1]["id"]), history.load_snapshot(scans[0]["id"]))
pdf = os.path.join(TMP, "rapport.pdf")
reportpdf.write_pdf(pdf, reportpdf.build_html(w.devices, [NET, VLAN], time.time(), "map", True, [], changes), img)
if shutil.which("pdftoppm"):
    subprocess.run(["pdftoppm", "-r", "70", "-f", "1", "-l", "1", "-png", "-singlefile", pdf, os.path.join(OUT, "rapport-pdf")], check=True)
    print("   rapport-pdf.png")

# --- GIF : un scan qui progresse, puis la carte hiérarchique
if shutil.which("ffmpeg"):
    print("GIF :")
    frames = os.path.join(TMP, "frames")
    os.makedirs(frames)
    g = window()
    g.resize(1100, 700)
    g.progress.show()
    steps = [(2, 8, "Découverte des hôtes"), (4, 20, "Découverte des hôtes"), (6, 38, "Découverte des hôtes"), (8, 52, "Découverte des hôtes"),
             (10, 66, "Analyse des appareils"), (12, 78, "Analyse des appareils"), (13, 88, "Analyse des appareils"), (16, 100, "Analyse des appareils")]
    n = 0

    def frame(count=1):
        global n
        settle(g)
        for _ in range(count):
            g.grab().save(os.path.join(frames, "f%03d.png" % n))
            n += 1
    for count, pct, phase in steps:
        feed(g, demo(count, sec=True))
        g.progress.setValue(pct)
        g.btn.setText(f"Arrêter le scan ({pct} %)")
        g.status.setText(f"{phase}  ·  {pct // 4 + 1} s  ·  profondeur normal")
        frame()
    g.progress.hide()
    g.btn.setText("Relancer le scan")
    g.status.setText("Scan terminé en 25 s")
    frame(4)
    g.selected = gui.dkey(g.devices[11])
    g.nodes[g.selected].setSelected(True)
    frame(5)
    g.scene.clearSelection()
    g.set_layout("hierarchique")
    frame(7)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", "2.5", "-i", os.path.join(frames, "f%03d.png"),
                    "-vf", "scale=860:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse=dither=bayer:bayer_scale=4",
                    "-loop", "0", os.path.join(OUT, "demo.gif")], check=True)
    print("   demo.gif", round(os.path.getsize(os.path.join(OUT, "demo.gif")) / 1024), "Ko")
shutil.rmtree(TMP, ignore_errors=True)
