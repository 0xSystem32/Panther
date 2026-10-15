"""Génère les captures d'écran et le GIF de démonstration du README, à partir d'un réseau FICTIF.

    QT_QPA_PLATFORM=offscreen .venv/bin/python tools/make_screenshots.py [fr|en]

Français par défaut (docs/img/) ; « en » écrit les captures anglaises dans docs/img/en/.

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
LANG = sys.argv[1] if len(sys.argv) > 1 else "fr"
sys.path.insert(0, ROOT)

from PyQt6.QtCore import QSettings  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from panther import compare, fingerprint, gui, history, reportpdf, security, store  # noqa: E402
from panther import demo as demo_mod  # noqa: E402
from panther import i18n  # noqa: E402

i18n.set_language(LANG)

OUT = os.path.join(ROOT, "docs", "img") if LANG == "fr" else os.path.join(ROOT, "docs", "img", LANG)
os.makedirs(OUT, exist_ok=True)
NET, VLAN = "192.168.1.0/24", "192.168.20.0/24"
app = QApplication([])
app.setStyle("Fusion")
QSettings.setPath(QSettings.Format.NativeFormat, QSettings.Scope.UserScope, TMP)
history.PATH, store.PATH = os.path.join(TMP, "panther.db"), os.path.join(TMP, "devices.json")
fingerprint.load_extra_oui(os.path.join(ROOT, "panther", "oui.txt"))
gui.T.update(gui.THEMES["dark"])
app.setStyleSheet(gui.make_style())


dev, demo = demo_mod.dev, lambda step=99, sec=False: demo_mod.devices(step, sec)
NETS, EXTRA = demo_mod.NETS, demo_mod.extra()


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
w.set_layout("types")
shot(w, "carte-types.png")
w.set_layout("etoile")
# zoom + mini-carte + sélection multiple (lasso) : ce qu'on voit sur une grande carte
w.view.resetTransform(); w.view.scale(1.5, 1.5)
w.view.centerOn(w.nodes[gui.dkey(w.devices[1])])
for d in w.devices:
    if d["type"] in ("camera", "tv"):
        w.nodes[gui.dkey(d)].setSelected(True)
for _ in range(3):
    app.processEvents()
w.grab().save(os.path.join(OUT, "carte-selection.png"))   # sans fit() : on veut voir le zoom et la mini-carte
print("   carte-selection.png")
w.scene.clearSelection()
w.fit()

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
record([x for x in base if x["ip"] not in ("192.168.1.50", "192.168.1.28")])
record([x for x in base if x["ip"] != "192.168.1.28"])
mod = [dict(x, ports=x["ports"] + [8060]) if x["ip"] == "192.168.1.10" else x for x in base]
mod = [x for x in mod if x["ip"] != "192.168.1.31"] + [demo_mod.guest_pc()]
mod[-1]["security"] = security.analyze(mod[-1])
record(mod)
w.tabs.setCurrentIndex(1)
shot(w, "appareils.png")
w.tabs.setCurrentIndex(2)
shot(w, "journal.png")
w.tabs.setCurrentIndex(3)
shot(w, "securite.png")
w.tabs.setCurrentIndex(0)
w.selected = gui.dkey(next(d for d in w.devices if d["ip"] == "192.168.1.50"))
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
reportpdf.write_pdf(pdf, reportpdf.build_html(w.devices, [NET, VLAN], time.time(), "map", True, [], changes,
                                                           image_width=reportpdf.map_width(img)), img)
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
    steps = [(2, 8, i18n.tr("Découverte des hôtes")), (4, 20, i18n.tr("Découverte des hôtes")), (6, 38, i18n.tr("Découverte des hôtes")), (8, 52, i18n.tr("Découverte des hôtes")),
             (10, 66, i18n.tr("Analyse des appareils")), (12, 78, i18n.tr("Analyse des appareils")), (13, 88, i18n.tr("Analyse des appareils")), (16, 100, i18n.tr("Analyse des appareils"))]
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
        g.btn.setText(i18n.tr("Arrêter le scan ({progress} %)", progress=pct))
        g.status.setText(i18n.tr("{phase}  ·  {elapsed} s  ·  profondeur {depth}", phase=phase, elapsed=pct // 4 + 1, depth="normal"))
        frame()
    g.progress.hide()
    g.btn.setText(i18n.tr("Relancer le scan"))
    g.status.setText(i18n.tr("Scan terminé en {elapsed} s", elapsed=25))
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
