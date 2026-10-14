"""Panther – application de bureau (PyQt6)."""
import csv
import html
import ipaddress
import json
import logging
import math
import os
import shutil
import sqlite3
import subprocess
import sys
import time

from PyQt6.QtCore import QPointF, QRectF, QSettings, QSize, Qt, QThread, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import (QAction, QActionGroup, QColor, QDesktopServices, QFont, QFontMetrics, QIcon, QImage, QPainter, QPainterPath, QPen,
                         QPixmap)
from PyQt6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QMenu, QFormLayout, QFrame,
                             QGraphicsItem, QGraphicsLineItem, QGraphicsPathItem, QGraphicsScene,
                             QGraphicsView, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                             QMainWindow, QMessageBox, QProgressBar, QPushButton,
                             QScrollArea, QSizePolicy, QSpinBox, QSplitter, QSystemTrayIcon, QTableWidget, QTableWidgetItem,
                             QTabWidget, QToolBar, QVBoxLayout, QWidget)

from . import compare
from . import fingerprint
from . import history
from . import identity
from . import layout
from . import models
from . import networks
from . import reportpdf
from . import rules
from . import security
from . import store
from .scanner import Scanner, local_network, reclassify

log = logging.getLogger("panther.gui")
LABELS = {"desktop": "Ordinateur", "laptop": "Portable", "phone": "Téléphone",
          "printer": "Imprimante", "router": "Routeur / box", "tv": "TV / multimédia",
          "tablet": "Tablette", "console": "Console de jeux", "speaker": "Enceinte connectée",
          "switch": "Switch", "internet": "Internet", "net": "Réseau", "hop": "Routeur du chemin",
          "gap": "Saut sans réponse", "camera": "Caméra", "server": "Serveur", "nas": "NAS", "iot": "Objet connecté",
          "unknown": "Non identifié"}

THEMES = {
    "dark": dict(bg="#1b1c1f", surface="#222428", panel="#26282d", border="#383b42",
                 fg="#d9dce1", mut="#8b909a", acc="#4c8dff", acc_bg="#243652",
                 grid="#2b2d32", hover="#2d3036", warn="#d9a441", ok="#4caf7d", bad="#e06c6c"),
    "light": dict(bg="#f1f2f4", surface="#ffffff", panel="#ffffff", border="#d2d5db",
                  fg="#1f2329", mut="#6a707b", acc="#2563eb", acc_bg="#dce7fd",
                  grid="#dfe1e6", hover="#eceef1", warn="#b7791f", ok="#2f855a", bad="#c53030"),
}
T = dict(THEMES["dark"])


TYPE_COLORS = {"router": "#7ea2cf", "printer": "#c4a574", "phone": "#a591c0", "tablet": "#a591c0", "console": "#b59a6d", "speaker": "#8fb3b8", "tv": "#c28d98",
               "camera": "#c08585", "server": "#7db5a0", "nas": "#7db5a0", "iot": "#c4b985",
               "desktop": "#92aed0", "laptop": "#92aed0", "switch": "#7ea2cf", "internet": "#8b909a", "net": "#8b909a",
               "hop": "#7ea2cf", "gap": "#8b909a", "unknown": "#8b909a"}


def type_color(kind):
    c = QColor(TYPE_COLORS.get(kind, "#8b909a"))
    return c.darker(140).name() if T["bg"] == THEMES["light"]["bg"] else c.name()


def make_style():
    return f"""
* {{ outline: 0; }}
QMainWindow, QWidget {{ background: {T['bg']}; color: {T['fg']}; }}
QMenuBar {{ background: {T['panel']}; border-bottom: 1px solid {T['border']}; padding: 2px 4px; }}
QMenuBar::item {{ padding: 5px 10px; background: transparent; border-radius: 4px; }}
QMenuBar::item:selected {{ background: {T['hover']}; }}
QMenu {{ background: {T['panel']}; border: 1px solid {T['border']}; padding: 4px; }}
QMenu::item {{ padding: 6px 24px; border-radius: 4px; }}
QMenu::item:selected {{ background: {T['acc_bg']}; }}
QMenu::separator {{ height: 1px; background: {T['border']}; margin: 4px 6px; }}
QToolBar {{ background: {T['panel']}; border: 0; border-bottom: 1px solid {T['border']};
           padding: 6px 10px; spacing: 8px; }}
QLineEdit {{ background: {T['surface']}; border: 1px solid {T['border']}; border-radius: 5px;
            padding: 5px 8px; selection-background-color: {T['acc']}; }}
QLineEdit:focus {{ border-color: {T['acc']}; }}
QComboBox {{ background: {T['surface']}; border: 1px solid {T['border']}; border-radius: 5px; padding: 5px 8px; }}
QComboBox:focus {{ border-color: {T['acc']}; }}
QComboBox QAbstractItemView {{ background: {T['panel']}; border: 1px solid {T['border']};
                              selection-background-color: {T['acc_bg']}; selection-color: {T['fg']}; outline: 0; }}
QDialog {{ background: {T['panel']}; }}
QPushButton {{ background: {T['surface']}; border: 1px solid {T['border']}; border-radius: 5px;
              padding: 6px 14px; }}
QPushButton:hover {{ background: {T['hover']}; }}
QPushButton#primary {{ background: {T['acc']}; border-color: {T['acc']}; color: #ffffff; font-weight: 600; }}
QPushButton#primary:hover {{ background: {T['acc']}; }}
QPushButton#primary:disabled {{ background: {T['border']}; border-color: {T['border']}; color: {T['mut']}; }}
QTabWidget::pane {{ border: 0; border-top: 1px solid {T['border']}; }}
QTabBar {{ background: {T['bg']}; }}
QTabBar::tab {{ background: transparent; color: {T['mut']}; padding: 9px 18px; border: 0;
               border-bottom: 2px solid transparent; }}
QTabBar::tab:selected {{ color: {T['fg']}; border-bottom: 2px solid {T['acc']}; }}
QTabBar::tab:hover:!selected {{ color: {T['fg']}; }}
QTableWidget {{ background: {T['surface']}; border: 0; gridline-color: transparent;
               alternate-background-color: {T['panel']}; selection-background-color: {T['acc_bg']};
               selection-color: {T['fg']}; }}
QTableWidget::item {{ padding: 4px 8px; border: 0; }}
QHeaderView::section {{ background: {T['bg']}; color: {T['mut']}; border: 0;
                       border-bottom: 1px solid {T['border']}; padding: 7px 8px; font-weight: 600; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {T['border']}; border-radius: 5px; min-height: 30px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {T['border']}; border-radius: 5px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QSplitter::handle {{ background: {T['border']}; width: 1px; }}
QStatusBar {{ background: {T['panel']}; border-top: 1px solid {T['border']}; color: {T['mut']}; }}
QStatusBar::item {{ border: 0; }}
QProgressBar {{ background: {T['border']}; border: 0; border-radius: 2px; max-height: 4px; min-height: 4px; }}
QProgressBar::chunk {{ background: {T['acc']}; border-radius: 2px; }}
QWidget#spacer {{ background: transparent; }}
QFrame#side, QFrame#side QScrollArea, QFrame#side QScrollArea > QWidget > QWidget {{ background: {T['panel']}; border: 0; }}
QFrame#sep {{ background: {T['border']}; max-height: 1px; min-height: 1px; }}
QLabel {{ background: transparent; }}
QLabel#title {{ font-size: 16px; font-weight: 600; }}
QLabel#section {{ color: {T['mut']}; font-size: 11px; font-weight: 600; }}
QLabel#key {{ color: {T['mut']}; }}
QLabel#muted {{ color: {T['mut']}; }}
QToolTip {{ background: {T['panel']}; color: {T['fg']}; border: 1px solid {T['border']}; padding: 4px; }}
"""


def draw_icon(p, kind, r, col, width=None):
    """Icône vectorielle (contour) centrée en (0,0)."""
    p.save()
    pen = QPen(QColor(col), width or max(1.6, r / 11), Qt.PenStyle.SolidLine,
               Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    u = r / 12
    R = lambda x, y, w, h, rad=1.2: p.drawRoundedRect(QRectF(x * u, y * u, w * u, h * u), rad * u, rad * u)
    L = lambda x1, y1, x2, y2: p.drawLine(QPointF(x1 * u, y1 * u), QPointF(x2 * u, y2 * u))
    D = lambda x, y: p.drawPoint(QPointF(x * u, y * u))
    if kind == "desktop":
        R(-9, -8, 18, 12); L(-4, 9, 4, 9); L(0, 4, 0, 9)
    elif kind == "laptop":
        R(-7, -7, 14, 10); L(-10, 7, 10, 7)
    elif kind == "phone":
        R(-5, -9, 10, 18, 2); L(-1.5, 6, 1.5, 6)
    elif kind == "printer":
        p.drawPolyline([QPointF(-5 * u, -3 * u), QPointF(-5 * u, -9 * u), QPointF(5 * u, -9 * u), QPointF(5 * u, -3 * u)])
        R(-9, -3, 18, 8, 1.5); R(-5, 1, 10, 8, 0.5)
    elif kind == "switch":
        R(-10, -2, 20, 10, 1.5); D(-6, 3); D(-2, 3); D(2, 3); D(6, 3); L(-5, -2, -5, -8); L(5, -2, 5, -8)
    elif kind == "internet":
        p.drawEllipse(QPointF(0, 0), 9 * u, 9 * u); L(-9, 0, 9, 0); p.drawEllipse(QPointF(0, 0), 4 * u, 9 * u)
    elif kind == "net":
        p.drawEllipse(QPointF(0, -6 * u), 2.4 * u, 2.4 * u); p.drawEllipse(QPointF(-7 * u, 6 * u), 2.4 * u, 2.4 * u)
        p.drawEllipse(QPointF(7 * u, 6 * u), 2.4 * u, 2.4 * u); L(0, -3.6, -5.5, 4); L(0, -3.6, 5.5, 4); L(-4.6, 6, 4.6, 6)
    elif kind in ("router", "hop"):
        R(-10, 1, 20, 7); D(-6, 4.5); D(-3, 4.5)
        p.drawArc(QRectF(-6 * u, -9 * u, 12 * u, 12 * u), 40 * 16, 100 * 16)
        p.drawArc(QRectF(-10 * u, -13 * u, 20 * u, 20 * u), 45 * 16, 90 * 16)
    elif kind == "tv":
        R(-10, -8, 20, 13, 2); L(-6, 9, -4, 5); L(6, 9, 4, 5)
        p.drawPolyline([QPointF(-2.5 * u, -5 * u), QPointF(3 * u, -1.5 * u), QPointF(-2.5 * u, 2 * u), QPointF(-2.5 * u, -5 * u)])
    elif kind == "tablet":
        R(-8, -9, 16, 18, 2); L(-1.5, 6.5, 1.5, 6.5)
    elif kind == "console":
        R(-10, -5, 20, 11, 4); L(-6, -2, -6, 3); L(-8.5, 0.5, -3.5, 0.5)
        p.drawEllipse(QPointF(4 * u, -0.5 * u), 1 * u, 1 * u); p.drawEllipse(QPointF(6.5 * u, 2 * u), 1 * u, 1 * u)
    elif kind == "speaker":
        R(-6, -9, 12, 18, 2.5); p.drawEllipse(QPointF(0, 3.5 * u), 3.2 * u, 3.2 * u); p.drawEllipse(QPointF(0, -4.5 * u), 1.1 * u, 1.1 * u)
    elif kind == "camera":
        R(-10, -5, 14, 10)
        p.drawPolyline([QPointF(4 * u, -1 * u), QPointF(10 * u, -5 * u), QPointF(10 * u, 5 * u), QPointF(4 * u, 1 * u)])
    elif kind in ("server", "nas"):
        R(-9, -9, 18, 7); R(-9, 2, 18, 7); D(-5, -5.5); D(-5, 5.5)
    elif kind == "iot":
        p.drawEllipse(QPointF(0, 0), 3 * u, 3 * u)
        L(0, -10, 0, -6); L(0, 6, 0, 10); L(-10, 0, -6, 0); L(6, 0, 10, 0)
    else:
        p.drawEllipse(QPointF(0, 0), 9 * u, 9 * u)
        f = p.font(); f.setPixelSize(max(8, int(10 * u))); p.setFont(f)
        p.drawText(QRectF(-9 * u, -9 * u, 18 * u, 18 * u), Qt.AlignmentFlag.AlignCenter, "?")
    p.restore()


def type_pixmap(kind, size, color=None, dpr=2):
    pm = QPixmap(size * dpr, size * dpr)
    pm.setDevicePixelRatio(dpr)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.translate(size / 2, size / 2)
    draw_icon(p, kind, size * 0.46, color or type_color(kind))
    p.end()
    return pm


EVENT_LABELS = {"first_seen": "Nouvel appareil", "online": "De retour en ligne", "offline": "Hors ligne",
                "exposure": "Nouvelle exposition", "exposure_fixed": "Exposition corrigée", "merged": "Appareils fusionnés", "ip_changed": "Changement d'adresse IP", "trusted": "Marqué de confiance", "untrusted": "Confiance retirée"}


SECURITY_INFO = (
    "L'analyse de sécurité est en lecture seule.\n\n"
    "Elle regarde les ports ouverts et les bannières, et envoie UNE requête de lecture sans identifiant à "
    "certains services pour savoir s'ils répondent sans mot de passe : PING (Redis), version (Memcached), "
    "GET / (Elasticsearch), GET /version (Docker), DESCRIBE (flux vidéo RTSP).\n\n"
    "Elle n'essaie aucun identifiant, ne devine aucun mot de passe et n'exploite aucune faille.\n\n"
    "À n'activer que sur des réseaux dont vous êtes responsable ou que vous avez l'autorisation d'analyser.")


def sev_color(sev):
    return T["bad"] if security.RANK.get(sev, 0) >= security.RANK["élevé"] else T["warn"] if sev == "moyen" else T["mut"]


def human_size(n):
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024 or unit == "Go":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024


def plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


def when(ts):
    return time.strftime("%d/%m/%Y %H:%M", time.localtime(ts)) if ts else ""


def when_short(ts):
    return time.strftime("%d/%m %H:%M", time.localtime(ts)) if ts else ""


class PresenceBar(QWidget):
    """Présence sur les derniers scans : une case par scan, la plus récente à droite."""

    def __init__(self, flags, parent=None):
        super().__init__(parent)
        self.flags = flags
        self.setFixedHeight(18)
        self.setMinimumWidth(10 * len(flags))
        self.setToolTip(f"Vu dans {sum(flags)} des {len(flags)} derniers scans (le plus récent est à droite)")

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        for i, seen in enumerate(self.flags):
            p.setBrush(QColor(T["ok"] if seen else T["border"]))
            p.drawRoundedRect(QRectF(i * 10, 2, 7, 14), 2, 2)


def seen_label(ts):
    """Heure si c'était aujourd'hui, sinon jour/mois."""
    if not ts:
        return ""
    t = time.localtime(ts)
    return time.strftime("%H:%M" if time.strftime("%Y%m%d", t) == time.strftime("%Y%m%d") else "%d/%m", t)


def status_text(d):
    if not d.get("online", True):
        return f"Hors ligne (vu {seen_label(d.get('last_seen'))})"
    return "Nouveau" if d.get("new") else "En ligne"


KEY_ROLE = Qt.ItemDataRole.UserRole + 1


def dkey(d):
    """Identité d'un appareil dans l'interface : sa clé (MAC d'abord), jamais l'IP seule."""
    return d.get("key") or store.key_for(d)


def ip_key(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (0,)


class SortItem(QTableWidgetItem):
    def __lt__(self, other):
        a, b = self.data(Qt.ItemDataRole.UserRole), other.data(Qt.ItemDataRole.UserRole)
        if a is not None and b is not None:
            return a < b
        return self.text().lower() < other.text().lower()


class EditDialog(QDialog):
    """Nom et type choisis à la main (mémorisés par adresse MAC)."""

    def __init__(self, dev, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Modifier l'appareil")
        self.setMinimumWidth(380)
        auto = dev.get("auto_type", dev["type"])
        self.name = QLineEdit(dev["hostname"] if dev.get("custom") and "auto_hostname" in dev else "")
        self.name.setPlaceholderText(dev.get("auto_hostname", dev["hostname"]) or dev["ip"])
        self.name.setMaxLength(60)
        self.kind = QComboBox()
        self.kind.addItem(f"Détection automatique ({LABELS.get(auto, '')})", None)
        for k in fingerprint.KINDS:
            self.kind.addItem(QIcon(type_pixmap(k, 20)), LABELS[k], k)
        if "auto_type" in dev:
            self.kind.setCurrentIndex(self.kind.findData(dev["type"]))
        form = QFormLayout()
        form.addRow("Nom", self.name)
        form.addRow("Type", self.kind)
        note = QLabel(f"Mémorisé pour l'adresse MAC {dev['mac'] or dev['ip']}.")
        note.setObjectName("muted")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Enregistrer")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Annuler")
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(14)
        lay.addLayout(form); lay.addWidget(note); lay.addWidget(buttons)

    def values(self):
        return self.name.text().strip(), self.kind.currentData()


class Hub(QGraphicsItem):
    """Point d'ancrage invisible au centre d'une zone (VLAN / sous-réseau)."""

    def boundingRect(self):
        return QRectF(-1, -1, 2, 2)

    def paint(self, *_):
        pass


class Zone(QGraphicsItem):
    """Zone nommée autour des appareils d'un autre réseau."""

    def __init__(self, r, label):
        super().__init__()
        self.r, self.label = r, label
        self.setZValue(-3)

    def boundingRect(self):
        return QRectF(-self.r, -self.r - 34, 2 * self.r, 2 * self.r + 34)

    def paint(self, p, *_):
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        fill = QColor(T["acc"]); fill.setAlpha(18)
        pen = QPen(QColor(T["acc"]), 1.2, Qt.PenStyle.DashLine); pen.setCosmetic(True)
        p.setPen(pen); p.setBrush(fill)
        p.drawEllipse(QPointF(0, 0), self.r, self.r)
        f = QFont(); f.setPointSizeF(9); f.setBold(True); p.setFont(f)
        w = QFontMetrics(f).horizontalAdvance(self.label) + 24
        box = QRectF(-w / 2, -self.r - 30, w, 24)
        p.setBrush(QColor(T["panel"])); p.setPen(QPen(QColor(T["acc"]), 1))
        p.drawRoundedRect(box, 12, 12)
        p.setPen(QColor(T["fg"]))
        p.drawText(box, Qt.AlignmentFlag.AlignCenter, self.label)


class ElidedLabel(QLabel):
    """Étiquette qui se tronque avec « … » au lieu d'imposer sa largeur (la barre d'outils ne déborde plus)."""

    def __init__(self, text=""):
        super().__init__(text)
        self._full = text
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    def setText(self, text):
        self._full = text
        self.setToolTip(text)
        super().setText(text)

    def sizeHint(self):
        return QSize(200, super().sizeHint().height())

    def minimumSizeHint(self):
        return QSize(30, super().minimumSizeHint().height())

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setPen(self.palette().windowText().color())
        p.drawText(self.rect(), int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft),
                   QFontMetrics(self.font()).elidedText(self._full, Qt.TextElideMode.ElideRight, self.width()))


class RefreshCombo(QComboBox):
    """Liste déroulante qui se rafraîchit à l'ouverture (les interfaces réseau apparaissent et disparaissent)."""
    about_to_show = pyqtSignal()

    def showPopup(self):
        self.about_to_show.emit()
        super().showPopup()


class CompareDialog(QDialog):
    """Compare deux scans enregistrés : nouveaux appareils, disparus, modifiés."""

    def __init__(self, scans, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Comparer deux scans")
        self.setMinimumSize(780, 540)
        self.a, self.b = QComboBox(), QComboBox()
        for sc in scans:
            label = f"{when(sc['ts'])}  ·  {sc['depth'] or 'normal'}  ·  {sc['count']} appareil(s)"
            self.a.addItem(label, sc["id"]); self.b.addItem(label, sc["id"])
        self.a.setCurrentIndex(min(1, len(scans) - 1)); self.b.setCurrentIndex(0)
        form = QFormLayout(); form.addRow("Scan de départ", self.a); form.addRow("Scan d'arrivée", self.b)
        self.summary = QLabel(); self.summary.setWordWrap(True)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Changement", "Appareil", "Adresse IP", "Détail"])
        self.table.setAlternatingRowColors(True); self.table.setShowGrid(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide(); self.table.verticalHeader().setDefaultSectionSize(32)
        self.table.horizontalHeader().setStretchLastSection(True)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.button(QDialogButtonBox.StandardButton.Close).setText("Fermer"); close.rejected.connect(self.reject)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(12)
        lay.addLayout(form); lay.addWidget(self.summary); lay.addWidget(self.table, 1); lay.addWidget(close)
        self.a.currentIndexChanged.connect(self.refresh); self.b.currentIndexChanged.connect(self.refresh)
        self.refresh()

    def refresh(self):
        t = self.table
        t.setRowCount(0)
        ia, ib = self.a.currentData(), self.b.currentData()
        if ia == ib:
            self.summary.setText("Choisissez deux scans différents."); return
        ra, rb = history.load_snapshot(ia), history.load_snapshot(ib)
        if ra is None or rb is None:
            self.summary.setText("Instantané indisponible pour l'un des scans."); return
        res = compare.compare(ra, rb)
        rows = [("Nouveau", T["ok"], r["name"] or r["ip"], r["ip"], "") for r in res["new"]]
        rows += [("Modifié", T["acc"], c["rec"]["name"] or c["rec"]["ip"], c["rec"]["ip"],
                  "  ;  ".join(compare.format_change(*ch) for ch in c["changes"])) for c in res["changed"]]
        rows += [("Disparu", T["warn"], r["name"] or r["ip"], r["ip"], "") for r in res["gone"]]
        t.setRowCount(len(rows))
        for r, (kind, col, name, ip, detail) in enumerate(rows):
            for c, v in enumerate((kind, name, ip, detail)):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setForeground(QColor(col)); f = it.font(); f.setBold(True); it.setFont(f)
                if c == 3:
                    it.setForeground(QColor(T["mut"])); it.setToolTip(v)
                t.setItem(r, c, it)
        for c, w in enumerate((110, 200, 130)):
            t.setColumnWidth(c, w)
        self.summary.setText(f"{plural(len(res['new']), 'nouveau', 'nouveaux')}  ·  {plural(len(res['gone']), 'disparu', 'disparus')}  ·  "
                             f"{plural(len(res['changed']), 'modifié', 'modifiés')}  ·  {res['same']} inchangé(s)")


class MergeDialog(QDialog):
    """Fusion manuelle : on choisit l'autre appareil à regrouper avec celui-ci."""

    def __init__(self, title, text, candidates, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(480)
        self.candidates = candidates
        info = QLabel(text); info.setWordWrap(True)
        self.combo = QComboBox()
        for d in candidates:
            self.combo.addItem(QIcon(type_pixmap(d["type"], 20)),
                               f"{d['hostname'] or d['ip']}  ·  {d['ip']}" + ("" if d.get("online", True) else f"  ·  hors ligne, vu {seen_label(d.get('last_seen'))}"))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Fusionner")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Annuler")
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(14)
        lay.addWidget(info); lay.addWidget(self.combo); lay.addWidget(buttons)

    def chosen(self):
        return self.candidates[self.combo.currentIndex()]


class DuplicatesDialog(QDialog):
    """Doublons probables détectés après un scan : à confirmer un par un."""

    def __init__(self, suggestions, merge_cb, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Doublons probables")
        self.setMinimumSize(780, 360)
        self.items, self.merge_cb = list(suggestions), merge_cb
        info = QLabel("Un appareil récent ressemble à un appareil hors ligne (même nom, même type, adresse MAC aléatoire). "
                      "Si c'est le même, fusionnez-les : l'historique, la confiance et les noms seront regroupés.")
        info.setWordWrap(True); info.setObjectName("muted")
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Appareil actuel", "Ressemble à (hors ligne)", "Pourquoi"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide(); self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setShowGrid(False); self.table.setAlternatingRowColors(True)
        self.merge_btn = QPushButton("Fusionner la sélection"); self.merge_btn.setObjectName("primary")
        self.merge_btn.clicked.connect(self.merge_selected)
        close = QPushButton("Fermer"); close.clicked.connect(self.accept)
        row = QHBoxLayout(); row.addStretch(1); row.addWidget(close); row.addWidget(self.merge_btn)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(12)
        lay.addWidget(info); lay.addWidget(self.table, 1); lay.addLayout(row)
        self.fill()

    def fill(self):
        t = self.table
        t.setRowCount(len(self.items))
        for r, (new, old, reasons) in enumerate(self.items):
            for c, v in enumerate((f"{new['hostname'] or new['ip']}  ·  {new['ip']}",
                                   f"{old['hostname'] or old['ip']}  ·  {old['ip']}  (vu {seen_label(old.get('last_seen'))})", ", ".join(reasons))):
                t.setItem(r, c, QTableWidgetItem(v))
        for c, w in enumerate((220, 260)):
            t.setColumnWidth(c, w)
        if self.items:
            t.selectRow(0)
        self.merge_btn.setEnabled(bool(self.items))

    def merge_selected(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.items):
            return
        new, old, _ = self.items[row]
        if self.merge_cb(new, old):
            self.items.pop(row)
            self.fill()


class RuleFromDeviceDialog(QDialog):
    """Crée une règle de détection à partir d'un appareil : on choisit le type et les critères à retenir."""

    CRITERIA = (("hostname", "Nom de l'appareil"), ("vendor", "Fabricant"), ("ports", "Ports ouverts"),
                ("mdns", "Services annoncés (mDNS)"), ("mac", "Préfixe de l'adresse MAC (fabricant)"))

    def __init__(self, dev, parent=None):
        super().__init__(parent)
        self.dev = dev
        self.setWindowTitle("Créer une règle de détection")
        self.setMinimumWidth(520)
        self.kind = QComboBox()
        for k in fingerprint.KINDS:
            self.kind.addItem(QIcon(type_pixmap(k, 20)), LABELS[k], k)
        cur = dev.get("auto_type", dev["type"])
        self.kind.setCurrentIndex(max(self.kind.findData(cur if cur != "unknown" else "iot"), 0))
        self.name = QLineEdit(f"{dev['hostname'] or dev['ip']}")
        self.boxes = {}
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(12)
        intro = QLabel(f"Quand un appareil ressemble à « {dev['hostname'] or dev['ip']} », Panther le classera dans le type choisi. "
                       "Cochez ce qui doit être commun (plus de critères = règle plus précise).")
        intro.setWordWrap(True); intro.setObjectName("muted")
        form = QFormLayout(); form.addRow("Type", self.kind); form.addRow("Nom de la règle", self.name)
        lay.addWidget(intro); lay.addLayout(form)
        for key, label in self.CRITERIA:
            b = QCheckBox(label); b.setChecked(key in ("hostname", "ports"))
            b.stateChanged.connect(self.preview); self.boxes[key] = b; lay.addWidget(b)
        self.kind.currentIndexChanged.connect(self.preview); self.name.textChanged.connect(self.preview)
        self.view = QLabel(); self.view.setWordWrap(True); self.view.setTextFormat(Qt.TextFormat.PlainText)
        self.view.setObjectName("muted")
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Enregistrer la règle")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Annuler")
        self.buttons.accepted.connect(self.accept); self.buttons.rejected.connect(self.reject)
        lay.addWidget(self.view); lay.addWidget(self.buttons)
        self.preview()

    def criteria(self):
        return {k for k, b in self.boxes.items() if b.isChecked()}

    def build(self):
        return rules.make_rule(self.dev, self.kind.currentData(), self.criteria(), self.name.text().strip() or None)

    def preview(self, *_):
        try:
            r = self.build()
            self.view.setText("Règle : " + rules.describe(r))
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
        except rules.RuleError as e:
            self.view.setText(str(e))
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)


class RulesDialog(QDialog):
    """Règles de détection personnalisées : liste, avertissements, import / export, édition du fichier."""

    def __init__(self, devices, on_change, parent=None):
        super().__init__(parent)
        self.devices, self.on_change = devices, on_change
        self.setWindowTitle("Règles de détection personnalisées")
        self.setMinimumSize(720, 520)
        self.info = QLabel(); self.info.setWordWrap(True); self.info.setTextFormat(Qt.TextFormat.PlainText); self.info.setObjectName("muted")
        self.warn = QLabel(); self.warn.setWordWrap(True); self.warn.setTextFormat(Qt.TextFormat.PlainText)
        self.warn.setStyleSheet(f"color: {T['warn']};")
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Règle", "Type", "Conditions", "Appareils"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide(); self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setShowGrid(False); self.table.setAlternatingRowColors(True)
        btns = []
        for text, fn in (("Modifier le fichier", self.open_file), ("Recharger", self.reload), ("Créer un exemple", self.example),
                         ("Supprimer la règle", self.remove), ("Exporter…", self.export), ("Importer…", self.import_)):
            b = QPushButton(text); b.clicked.connect(fn); btns.append(b)
        self.example_btn = btns[2]
        row = QHBoxLayout()
        for b in btns:
            row.addWidget(b)
        close = QPushButton("Fermer"); close.setObjectName("primary"); close.clicked.connect(self.accept)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(12)
        lay.addWidget(self.info); lay.addWidget(self.warn); lay.addWidget(self.table, 1); lay.addLayout(row)
        end = QHBoxLayout(); end.addStretch(1); end.addWidget(close); lay.addLayout(end)
        self.refresh()

    def refresh(self):
        rules._cache.update(path=None, mtime=None)  # relit le fichier
        rs = rules.current()
        try:
            raw = {x.get("name"): x for x in (rules.read_data().get("rules", []) or []) if isinstance(x, dict)}
        except rules.RuleError:
            raw = {}
        self.info.setText(f"Fichier : {rules.PATH}\n{plural(len(rs.rules), 'règle valide', 'règles valides')} · "
                          f"{plural(len(rs.models), 'modèle personnalisé', 'modèles personnalisés')}. "
                          "Chaque règle ajoute des points au type indiqué ; la détection intégrée garde son rôle (\"force\": true impose le type).")
        self.warn.setText("\n".join("⚠ " + w for w in rs.warnings))
        self.warn.setVisible(bool(rs.warnings))
        t = self.table
        t.setRowCount(len(rs.rules))
        for r, rule in enumerate(rs.rules):
            hits = sum(1 for d in self.devices if d.get("online", True) and not d.get("virtual")
                       and any(e[0] == rule.kind and e[2] == rule.reason for e in rules.evaluate(d, rules.RuleSet([rule]))))
            for c, v in enumerate((rule.name, LABELS.get(rule.kind, rule.kind), rules.describe(raw.get(rule.name, {})), str(hits))):
                t.setItem(r, c, QTableWidgetItem(v))
        t.setColumnWidth(0, 220); t.setColumnWidth(1, 130); t.setColumnWidth(2, 260)
        self.example_btn.setEnabled(not os.path.exists(rules.PATH))

    def selected_name(self):
        row = self.table.currentRow()
        return self.table.item(row, 0).text() if row >= 0 else None

    def open_file(self):
        if not os.path.exists(rules.PATH):
            rules.create_example()
        QDesktopServices.openUrl(QUrl.fromLocalFile(rules.PATH))

    def reload(self):
        self.refresh(); self.on_change()

    def example(self):
        try:
            rules.create_example()
        except OSError as e:
            QMessageBox.warning(self, "Panther", f"Impossible d'écrire le fichier :\n{e}"); return
        self.reload()

    def remove(self):
        name = self.selected_name()
        if name and QMessageBox.question(self, "Supprimer", f"Supprimer la règle « {name} » ?") == QMessageBox.StandardButton.Yes:
            try:
                rules.remove_rule(name)
            except (OSError, rules.RuleError) as e:
                QMessageBox.warning(self, "Panther", f"Impossible de modifier le fichier :\n{e}"); return
            self.reload()

    def export(self):
        path, _ = QFileDialog.getSaveFileName(self, "Exporter les règles", "regles-panther.json", "JSON (*.json)")
        if path:
            try:
                rules.export_to(path)
            except (OSError, rules.RuleError) as e:
                QMessageBox.warning(self, "Panther", f"Export impossible :\n{e}")

    def import_(self):
        path, _ = QFileDialog.getOpenFileName(self, "Importer des règles", "", "JSON (*.json)")
        if not path:
            return
        try:
            added, warnings = rules.import_from(path)
        except (OSError, rules.RuleError) as e:
            QMessageBox.warning(self, "Panther", f"Import impossible :\n{e}"); return
        QMessageBox.information(self, "Import", f"{plural(added, 'règle importée', 'règles importées')}."
                                + ("\n\nÉcartées :\n" + "\n".join(warnings) if warnings else ""))
        self.reload()


class DataDialog(QDialog):
    """Taille de l'historique, durée de conservation et purge."""

    def __init__(self, scans_days, events_days, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Historique et données")
        self.setMinimumWidth(500)
        self.info = QLabel(); self.info.setTextFormat(Qt.TextFormat.PlainText)
        self.sp_scans, self.sp_events = QSpinBox(), QSpinBox()
        for sp, v in ((self.sp_scans, scans_days), (self.sp_events, events_days)):
            sp.setRange(7, 3650); sp.setValue(v); sp.setSuffix(" jours")
        form = QFormLayout()
        form.addRow("Conserver la présence détaillée", self.sp_scans)
        form.addRow("Conserver le journal", self.sp_events)
        note = QLabel("La purge supprime aussi les instantanés qui servent à comparer deux scans. Les appareils connus, leur confiance "
                      "et leurs noms sont conservés.")
        note.setWordWrap(True); note.setObjectName("muted")
        self.result = QLabel(""); self.result.setObjectName("muted")
        purge = QPushButton("Purger maintenant"); purge.clicked.connect(self.purge)
        close = QPushButton("Enregistrer et fermer"); close.setObjectName("primary"); close.clicked.connect(self.accept)
        row = QHBoxLayout(); row.addWidget(purge); row.addStretch(1); row.addWidget(close)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(14)
        for w in (self.info,):
            lay.addWidget(w)
        lay.addLayout(form); lay.addWidget(note); lay.addWidget(self.result); lay.addLayout(row)
        self.refresh()

    def refresh(self):
        try:
            st = history.db_stats()
        except (sqlite3.Error, OSError) as e:
            self.info.setText(f"Historique indisponible : {e}"); return
        oldest = f"  (le plus ancien : {when(st['oldest_scan'])})" if st["oldest_scan"] else ""
        self.info.setText(f"Fichier : {history.PATH}\nTaille : {human_size(st['size'])}\nAppareils connus : {st['devices']}\n"
                          f"Scans conservés : {st['scans']}{oldest}\nÉvénements du journal : {st['events']}")

    def purge(self):
        try:
            r = history.purge(self.sp_scans.value(), self.sp_events.value())
        except (sqlite3.Error, OSError) as e:
            self.result.setText(f"Purge impossible : {e}"); return
        self.result.setText(f"{plural(r['scans'], 'scan supprimé', 'scans supprimés')}, {plural(r['events'], 'événement supprimé', 'événements supprimés')}.")
        self.refresh()

    def values(self):
        return self.sp_scans.value(), self.sp_events.value()


class Detector(QThread):
    """Sonde les passerelles probables en arrière-plan (sans figer la fenêtre)."""
    found = pyqtSignal(list)

    def __init__(self, exclude, parent=None):
        super().__init__(parent)
        self.exclude = exclude

    def run(self):
        self.found.emit(networks.discover_reachable(self.exclude))


class NetworksDialog(QDialog):
    """Choix des plages à scanner en plus du réseau local."""

    def __init__(self, local_cidr, selected, snmp_sources, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Réseaux à scanner")
        self.setMinimumSize(580, 640)
        self.local, self.detector = local_cidr, None
        intro = QLabel("Le réseau local est toujours scanné. Cochez d'autres plages (autres VLAN, sous-réseaux "
                       "routés) ou ajoutez-les à la main. Panther refuse les plages publiques.")
        intro.setWordWrap(True); intro.setObjectName("muted")
        self.list = QListWidget()
        self.edit = QLineEdit(); self.edit.setPlaceholderText("Ajouter une plage, par exemple 192.168.20.0/24")
        self.edit.returnPressed.connect(self.add_custom)
        add = QPushButton("Ajouter"); add.clicked.connect(self.add_custom)
        row = QHBoxLayout(); row.addWidget(self.edit, 1); row.addWidget(add)
        self.msg = QLabel(""); self.msg.setObjectName("muted"); self.msg.setWordWrap(True)
        self.detect = QPushButton("Détecter les réseaux joignables"); self.detect.clicked.connect(self.start_detect)
        note = QLabel("La détection sonde les passerelles .1 et .254 des plages 192.168.X.0/24 et 10.0.X.0/24 "
                      "(environ 1 000 adresses). Au-delà d'un routeur, les adresses MAC ne sont pas visibles. "
                      "Ne cochez que des réseaux dont vous êtes responsable.")
        note.setWordWrap(True); note.setObjectName("muted")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Enregistrer")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Annuler")
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(12)
        for w in (intro, self.list):
            lay.addWidget(w)
        lay.addLayout(row); lay.addWidget(self.msg); lay.addWidget(self.detect); lay.addWidget(note)
        sep = QFrame(); sep.setObjectName("sep"); lay.addWidget(sep)
        snmp_title = QLabel("SNMP (optionnel, lecture seule)"); snmp_title.setObjectName("section")
        snmp_note = QLabel("Interroge un routeur ou un switch que vous désignez : sa table ARP donne les adresses MAC "
                           "et les appareils des autres VLAN, sa table de ports donne le port et le VLAN de chaque appareil.")
        snmp_note.setWordWrap(True); snmp_note.setObjectName("muted")
        self.snmp_host = QLineEdit(); self.snmp_host.setPlaceholderText("IP du routeur / switch")
        self.snmp_comm = QLineEdit(); self.snmp_comm.setPlaceholderText("Communauté (lecture)")
        self.snmp_comm.setEchoMode(QLineEdit.EchoMode.Password)
        snmp_add = QPushButton("Ajouter"); snmp_add.clicked.connect(self.add_snmp)
        snmp_del = QPushButton("Retirer"); snmp_del.clicked.connect(self.remove_snmp)
        srow = QHBoxLayout(); srow.addWidget(self.snmp_host, 1); srow.addWidget(self.snmp_comm, 1); srow.addWidget(snmp_add); srow.addWidget(snmp_del)
        self.snmp_list = QListWidget(); self.snmp_list.setMaximumHeight(84)
        self.sources = []
        for src in snmp_sources:
            self._add_snmp_item(src)
        for w in (snmp_title, snmp_note):
            lay.addWidget(w)
        lay.addLayout(srow); lay.addWidget(self.snmp_list); lay.addWidget(buttons)
        for n in networks.known_networks(local_cidr):
            self.add_item(n, n["cidr"] in selected)
        for c in selected:
            self.add_item({"cidr": c, "kind": "manuel"}, True)

    def _add_snmp_item(self, src):
        self.sources.append(src)
        self.snmp_list.addItem(f"{src['host']}  ·  communauté {'•' * min(len(src['community']), 8)}")

    def add_snmp(self):
        host, comm = self.snmp_host.text().strip(), self.snmp_comm.text().strip()
        try:
            if not ipaddress.ip_address(host).is_private:
                raise ValueError("Seules les adresses privées sont acceptées.")
        except ValueError as e:
            self.msg.setText(str(e) if "privées" in str(e) else f"« {host} » n'est pas une adresse IP valide."); return
        if not comm:
            self.msg.setText("Indiquez la communauté SNMP en lecture seule."); return
        self._add_snmp_item({"host": host, "community": comm})
        self.snmp_host.clear(); self.snmp_comm.clear(); self.msg.setText("")

    def remove_snmp(self):
        row = self.snmp_list.currentRow()
        if row >= 0:
            self.snmp_list.takeItem(row); self.sources.pop(row)

    def snmp_sources(self):
        return list(self.sources)

    def cidrs(self):
        return [self.list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.list.count())]

    def add_item(self, net, checked):
        if net["cidr"] in self.cidrs():
            return
        locked = net.get("kind") == "local"
        label = networks.describe(net) + {"local": "  (réseau local)", "découvert": "  (détecté)",
                                           "manuel": "  (ajouté)", "interface": "  (autre interface)"}.get(net.get("kind"), "")
        it = QListWidgetItem(label)
        it.setData(Qt.ItemDataRole.UserRole, net["cidr"])
        it.setFlags(Qt.ItemFlag.ItemIsEnabled if locked else Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
        it.setCheckState(Qt.CheckState.Checked if (checked or locked) else Qt.CheckState.Unchecked)
        self.list.addItem(it)

    def add_custom(self):
        try:
            net = networks.validate_cidr(self.edit.text())
        except ValueError as e:
            self.msg.setText(str(e)); return
        self.add_item({"cidr": str(net), "kind": "manuel"}, True)
        self.edit.clear(); self.msg.setText("")

    def start_detect(self):
        self.detect.setEnabled(False); self.detect.setText("Détection en cours…")
        self.detector = Detector([c for c in [self.local] if c], self)
        self.detector.found.connect(self.on_detected)
        self.detector.start()

    def on_detected(self, found):
        for n in found:
            self.add_item(n, False)  # jamais coché d'office : à l'utilisateur de décider
        self.msg.setText(f"{len(found)} réseau(x) joignable(s) trouvé(s)." if found else
                         "Aucun autre réseau joignable détecté (routage ou pare-feu entre les VLAN ?).")
        self.detect.setEnabled(True); self.detect.setText("Détecter les réseaux joignables")

    def reject(self):
        if self.detector and self.detector.isRunning():
            self.detector.wait(30000)
        super().reject()

    def done(self, r):
        if self.detector and self.detector.isRunning():
            self.detector.wait(30000)
        super().done(r)

    def selected(self):
        return [it.data(Qt.ItemDataRole.UserRole) for it in (self.list.item(i) for i in range(self.list.count()))
                if it.checkState() == Qt.CheckState.Checked and it.data(Qt.ItemDataRole.UserRole) != self.local]


class Link(QGraphicsLineItem):
    def __init__(self, a, b, strong, dashed=False):
        super().__init__()
        self.a, self.b = a, b
        self.setZValue(-1)
        pen = QPen(QColor(T["acc"] if strong else T["border"]), 1.8 if strong else 1.2)
        if dashed:
            pen.setStyle(Qt.PenStyle.DashLine)
        pen.setCosmetic(True)
        self.setPen(pen)
        self.update_pos()

    def update_pos(self):
        self.setLine(self.a.pos().x(), self.a.pos().y(), self.b.pos().x(), self.b.pos().y())


class ElbowLink(QGraphicsPathItem):
    """Lien en équerre (vertical – horizontal – vertical) pour la disposition hiérarchique."""

    def __init__(self, a, b, strong, dashed=False):
        super().__init__()
        self.a, self.b = a, b
        self.setZValue(-1)
        pen = QPen(QColor(T["acc"] if strong else T["border"]), 1.8 if strong else 1.2)
        if dashed:
            pen.setStyle(Qt.PenStyle.DashLine)
        pen.setCosmetic(True)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        self.setPen(pen)
        self.update_pos()

    def update_pos(self):
        ax, ay, bx, by = self.a.pos().x(), self.a.pos().y(), self.b.pos().x(), self.b.pos().y()
        mid = (ay + by) / 2
        path = QPainterPath(QPointF(ax, ay))
        for pt in (QPointF(ax, mid), QPointF(bx, mid), QPointF(bx, by)):
            path.lineTo(pt)
        self.setPath(path)


class Node(QGraphicsItem):
    """Nœud rond : icône du type + nom + IP."""

    def __init__(self, dev):
        super().__init__()
        self.dev, self.links, self.hover = dev, [], False
        self.r = 36 if dev["is_self"] or dev["is_gateway"] else 29
        flags = QGraphicsItem.GraphicsItemFlag.ItemIsMovable | QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        if not dev.get("virtual"):  # Internet, routeurs du chemin, réseaux : déplaçables mais sans fiche
            flags |= QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
        self.setFlags(flags)
        self._press = None
        self.setAcceptHoverEvents(True)
        self.setToolTip(f"{dev['hostname'] or dev['ip']}\n{dev['ip']}  ·  {LABELS.get(dev['type'], '')}"
                        + (f"\n{dev['mac']}" if dev["mac"] else "")
                        + (f"\nSwitch : {dev.get('switch', '')}  ·  {dev['switch_port']}" if dev.get("switch_port") else ""))

    def boundingRect(self):
        return QRectF(-90, -self.r - 8, 180, 2 * self.r + 56)

    def paint(self, p, *_):
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        d, r = self.dev, self.r
        col = type_color(d["type"])
        sel = self.isSelected()
        offline = not d.get("online", True)
        if offline:
            p.setOpacity(p.opacity() * 0.55)
        if sel or self.hover:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(T["acc_bg"] if sel else T["hover"]))
            p.drawEllipse(QPointF(0, 0), r + 7, r + 7)
        p.setBrush(QColor(T["acc_bg"] if d["is_self"] else T["surface"]))
        pen = QPen(QColor(col), 2.4 if (sel or d["is_self"] or d["is_gateway"]) else 1.8)
        if offline:
            pen.setStyle(Qt.PenStyle.DashLine)
        p.setPen(pen)
        p.drawEllipse(QPointF(0, 0), r, r)
        draw_icon(p, d["type"], r * 0.62, col)
        if d.get("custom"):
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(T["acc"]))
            p.drawEllipse(QPointF(r * 0.72, -r * 0.72), 4.5, 4.5)
        w_sev = security.worst(d.get("security"))
        if security.RANK.get(w_sev, 0) >= security.RANK["moyen"]:
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(sev_color(w_sev)))
            p.drawEllipse(QPointF(-r * 0.72, r * 0.72), 6, 6)
            p.setPen(QPen(QColor("#ffffff"), 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawLine(QPointF(-r * 0.72, r * 0.72 - 3), QPointF(-r * 0.72, r * 0.72 + 0.6)); p.drawPoint(QPointF(-r * 0.72, r * 0.72 + 3))
        if d.get("trusted"):
            c = QPointF(r * 0.72, r * 0.72)
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(T["ok"]))
            p.drawEllipse(c, 7, 7)
            p.setPen(QPen(QColor("#ffffff"), 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            p.drawPolyline([QPointF(c.x() - 3, c.y()), QPointF(c.x() - 0.8, c.y() + 2.6), QPointF(c.x() + 3.2, c.y() - 2.4)])
        if d.get("new"):
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(T["warn"]))
            p.drawEllipse(QPointF(-r * 0.72, -r * 0.72), 5.5, 5.5)
        f = QFont(); f.setPointSizeF(9); p.setFont(f)
        name = QFontMetrics(f).elidedText(d["hostname"] or d["ip"], Qt.TextElideMode.ElideRight, 170)
        p.setPen(QColor(T["fg"]))
        p.drawText(QRectF(-90, r + 5, 180, 16), Qt.AlignmentFlag.AlignCenter, name)
        m = QFont("monospace"); m.setPointSizeF(8); p.setFont(m)
        p.setPen(QColor(T["mut"]))
        p.drawText(QRectF(-90, r + 21, 180, 14), Qt.AlignmentFlag.AlignCenter,
                   d.get("sub", "") if d.get("virtual") else "cette machine" if d["is_self"] else f"hors ligne · vu {seen_label(d.get('last_seen'))}" if offline else d["ip"])

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for l in self.links:
                l.update_pos()
        return super().itemChange(change, value)

    edit_cb = None
    pos_cb = None

    def mousePressEvent(self, e):
        self._press = self.pos()
        super().mousePressEvent(e)

    def mouseReleaseEvent(self, e):
        super().mouseReleaseEvent(e)
        if self.pos_cb and self._press is not None and self.pos() != self._press:
            self.pos_cb(self)  # position mémorisée uniquement si le nœud a vraiment été déplacé

    def mouseDoubleClickEvent(self, e):
        if self.edit_cb:
            self.edit_cb(self.dev)

    def contextMenuEvent(self, e):
        self.setSelected(True)
        if self.menu_cb:
            self.menu_cb(self.dev, e.screenPos())

    menu_cb = None

    def hoverEnterEvent(self, e): self.hover = True; self.update()
    def hoverLeaveEvent(self, e): self.hover = False; self.update()


class MapView(QGraphicsView):
    def __init__(self, scene):
        super().__init__(scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.legend, self.show_legend = [], True
        self.fit_cb, self.auto_fit = None, False
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

    def drawBackground(self, p, rect):
        p.fillRect(rect, QColor(T["bg"]))
        p.setPen(QPen(QColor(T["grid"]), 2.5 / max(self.transform().m11(), 0.2), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        step = 32
        x0, y0 = math.floor(rect.left() / step) * step, math.floor(rect.top() / step) * step
        pts = [QPointF(x, y) for x in range(int(x0), int(rect.right()) + step, step)
               for y in range(int(y0), int(rect.bottom()) + step, step)]
        if len(pts) < 20000:
            p.drawPoints(pts)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self.auto_fit and self.fit_cb:
            self.fit_cb()  # la fenêtre change de taille : on garde la carte centrée

    def mousePressEvent(self, e):
        self.auto_fit = False
        super().mousePressEvent(e)

    def wheelEvent(self, e):
        self.auto_fit = False
        z = 1.12 if e.angleDelta().y() > 0 else 1 / 1.12
        self.scale(z, z)

    def paintEvent(self, e):
        super().paintEvent(e)
        if not self.legend or not self.show_legend:
            return
        p = QPainter(self.viewport())
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        f = QFont(); f.setPointSizeF(8.5); p.setFont(f)
        rows = self.legend
        cols = 2 if len(rows) > 7 else 1          # légende longue : deux colonnes pour ne pas cacher la carte
        per = -(-len(rows) // cols)
        w, h = 176 * cols, 12 + 20 * per
        box = QRectF(14, self.viewport().height() - h - 14, w, h)
        p.setBrush(QColor(T["panel"])); p.setPen(QPen(QColor(T["border"]), 1))
        p.drawRoundedRect(box, 8, 8)
        for i, (kind, n) in enumerate(rows):
            x0, y = box.left() + (i // per) * 176, box.top() + 6 + (i % per) * 20
            p.drawPixmap(int(x0 + 10), int(y + 2), type_pixmap(kind, 16))
            p.setPen(QColor(T["fg"]))
            p.drawText(QRectF(x0 + 34, y, 120, 20), Qt.AlignmentFlag.AlignVCenter, LABELS[kind])
            p.setPen(QColor(T["mut"]))
            p.drawText(QRectF(x0 + 136, y, 30, 20), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, str(n))


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Panther")
        self.resize(1320, 820)
        self.scanner = Scanner()
        self.settings = QSettings("Panther", "Panther")
        self.devices, self.nodes, self.selected, self.network = [], {}, None, None
        self.networks_info, self.scan_extra = [], {}
        try:
            raw = json.loads(self.settings.value("snmp", "[]"))
            self.snmp = [{"host": str(x["host"]), "community": str(x["community"])} for x in raw]
        except (ValueError, TypeError, KeyError):
            self.snmp = []
        try:
            self.targets = [c for c in json.loads(self.settings.value("targets", "[]")) if networks.validate_cidr(c)]
        except (ValueError, TypeError):
            self.targets = []
        self._building, self.t0 = False, 0
        self.last_new, self.last_scan_auto, self.tray = [], False, None
        self.dup_suggestions = []
        try:  # durée de conservation de l'historique, réglée par l'utilisateur
            history.KEEP_SCANS_DAYS = int(self.settings.value("keep_scans_days", history.KEEP_SCANS_DAYS))
            history.KEEP_EVENTS_DAYS = int(self.settings.value("keep_events_days", history.KEEP_EVENTS_DAYS))
        except (TypeError, ValueError):
            pass
        try:
            self.last_full_scan = float(self.settings.value("last_full_scan", 0))
        except (TypeError, ValueError):
            self.last_full_scan = 0.0
        self.saved_pos = {}
        self.security_on = str(self.settings.value("security", False)).lower() in ("true", "1")
        self.security_consent = str(self.settings.value("security_consent", False)).lower() in ("true", "1")
        self.layout_mode = self.settings.value("layout", "etoile") if self.settings.value("layout", "etoile") in ("etoile", "hierarchique") else "etoile"
        self.show_offline = str(self.settings.value("show_offline", True)).lower() in ("true", "1")

        self._build_menu()
        self._build_toolbar()

        self.scene = QGraphicsScene()
        self.scene.setSceneRect(-3000, -3000, 6000, 6000)
        self.scene.selectionChanged.connect(self.on_scene_selection)
        self.view = MapView(self.scene)
        self.view.fit_cb = self.fit

        self.table = QTableWidget(0, 11)
        self.table.setHorizontalHeaderLabels(["Appareil", "Adresse IP", "Adresse MAC", "Fabricant", "Type", "Système", "Services", "Réseau", "Statut", "Confiance", "Exposition"])
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.setIconSize(self.table.iconSize().expandedTo(self.table.iconSize()))
        self.table.itemSelectionChanged.connect(self.on_table_selection)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(
            lambda pos: self.device_menu(self.table_device(self.table.rowAt(pos.y())), self.table.viewport().mapToGlobal(pos)))
        self.table.cellDoubleClicked.connect(lambda r, c: self.edit_device(self.table_device(r)))

        self.journal = QTableWidget(0, 4)
        self.journal.setHorizontalHeaderLabels(["Date", "Appareil", "Événement", "Détail"])
        self.journal.setAlternatingRowColors(True); self.journal.setShowGrid(False)
        self.journal.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.journal.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.journal.verticalHeader().hide(); self.journal.verticalHeader().setDefaultSectionSize(32)
        self.journal.horizontalHeader().setStretchLastSection(True)
        self.journal.cellDoubleClicked.connect(self.journal_open)
        tabs = self.tabs = QTabWidget()
        tabs.addTab(self.view, "Carte réseau")
        tabs.addTab(self.table, "Appareils")
        tabs.addTab(self.journal, "Journal")
        self.sec_label = QLabel(); self.sec_label.setWordWrap(True); self.sec_label.setObjectName("muted")
        self.sec_label.setContentsMargins(16, 12, 16, 8)
        self.sec_table = QTableWidget(0, 5)
        self.sec_table.setHorizontalHeaderLabels(["Gravité", "Appareil", "Adresse IP", "Constat", "Recommandation"])
        self.sec_table.setAlternatingRowColors(True); self.sec_table.setShowGrid(False)
        self.sec_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sec_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sec_table.verticalHeader().hide(); self.sec_table.verticalHeader().setDefaultSectionSize(34)
        self.sec_table.horizontalHeader().setStretchLastSection(True)
        self.sec_table.cellDoubleClicked.connect(self.security_open)
        sec_page = QWidget(); sl_ = QVBoxLayout(sec_page); sl_.setContentsMargins(0, 0, 0, 0); sl_.setSpacing(0)
        sl_.addWidget(self.sec_label); sl_.addWidget(self.sec_table)
        tabs.addTab(sec_page, "Sécurité")
        tabs.setDocumentMode(True)
        tabs.currentChanged.connect(lambda i: self.refresh_journal() if i == 2 else self.refresh_security() if i == 3 else None)

        self.side = QFrame(); self.side.setObjectName("side"); self.side.setMinimumWidth(310); self.side.setMaximumWidth(420)
        sl = QVBoxLayout(self.side); sl.setContentsMargins(20, 20, 20, 20); sl.setSpacing(14)
        head = QHBoxLayout(); head.setSpacing(12)
        self.side_icon = QLabel(); self.side_icon.setFixedSize(44, 44)
        ht = QVBoxLayout(); ht.setSpacing(2)
        self.side_title = QLabel(); self.side_title.setObjectName("title"); self.side_title.setTextFormat(Qt.TextFormat.PlainText)
        self.side_sub = QLabel(); self.side_sub.setObjectName("muted"); self.side_sub.setTextFormat(Qt.TextFormat.PlainText)
        ht.addWidget(self.side_title); ht.addWidget(self.side_sub)
        head.addWidget(self.side_icon); head.addLayout(ht, 1)
        sep = QFrame(); sep.setObjectName("sep")
        self.form = QFormLayout(); self.form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.form.setHorizontalSpacing(16); self.form.setVerticalSpacing(10)
        self.edit_btn = QPushButton("Modifier le nom / le type…")
        self.edit_btn.clicked.connect(lambda: self.edit_device(self.current_device()))
        self.trust_btn = QPushButton()
        self.trust_btn.clicked.connect(lambda: self.toggle_trust(self.current_device()))
        body = QWidget(); bl = QVBoxLayout(body); bl.setContentsMargins(0, 0, 4, 0); bl.setSpacing(14)
        bl.addLayout(head); bl.addWidget(sep); bl.addLayout(self.form); bl.addStretch(1)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff); scroll.setWidget(body)
        sl.addWidget(scroll, 1); sl.addWidget(self.edit_btn); sl.addWidget(self.trust_btn)

        split = QSplitter(); split.addWidget(tabs); split.addWidget(self.side)
        split.setStretchFactor(0, 1); split.setSizes([980, 340]); split.setChildrenCollapsible(False)
        self.setCentralWidget(split)

        self.status = QLabel("Prêt")
        self.count = QLabel("")
        self.progress = QProgressBar(); self.progress.setFixedWidth(160); self.progress.setTextVisible(False); self.progress.hide()
        self.statusBar().addWidget(self.status, 1)
        self.auto_label = QLabel(""); self.auto_label.setObjectName("muted")
        self.auto_timer = QTimer(self); self.auto_timer.timeout.connect(self.auto_tick)
        self.statusBar().addPermanentWidget(self.auto_label)
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().addPermanentWidget(self.count)
        self.statusBar().setSizeGripEnabled(False)

        self.timer = QTimer(self); self.timer.timeout.connect(self.poll)
        self.update_netlabel()
        w_rules = rules.current().warnings
        if w_rules:
            self.status.setText(f"Règles de détection : {plural(len(w_rules), 'avertissement', 'avertissements')} (menu Détection)")
        try:
            minutes = int(self.settings.value("auto_minutes", 0))
        except (TypeError, ValueError):
            minutes = 0
        minutes = minutes if minutes in self.auto_actions else 0
        self.auto_actions[minutes].setChecked(True); self.set_auto(minutes)
        self.refresh_panel()
        self.refresh_security()

    # ---------- construction ----------
    def _build_menu(self):
        mb = self.menuBar()
        m = mb.addMenu("Fichier")
        for text, fn in (("Exporter le rapport en PDF…", self.export_pdf), ("Exporter en JSON…", lambda: self.export("json")),
                         ("Exporter en CSV…", lambda: self.export("csv"))):
            m.addAction(QAction(text, self, triggered=fn))
        m.addSeparator()
        m.addAction(QAction("Comparer deux scans…", self, triggered=self.compare_scans))
        m.addAction(QAction("Historique et données…", self, triggered=self.open_data))
        m.addSeparator()
        quit_ = QAction("Quitter", self, triggered=self.close); quit_.setShortcut("Ctrl+Q"); m.addAction(quit_)
        m = mb.addMenu("Scan")
        self.act_scan = QAction("Lancer le scan", self, triggered=self.on_scan_button); self.act_scan.setShortcut("Ctrl+R")
        self.act_stop = QAction("Arrêter le scan", self, triggered=self.stop_scan); self.act_stop.setShortcut("Ctrl+.")
        self.act_stop.setEnabled(False)
        m.addAction(self.act_scan); m.addAction(self.act_stop); m.addSeparator()
        m.addAction(QAction("Faire confiance à tous les appareils en ligne…", self, triggered=self.trust_all))
        m.addAction(QAction("Fusionner des doublons…", self, triggered=self.show_duplicates))
        m.addSeparator()
        auto = m.addMenu("Scan automatique"); group = QActionGroup(self); self.auto_actions = {}
        for minutes, label in ((0, "Désactivé"), (5, "Toutes les 5 minutes"), (15, "Toutes les 15 minutes"),
                               (30, "Toutes les 30 minutes"), (60, "Toutes les heures")):
            a = QAction(label, self, checkable=True); group.addAction(a); auto.addAction(a)
            a.triggered.connect(lambda _checked, mm=minutes: self.set_auto(mm)); self.auto_actions[minutes] = a
        m = mb.addMenu("Affichage")
        fit = QAction("Recentrer la carte", self, triggered=self.fit); fit.setShortcut("Ctrl+0"); m.addAction(fit)
        lay = m.addMenu("Disposition"); lgroup = QActionGroup(self); self.layout_actions = {}
        for mode, label in (("etoile", "Étoile (autour de cette machine)"), ("hierarchique", "Hiérarchique (Internet → box → switch → appareils)")):
            a = QAction(label, self, checkable=True); lgroup.addAction(a); lay.addAction(a)
            a.triggered.connect(lambda _c, mm=mode: self.set_layout(mm)); self.layout_actions[mode] = a
        self.layout_actions[self.layout_mode].setChecked(True)
        lay.addSeparator()
        lay.addAction(QAction("Réinitialiser les positions de cette disposition", self, triggered=self.reset_positions))
        leg = QAction("Légende de la carte", self, checkable=True, checked=True, triggered=lambda on: (setattr(self.view, "show_legend", on), self.view.viewport().update()))
        m.addAction(leg)
        off = QAction("Afficher les appareils hors ligne", self, checkable=True, checked=self.show_offline, triggered=self.toggle_offline)
        m.addAction(off)
        self.act_theme = QAction("Thème clair", self, checkable=True, triggered=self.toggle_theme); m.addAction(self.act_theme)
        m = mb.addMenu("Sécurité")
        self.act_security = QAction("Analyse de sécurité (lecture seule)", self, checkable=True, checked=self.security_on)
        self.act_security.triggered.connect(self.toggle_security)
        m.addAction(self.act_security)
        m.addAction(QAction("Voir le rapport de sécurité", self, triggered=lambda: self.tabs.setCurrentIndex(3)))
        m.addAction(QAction("Exporter le rapport (Markdown)…", self, triggered=self.export_security))
        m.addSeparator()
        m.addAction(QAction("Ce que fait l'analyse…", self, triggered=lambda: QMessageBox.information(self, "Analyse de sécurité", SECURITY_INFO)))
        m = mb.addMenu("Détection")
        m.addAction(QAction("Règles personnalisées…", self, triggered=self.open_rules))
        m.addAction(QAction("Créer une règle pour l'appareil sélectionné…", self, triggered=lambda: self.create_rule(self.current_device())))
        m = mb.addMenu("Aide")
        m.addAction(QAction("Ouvrir le journal d'erreurs", self, triggered=self.open_log))
        m.addAction(QAction("À propos de Panther", self, triggered=lambda: QMessageBox.about(
            self, "Panther", "Panther – scanner et cartographie de réseau local.\n\n"
            "Moteur de scan maison (TCP, ARP, NetBIOS, mDNS), sans dépendance externe.\n"
            "À n'utiliser que sur des réseaux dont vous avez l'autorisation.")))

    def _build_toolbar(self):
        tb = QToolBar(); tb.setMovable(False); tb.setFloatable(False); self.addToolBar(tb)
        self.btn = QPushButton("Lancer le scan"); self.btn.setObjectName("primary"); self.btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn.clicked.connect(self.on_scan_button); tb.addWidget(self.btn)
        self.net_btn = QPushButton(); self.net_btn.clicked.connect(self.open_networks); tb.addWidget(self.net_btn)
        lab = QLabel("  Profondeur"); lab.setObjectName("muted"); tb.addWidget(lab)
        self.depth = QComboBox()
        for key, label in (("presence", "Présence"), ("rapide", "Rapide"), ("normal", "Normal"), ("approfondi", "Approfondi")):
            self.depth.addItem(label, key)
        self.depth.setToolTip("Présence : qui est là ? (réutilise les détails du dernier scan complet, très discret).\n"
                              "Rapide : ports courants.\nNormal : bon équilibre.\n"
                              "Approfondi : plus de ports et des délais plus longs.\n"
                              "Les scans automatiques utilisent la présence, avec un scan complet au plus toutes les heures.")
        self.depth.setCurrentIndex(max(self.depth.findData(self.settings.value("depth", "normal")), 0))
        self.depth.currentIndexChanged.connect(lambda _i: self.settings.setValue("depth", self.depth.currentData()))
        tb.addWidget(self.depth)
        lab2 = QLabel("  Interface"); lab2.setObjectName("muted"); tb.addWidget(lab2)
        self.iface_combo = RefreshCombo()
        self.iface_combo.setToolTip("Réseau à scanner. « Automatique » suit la route par défaut ; "
                                    "choisissez une interface pour scanner un autre réseau (Ethernet, VPN…).")
        self.iface_combo.about_to_show.connect(self.populate_ifaces)
        self.populate_ifaces()
        self.iface_combo.currentIndexChanged.connect(lambda _i: self.settings.setValue("iface", self.iface_combo.currentData() or ""))
        tb.addWidget(self.iface_combo)
        self.netlabel = ElidedLabel("  Aucun scan effectué"); self.netlabel.setObjectName("muted"); tb.addWidget(self.netlabel)
        self.search = QLineEdit(); self.search.setPlaceholderText("Filtrer (nom, IP, MAC, type…)")
        self.search.setClearButtonEnabled(True); self.search.setFixedWidth(220)
        self.search.textChanged.connect(self.apply_filter); tb.addWidget(self.search)

    # ---------- scan ----------
    def on_scan_button(self):
        if self.scanner.snapshot()["status"] == "scanning":
            self.stop_scan()
        else:
            self.start_scan()

    def stop_scan(self):
        if self.scanner.stop():
            self.status.setText("Arrêt en cours…"); self.btn.setEnabled(False); self.act_stop.setEnabled(False)

    FULL_SCAN_EVERY = 3600  # secondes : au plus un scan complet par heure pendant les scans automatiques

    def choose_depth(self, auto=False, now=None):
        """Profondeur réellement utilisée et appareils connus. Le scan de présence réutilise les détails du dernier
        scan complet : il n'a de sens que s'il y en a un, et les scans automatiques refont un scan complet toutes les heures."""
        chosen = self.depth.currentData()
        now = time.time() if now is None else now
        want_presence = chosen == "presence" or (auto and now - self.last_full_scan < self.FULL_SCAN_EVERY)
        if want_presence:
            try:
                known = history.last_snapshot_map()
            except (sqlite3.Error, OSError):
                known = {}
            if known:
                return "presence", known
        return ("normal" if chosen == "presence" else chosen), None

    def start_scan(self, auto=False):
        depth, known = self.choose_depth(auto)
        try:
            aliases = history.alias_map()
        except (sqlite3.Error, OSError):
            aliases = {}
        if self.scanner.start(self.targets, self.snmp, depth, self.security_on, self.iface_combo.currentData() or None, known, aliases):
            self.t0, self.last_scan_auto, self.last_new = time.time(), auto, []
            self.act_scan.setEnabled(False); self.act_stop.setEnabled(True)
            self.progress.setValue(0); self.progress.show(); self.timer.start(700)

    def poll(self):
        s = self.scanner.snapshot()
        self.progress.setValue(s["progress"])
        if s["network"]:
            self.network = s["network"]; self.networks_info = s.get("networks", [])
            self.scan_extra = {k: s.get(k) for k in ("neighbors", "neighbors_status", "paths", "warnings", "snmp")}
            self.update_netlabel()
        busy = s["status"] == "scanning"
        if busy:
            self.live_update(s["devices"])
        elapsed = int(time.time() - self.t0)
        self.update_count()
        if busy:
            phase = "Découverte des hôtes" if s["progress"] < 60 else "Analyse des appareils"
            if self.btn.isEnabled():
                self.btn.setText(f"Arrêter le scan ({s['progress']} %)")
            self.status.setText(f"{phase}  ·  {elapsed} s  ·  profondeur {s['depth']}")
            return
        self.timer.stop(); self.progress.hide()
        self.btn.setEnabled(True); self.act_scan.setEnabled(True); self.act_stop.setEnabled(False)
        self.btn.setText("Relancer le scan")
        if s["status"] == "error":
            self.status.setText(f"Erreur : {s['error']}")
        elif s["status"] == "stopped":
            self.devices = s["devices"]; self.rebuild(); self.update_count()
            self.status.setText(f"Scan interrompu : {len(self.devices)} appareil(s) analysé(s) avant l'arrêt" if self.devices
                                else "Scan interrompu pendant la découverte : aucun appareil n'avait encore été analysé")
            self.fit()
        else:
            self.finish_scan(s, elapsed)
        self.refresh_panel()

    def finish_scan(self, s, elapsed):
        """Scan terminé : mémorisation, nouveaux appareils, appareils hors ligne, notification."""
        online, res, offline, note = list(s["devices"]), {"new": [], "baseline": False}, [], ""
        fr = {"new": [], "fixed": [], "baseline": False}
        try:
            res = history.record_scan(online, networks=[n["cidr"] for n in s["networks"]], depth=s["depth"])
            history.annotate(online)
            fr = history.record_findings(online)
            new = set(res["new"])
            for d in online:
                d["new"] = dkey(d) in new
            offline = self.load_offline(online, s["networks"])
        except (sqlite3.Error, OSError) as e:
            log.warning("Historique indisponible", exc_info=True)
            note = f"  ·  historique indisponible ({e})"
        self.devices = online + offline
        self.rebuild(); self.update_count(); self.refresh_journal(); self.refresh_security()
        self.last_new = [f"{d['hostname'] or d['ip']}  ·  {d['ip']}" for d in online if d.get("new")]
        light = s.get("depth") == "presence"
        if not light:
            self.last_full_scan = time.time()
            self.settings.setValue("last_full_scan", self.last_full_scan)
        msg = f"Scan de présence terminé en {elapsed} s" if light else f"Scan terminé en {elapsed} s"
        if res["baseline"]:
            msg += f"  ·  première analyse : {len(online)} appareil(s) enregistrés comme connus"
        elif self.last_new:
            msg += f"  ·  {len(self.last_new)} nouvel appareil" + ("s" if len(self.last_new) > 1 else "")
            if self.last_scan_auto:
                first = [d["hostname"] or d["ip"] for d in online if d.get("new")][:3]
                self.notify("Panther : nouvel appareil sur le réseau", ", ".join(first) + ("…" if len(self.last_new) > 3 else ""))
        if self.security_on and fr["baseline"]:
            msg += "  ·  analyse de sécurité : référence enregistrée"
        if fr["new"]:
            msg += "  ·  " + plural(len(fr["new"]), "nouvelle exposition", "nouvelles expositions")
            bad = [(d, f) for d, f in fr["new"] if security.RANK[f["severity"]] >= security.RANK["élevé"]]
            if bad and self.last_scan_auto:
                d, f = bad[0]
                self.notify("Panther : nouvelle exposition", f"{d['hostname'] or d['ip']} : {f['title']}" + ("…" if len(bad) > 1 else ""))
        if fr["fixed"]:
            msg += "  ·  " + plural(len(fr["fixed"]), "exposition corrigée", "expositions corrigées")
        self.dup_suggestions = identity.suggest_duplicates(self.devices)
        if self.dup_suggestions:
            msg += "  ·  " + plural(len(self.dup_suggestions), "doublon possible", "doublons possibles") + " (menu Scan)"
        w = len(self.scan_extra.get("warnings") or [])
        self.status.setText(msg + (f"  ·  {w} avertissement(s)" if w else "") + note)
        self.fit()

    def load_offline(self, online, nets):
        """Appareils connus mais absents de ce scan (masqués si l'option est désactivée)."""
        if not self.show_offline:
            return []
        off = history.known_offline({dkey(d) for d in online}, [n["cidr"] for n in nets])
        ov = store.load()
        for d in off:
            store.apply(d, ov)
        return off

    def toggle_offline(self, on):
        self.show_offline = on
        self.settings.setValue("show_offline", on)
        online = [d for d in self.devices if d.get("online", True)]
        if online and self.scanner.snapshot()["status"] != "scanning":
            try:
                self.devices = online + self.load_offline(online, self.networks_info)
            except (sqlite3.Error, OSError):
                return
            self.rebuild(); self.update_count(); self.refresh_panel()

    def populate_ifaces(self):
        cur = self.iface_combo.currentData() if self.iface_combo.count() else self.settings.value("iface", "")
        cb = self.iface_combo
        cb.blockSignals(True); cb.clear()
        cb.addItem("Automatique", "")
        for it in networks.interfaces():
            cb.addItem(f"{it['iface']}  ·  {networks.LINK_LABELS.get(it['kind'], '')}", it["iface"])
            cb.setItemData(cb.count() - 1, f"{it['ip']}  ({it['cidr']})", Qt.ItemDataRole.ToolTipRole)
        cb.setCurrentIndex(max(cb.findData(cur), 0))
        cb.blockSignals(False)

    def reclassify_all(self):
        """Après un changement de règles : recalcule le type des appareils analysés (les appareils de présence gardent le leur)."""
        ov = store.load()
        try:
            al = history.alias_map()
        except (sqlite3.Error, OSError):
            al = {}
        for d in self.devices:
            if d.get("online", True) and not d.get("light") and not d.get("virtual") and not d.get("is_self"):
                reclassify(d, ov, al)
        if self.devices:
            self.rebuild(); self.update_count(); self.refresh_panel()

    def open_rules(self):
        RulesDialog(self.devices, self.reclassify_all, self).exec()
        self.reclassify_all()

    def create_rule(self, dev):
        if not dev or dev.get("virtual"):
            QMessageBox.information(self, "Règle de détection", "Sélectionnez d'abord un appareil.")
            return
        dlg = RuleFromDeviceDialog(dev, self)
        if dlg.exec():
            try:
                rules.add_rule(dlg.build())
            except (OSError, rules.RuleError) as e:
                QMessageBox.warning(self, "Panther", f"Impossible d'enregistrer la règle :\n{e}"); return
            self.reclassify_all()
            self.status.setText("Règle enregistrée et appliquée aux appareils affichés")

    def apply_retention(self, scans_days, events_days):
        history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS = int(scans_days), int(events_days)
        self.settings.setValue("keep_scans_days", int(scans_days)); self.settings.setValue("keep_events_days", int(events_days))

    def open_data(self):
        dlg = DataDialog(history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS, self)
        if dlg.exec():
            self.apply_retention(*dlg.values())
            self.status.setText("Durée de conservation enregistrée")

    def compare_scans(self):
        try:
            scans = history.list_scans()
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, "Panther", f"Historique indisponible :\n{e}"); return
        if len(scans) < 2:
            QMessageBox.information(self, "Comparer deux scans", "Il faut au moins deux scans enregistrés. Lancez un scan "
                                    "(ou deux) : chaque scan terminé est conservé pour la comparaison.")
            return
        CompareDialog(scans, self).exec()

    def render_map_image(self, width=1600):
        """Image de la carte, en thème clair (adapté au papier), sans modifier l'affichage."""
        r = self.scene.itemsBoundingRect().adjusted(-40, -40, 40, 40)
        if r.isEmpty():
            return None
        h = max(1, int(width * r.height() / r.width()))
        img = QImage(width, h, QImage.Format.Format_ARGB32)
        saved, sel = dict(T), [i for i in self.scene.selectedItems()]
        self._building = True
        self.scene.clearSelection()
        T.update(THEMES["light"])
        try:
            img.fill(QColor(T["surface"]))
            p = QPainter(img); p.setRenderHint(QPainter.RenderHint.Antialiasing)
            self.scene.render(p, QRectF(0, 0, width, h), r)
            p.end()
        finally:
            T.clear(); T.update(saved)
            for i in sel:
                i.setSelected(True)
            self._building = False
        return img

    def export_pdf(self):
        if not self.devices:
            QMessageBox.information(self, "Rapport PDF", "Aucun résultat à exporter : lancez d'abord un scan."); return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter le rapport", "rapport-panther.pdf", "PDF (*.pdf)")
        if not path:
            return
        changes = None
        try:  # évolution depuis le scan précédent, si on en a un
            scans = history.list_scans(2)
            if len(scans) == 2:
                changes = compare.compare(history.load_snapshot(scans[1]["id"]), history.load_snapshot(scans[0]["id"]))
        except (sqlite3.Error, OSError):
            pass
        img = self.render_map_image()
        page = reportpdf.build_html(self.devices, [n["cidr"] for n in self.networks_info], time.time(), "map" if img else None,
                                    self.security_on, self.scan_extra.get("warnings") or [], changes)
        try:
            reportpdf.write_pdf(path, page, img)
        except OSError as e:
            QMessageBox.warning(self, "Panther", f"Impossible d'écrire le PDF :\n{e}"); return
        self.status.setText(f"Rapport PDF exporté : {os.path.basename(path)}")

    def merge_into(self, keep, drop):
        """Regroupe l'historique de `drop` (hors ligne) dans `keep`. Retourne True si la fusion a eu lieu."""
        if not keep or not drop or drop.get("online", True) or keep is drop:
            QMessageBox.information(self, "Fusion", "Seul un appareil hors ligne peut être fusionné dans un autre appareil.")
            return False
        try:
            history.merge_devices(dkey(keep), dkey(drop))
            history.annotate([keep])
        except (ValueError, sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, "Panther", f"Fusion impossible :\n{e}")
            return False
        store.apply(keep, store.load(), history.alias_map())
        self.devices = [d for d in self.devices if d is not drop]
        self.dup_suggestions = [t for t in self.dup_suggestions if t[0] is not drop and t[1] is not drop]
        self.selected = dkey(keep)
        self.rebuild(); self.update_count(); self.refresh_panel(); self.refresh_journal()
        self.status.setText(f"{drop['hostname'] or drop['ip']} fusionné dans {keep['hostname'] or keep['ip']}")
        return True

    def open_merge(self, dev):
        if dev.get("online", True):
            cands = [d for d in self.devices if not d.get("online", True) and not d.get("virtual")]
            text = (f"Choisissez l'appareil hors ligne qui est en réalité « {dev['hostname'] or dev['ip']} » (par exemple avec une ancienne "
                    "adresse MAC). Son historique, sa confiance et ses noms seront regroupés ici.")
        else:
            cands = [d for d in self.devices if d.get("online", True) and not d.get("virtual") and not d.get("is_self")]
            text = (f"« {dev['hostname'] or dev['ip']} » (hors ligne) est-il un appareil actuellement en ligne ? Choisissez-le : "
                    "l'historique de l'appareil hors ligne sera regroupé avec le sien.")
        if not cands:
            QMessageBox.information(self, "Fusion", "Aucun appareil à fusionner."); return
        dlg = MergeDialog("Fusionner des appareils", text, cands, self)
        if dlg.exec():
            other = dlg.chosen()
            self.merge_into(dev, other) if dev.get("online", True) else self.merge_into(other, dev)

    def show_duplicates(self):
        if not self.dup_suggestions:
            QMessageBox.information(self, "Doublons", "Aucun doublon probable : aucun appareil récent ne ressemble à un appareil hors ligne.")
            return
        DuplicatesDialog(self.dup_suggestions, self.merge_into, self).exec()
        self.refresh_panel()

    def open_log(self):
        from . import log as plog
        if os.path.exists(plog.PATH):
            QDesktopServices.openUrl(QUrl.fromLocalFile(plog.PATH))
        else:
            QMessageBox.information(self, "Journal d'erreurs", f"Aucune erreur enregistrée pour le moment.\n\nEmplacement : {plog.PATH}")

    def toggle_trust(self, dev):
        if not dev:
            return
        flag = not dev.get("trusted")
        try:
            history.set_trusted([dev], flag)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, "Panther", f"Impossible d'enregistrer la confiance :\n{e}"); return
        self.refresh_views(); self.refresh_journal()
        self.status.setText(f"{dev['hostname'] or dev['ip']} : " + ("marqué de confiance" if flag else "confiance retirée"))

    def trust_all(self):
        todo = [d for d in self.devices if d.get("online", True) and not d.get("trusted")]
        if not todo:
            QMessageBox.information(self, "Panther", "Aucun appareil en ligne à valider."); return
        names = "\n".join(f"• {d['hostname'] or d['ip']}  ({d['ip']})" for d in todo[:12]) + ("\n…" if len(todo) > 12 else "")
        if QMessageBox.question(self, "Faire confiance", f"Marquer ces {len(todo)} appareil(s) comme de confiance ?\n\n{names}\n\n"
                                "Vérifiez qu'ils sont tous reconnus : un intrus présent maintenant serait validé.") \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            history.set_trusted(todo, True)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, "Panther", f"Impossible d'enregistrer la confiance :\n{e}"); return
        self.refresh_views(); self.refresh_journal()
        self.status.setText(f"{len(todo)} appareil(s) marqués de confiance")

    def forget_device(self, dev):
        if not dev or QMessageBox.question(self, "Oublier", f"Oublier {dev['hostname'] or dev['ip']} et son historique ?") \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            history.forget(dev)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, "Panther", f"Impossible d'oublier l'appareil :\n{e}"); return
        self.devices = [d for d in self.devices if d is not dev]
        self.selected = None if self.selected == dkey(dev) else self.selected
        self.rebuild(); self.update_count(); self.refresh_panel(); self.refresh_journal()

    def refresh_views(self):
        """Met à jour l'affichage sans recalculer la disposition (les nœuds déplacés restent en place)."""
        for n in self.nodes.values():
            n.update()
        self.fill_table(); self.apply_filter(); self.sync_table(self.selected); self.refresh_panel()

    def refresh_journal(self):
        try:
            ev = history.recent_events(500)
        except (sqlite3.Error, OSError):
            log.warning("Journal des événements illisible", exc_info=True)
            return
        t = self.journal
        t.setRowCount(len(ev))
        for r, e in enumerate(ev):
            cells = [when(e["ts"]), e["name"] or "", EVENT_LABELS.get(e["kind"], e["kind"]), e["detail"] or ""]
            for c, v in enumerate(cells):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, e["key"])
                if c == 3:
                    it.setForeground(QColor(T["mut"]))
                t.setItem(r, c, it)
        for c, w in enumerate((140, 200, 200)):
            t.setColumnWidth(c, w)

    def journal_open(self, row, _col):
        """Double-clic sur un événement : on va sur l'appareil concerné, sur la carte."""
        key = self.journal.item(row, 0).data(Qt.ItemDataRole.UserRole)
        n = self.nodes.get(key)
        if n:
            self.tabs.setCurrentIndex(0); self.scene.clearSelection(); n.setSelected(True); self.view.centerOn(n)

    def toggle_security(self, on):
        if on and not self.security_consent:
            ok = QMessageBox.question(self, "Activer l'analyse de sécurité ?", SECURITY_INFO + "\n\nActiver l'analyse ?") \
                == QMessageBox.StandardButton.Yes
            if not ok:
                self.act_security.setChecked(False); return
            self.security_consent = True
            self.settings.setValue("security_consent", True)
        self.security_on = on
        self.settings.setValue("security", on)
        self.status.setText("Analyse de sécurité activée : elle sera effectuée au prochain scan" if on else "Analyse de sécurité désactivée")
        self.refresh_security()

    def refresh_security(self):
        t = self.sec_table
        analysed = [d for d in self.devices if d.get("security") is not None and d.get("online", True)]
        rows = sorted(((f, d) for d in analysed for f in d["security"]),
                      key=lambda fd: (-security.RANK[fd[0]["severity"]], fd[1].get("hostname") or fd[1]["ip"]))
        t.setRowCount(len(rows))
        for r, (f, d) in enumerate(rows):
            cells = [security.LABELS[f["severity"]], d["hostname"] or d["ip"], d["ip"],
                     f["title"] + (f"  (port {f['port']})" if f.get("port") else ""), f["remedy"]]
            for c, v in enumerate(cells):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setForeground(QColor(sev_color(f["severity"]))); it.setData(KEY_ROLE, dkey(d))
                    ft = it.font(); ft.setBold(True); it.setFont(ft)
                if c == 4:
                    it.setForeground(QColor(T["mut"]))
                if c == 3 and f["detail"]:
                    it.setToolTip(f["detail"])
                t.setItem(r, c, it)
        for c, w in enumerate((90, 180, 120, 380)):
            t.setColumnWidth(c, w)
        if not self.security_on:
            self.sec_label.setText("L'analyse de sécurité est désactivée. Activez-la dans le menu Sécurité (lecture seule), puis lancez un scan.")
        elif not analysed:
            self.sec_label.setText("Lancez un scan pour analyser l'exposition des appareils.")
        elif not rows:
            self.sec_label.setText(f"Aucun constat sur {len(analysed)} appareil(s) analysé(s).")
        else:
            c = security.count_by_severity(analysed)
            self.sec_label.setText(f"{len(rows)} constat(s) sur {len({dkey(d) for _, d in rows})} appareil(s) "
                                   f"({len(analysed)} analysés) : " + " · ".join(f"{n} {security.LABELS[sv].lower()}" for sv, n in c.items() if n)
                                   + "   —   double-clic pour voir l'appareil sur la carte.")

    def security_open(self, row, _col):
        key = self.sec_table.item(row, 0).data(KEY_ROLE)
        n = self.nodes.get(key)
        if n:
            self.tabs.setCurrentIndex(0); self.scene.clearSelection(); n.setSelected(True); self.view.centerOn(n)

    def export_security(self):
        if not any(d.get("security") is not None for d in self.devices):
            QMessageBox.information(self, "Rapport", "Aucun résultat d'analyse : activez l'analyse de sécurité (menu Sécurité) puis lancez un scan.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter le rapport", "rapport-securite.md", "Markdown (*.md)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(security.report_markdown(self.devices, [n["cidr"] for n in self.networks_info]))
            self.status.setText(f"Rapport exporté : {os.path.basename(path)}")

    def update_count(self):
        on = sum(1 for d in self.devices if d.get("online", True))
        off = len(self.devices) - on
        self.count.setText(f"{on} en ligne" + (f"  ·  {off} hors ligne" if off else "") + "   ")

    def set_auto(self, minutes):
        self.settings.setValue("auto_minutes", minutes)
        self.auto_timer.stop()
        if minutes:
            self.auto_timer.start(minutes * 60000)
        self.auto_label.setText(f"Scan auto : toutes les {minutes} min   " if minutes else "")

    def auto_tick(self):
        if self.scanner.snapshot()["status"] != "scanning":
            self.start_scan(auto=True)

    def notify(self, title, message):
        """Notification de bureau : zone de notification Qt si disponible, sinon notify-send."""
        if QSystemTrayIcon.isSystemTrayAvailable():
            if self.tray is None:
                self.tray = QSystemTrayIcon(QIcon(type_pixmap("router", 32)), self); self.tray.show()
            self.tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 8000)
        elif shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "-a", "Panther", title, html.escape(message)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def closeEvent(self, e):
        self.scanner.stop()
        super().closeEvent(e)

    # ---------- carte & tableau ----------
    def add_node(self, d, x, y):
        """Crée un nœud ; une position mémorisée (déplacement manuel) prend le pas sur celle calculée."""
        n = Node(d)
        n.edit_cb, n.menu_cb, n.pos_cb = self.edit_device, self.device_menu, self.remember_position
        n.setPos(*self.saved_pos.get(dkey(d), (x, y)))
        self.scene.addItem(n); self.nodes[dkey(d)] = n
        return n

    def remember_position(self, node):
        try:
            history.save_position(self.layout_mode, dkey(node.dev), node.pos().x(), node.pos().y())
        except (sqlite3.Error, OSError):
            log.debug("Position non mémorisée", exc_info=True)  # confort seulement : on ne gêne pas l'utilisateur

    def rebuild(self):
        self._last_rebuild = time.time()
        self._building = True
        self.scene.clear(); self.nodes = {}
        try:
            self.saved_pos = history.load_positions(self.layout_mode)
        except (sqlite3.Error, OSError):
            self.saved_pos = {}
        if self.layout_mode == "hierarchique":
            self.build_hier()
        else:
            self.build_star()
        kinds = {}
        for d in self.devices:
            kinds[d["type"]] = kinds.get(d["type"], 0) + 1
        self.view.legend = sorted(kinds.items(), key=lambda kv: -kv[1])
        self._building = False
        if self.selected in self.nodes:
            self.nodes[self.selected].setSelected(True)
        self.fill_table(); self.apply_filter()
        if len(self.devices) <= 2:
            self.fit()
        self.view.viewport().update()

    def build_hier(self):
        """Internet → box → switch(s) → appareils ; autres réseaux à la suite du chemin traceroute."""
        ex = self.scan_extra
        lc = self.network["cidr"] if self.network else None
        tree = layout.build_tree(self.devices, lc, self.networks_info, ex.get("paths") or {},
                                 ex.get("neighbors") or [], ex.get("snmp") or [])
        pos = layout.hierarchical_positions(tree)
        for nid, n in tree.nodes.items():
            dev = n["dev"] or {"ip": "", "mac": "", "hostname": n["label"], "type": n["kind"], "vendor": "", "is_self": False,
                               "is_gateway": False, "online": True, "virtual": True, "sub": n["sub"], "key": nid,
                               "custom": False, "new": False, "trusted": False}
            self.add_node(dev, *pos[nid])
        me = next((d for d in self.devices if d["is_self"]), None)
        mine = {dkey(me), *tree.ancestors(dkey(me))} if me and dkey(me) in tree.nodes else set()  # votre chemin vers Internet
        for nid, n in tree.nodes.items():
            p = tree.parent.get(nid)
            if p:
                dashed = n["dashed"] or bool(n["dev"] and not n["dev"].get("online", True))
                l = ElbowLink(self.nodes[p], self.nodes[nid], nid in mine and p in mine, dashed)
                self.scene.addItem(l); self.nodes[p].links.append(l); self.nodes[nid].links.append(l)

    def build_star(self):
        me = next((d for d in self.devices if d["is_self"]), None)
        others = [d for d in self.devices if not d["is_self"]]
        lc = self.network["cidr"] if self.network else None
        local_devs = [d for d in others if d.get("network", lc) == lc]
        groups = {}
        for d in others:
            if d.get("network", lc) != lc:
                groups.setdefault(d["network"], []).append(d)
        for n_ in self.networks_info:
            if n_["cidr"] != lc and n_["cidr"] not in groups:
                groups[n_["cidr"]] = []  # réseau scanné mais sans réponse : on garde sa zone
        gws = [d for d in local_devs if d["is_gateway"]]
        rest = [d for d in local_devs if not d["is_gateway"]]
        place = self.add_node
        self._slot, self._live_ok = len(rest), bool(me)  # la mise à jour incrémentale reprend après les nœuds déjà placés
        if me:
            place(me, 0, 0)
        for i, d in enumerate(gws):
            a = -math.pi / 2 + i * 2 * math.pi / len(gws)
            place(d, 190 * math.cos(a), 190 * math.sin(a))
        cap, idx, ring = 12, 0, 0
        while idx < len(rest):
            chunk = rest[idx: idx + cap]
            for i, d in enumerate(chunk):
                a = -math.pi / 2 + .4 + i * 2 * math.pi / len(chunk)
                place(d, (340 + ring * 150) * math.cos(a), (300 + ring * 130) * math.sin(a))
            idx += cap; ring += 1
        center = self.nodes.get(dkey(me)) if me else None
        if center:
            for d in local_devs:
                n = self.nodes[dkey(d)]
                l = Link(center, n, d["is_gateway"], dashed=not d.get("online", True)); self.scene.addItem(l)
                center.links.append(l); n.links.append(l)
        # autres réseaux / VLAN : une zone nommée par plage, reliée à la passerelle
        router = self.nodes[dkey(gws[0])] if gws else center
        info = {n["cidr"]: n for n in self.networks_info}
        local_reach = 340 + max(ring - 1, 0) * 150
        for zi, (cidr, devs) in enumerate(sorted(groups.items())):
            rz = max(110, len(devs) * 95 / (2 * math.pi))
            dist = local_reach + 260 + rz
            za = -math.pi / 2 + (zi + 1) * 2 * math.pi / (len(groups) + 1)
            zc = QPointF(dist * 1.25 * math.cos(za), dist * math.sin(za))
            vlan = (info.get(cidr) or {}).get("vlan")
            zone = Zone(rz + 70, cidr + (f"  ·  VLAN {vlan}" if vlan else "") + ("" if devs else "  ·  aucun appareil")); zone.setPos(zc); self.scene.addItem(zone)
            hub = Hub(); hub.setPos(zc); self.scene.addItem(hub)
            if router:
                self.scene.addItem(Link(router, hub, True, dashed=True))
            for i, d in enumerate(devs):
                a = -math.pi / 2 + i * 2 * math.pi / len(devs)
                place(d, zc.x() + rz * math.cos(a), zc.y() + rz * math.sin(a))
                n = self.nodes[dkey(d)]
                l = Link(hub, n, False, dashed=not d.get("online", True)); self.scene.addItem(l); n.links.append(l)

    def set_layout(self, mode):
        self.layout_mode = mode
        self.settings.setValue("layout", mode)
        if self.devices:
            self.rebuild(); self.fit()

    def reset_positions(self):
        try:
            history.clear_positions(self.layout_mode)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, "Panther", f"Impossible de réinitialiser les positions :\n{e}"); return
        if self.devices:
            self.rebuild(); self.fit()
        self.status.setText("Positions de cette disposition réinitialisées")

    @staticmethod
    def exposure_item(d):
        f = d.get("security") or []
        w = security.worst(f)
        it = SortItem(f"{security.LABELS[w]} ({len(f)})" if f else "")
        it.setData(Qt.ItemDataRole.UserRole, (security.RANK[w] if w else -1, len(f)))
        if f:
            it.setForeground(QColor(sev_color(w)))
        return it

    def table_items(self, d):
        name = SortItem(d["hostname"] or d["ip"])
        name.setIcon(QIcon(type_pixmap(d["type"], 20)))
        name.setData(KEY_ROLE, dkey(d))
        ip = SortItem(d["ip"]); ip.setData(Qt.ItemDataRole.UserRole, ip_key(d["ip"]))
        vals = [name, ip, SortItem(d["mac"]), SortItem(d["vendor"]), SortItem(LABELS.get(d["type"], "")),
                SortItem(d["os"]), SortItem(", ".join(d["services"])),
                SortItem(d.get("network", "")), SortItem(status_text(d)),
                SortItem("De confiance" if d.get("trusted") else ""), self.exposure_item(d)]
        for c, it in enumerate(vals):
            if c in (1, 2):
                it.setFont(QFont("monospace", 9))
            if not d.get("online", True):
                it.setForeground(QColor(T["mut"]))
        return vals

    def fill_table(self):
        t = self.table
        t.setSortingEnabled(False); t.setRowCount(len(self.devices))
        for r, d in enumerate(self.devices):
            for c, it in enumerate(self.table_items(d)):
                t.setItem(r, c, it)
        t.setSortingEnabled(True)
        t.sortByColumn(1, Qt.SortOrder.AscendingOrder)
        for c, w in enumerate((170, 120, 140, 130, 140, 150)):
            t.setColumnWidth(c, w)

    def live_update(self, devs):
        """Pendant un scan : ajoute les nouveaux appareils sans reconstruire la carte (les nœuds existants, y compris
        ceux que vous avez déplacés, ne bougent pas). Les cas qui changent la disposition (autre réseau, passerelle
        tardive, disposition hiérarchique) retombent sur une reconstruction, au plus une par seconde."""
        if not devs:  # le scan vient de démarrer : on garde l'ancien affichage jusqu'à l'arrivée du premier appareil
            return
        if len(devs) < len(self.devices):  # nouveau scan en cours : l'ancien affichage est remplacé
            self.devices = list(devs); self.rebuild(); return
        known = {dkey(d) for d in self.devices}
        new = [d for d in devs if dkey(d) not in known]
        if not new:
            return
        lc = self.network["cidr"] if self.network else None
        incremental = (self.layout_mode == "etoile" and getattr(self, "_live_ok", False)
                       and all(d.get("network", lc) == lc and not d["is_self"] for d in new))
        self.devices = list(devs)
        if not incremental:
            if time.time() - getattr(self, "_last_rebuild", 0) > 1.0 or not self.nodes:
                self.rebuild()
            return
        center = next((n for n in self.nodes.values() if n.dev.get("is_self")), None)
        for d in new:
            if d["is_gateway"]:
                x, y = 0, -190
            else:
                ring, idx = divmod(self._slot, 12)
                a = -math.pi / 2 + .4 + idx * 2 * math.pi / 12
                x, y = (340 + ring * 150) * math.cos(a), (300 + ring * 130) * math.sin(a)
                self._slot += 1
            n = self.add_node(d, x, y)
            if center:
                l = Link(center, n, d["is_gateway"]); self.scene.addItem(l)
                center.links.append(l); n.links.append(l)
            t = self.table
            t.setSortingEnabled(False)
            r = t.rowCount(); t.insertRow(r)
            for c, it in enumerate(self.table_items(d)):
                t.setItem(r, c, it)
            t.setSortingEnabled(True)
        kinds = {}
        for d in self.devices:
            kinds[d["type"]] = kinds.get(d["type"], 0) + 1
        self.view.legend = sorted(kinds.items(), key=lambda kv: -kv[1])
        self.apply_filter()
        if not self.view.auto_fit:
            self.view.auto_fit = True
        self.fit()
        self.view.viewport().update()

    def apply_filter(self):
        q = self.search.text().strip().lower()
        def match(d):
            hay = " ".join([d["ip"], d.get("network", ""), status_text(d), "de confiance" if d.get("trusted") else "non vérifié", security.worst(d.get("security")), d["mac"], d["vendor"], d["hostname"], d["os"], LABELS.get(d["type"], ""), " ".join(d["services"])]).lower()
            return all(w in hay for w in q.split())
        for d in self.devices:
            n = self.nodes.get(dkey(d))
            if n:
                n.setOpacity(1.0 if match(d) else 0.18)
        by_key = {dkey(x): x for x in self.devices}
        for r in range(self.table.rowCount()):
            d = by_key.get(self.table.item(r, 0).data(KEY_ROLE))
            self.table.setRowHidden(r, bool(d) and not match(d))

    def fit(self):
        r = self.scene.itemsBoundingRect()
        if r.isEmpty():
            return
        self.scene.setSceneRect(r.adjusted(-900, -900, 900, 900))  # la carte reste au centre de la vue
        self.view.fitInView(r.adjusted(-40, -40, 40, 40), Qt.AspectRatioMode.KeepAspectRatio)
        if self.view.transform().m11() > 1.8:
            self.view.resetTransform(); self.view.scale(1.8, 1.8)
        self.view.centerOn(r.center())
        self.view.auto_fit = True

    # ---------- sélection ----------
    def on_scene_selection(self):
        if self._building:
            return
        try:
            items = self.scene.selectedItems()
        except RuntimeError:  # scène détruite à la fermeture
            return
        self.selected = dkey(items[0].dev) if items else None
        self.sync_table(self.selected); self.refresh_panel()

    def on_table_selection(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        n = self.nodes.get(self.table.item(rows[0].row(), 0).data(KEY_ROLE))
        if n:
            self.scene.clearSelection(); n.setSelected(True); self.view.centerOn(n)

    def sync_table(self, key):
        self.table.blockSignals(True)
        self.table.clearSelection()
        if key:
            for r in range(self.table.rowCount()):
                if self.table.item(r, 0).data(KEY_ROLE) == key:
                    self.table.selectRow(r); break
        self.table.blockSignals(False)

    # ---------- panneau latéral ----------
    def add_row(self, key, value, mono=False):
        if not value:
            return
        k = QLabel(key); k.setObjectName("key")
        v = QLabel(str(value)); v.setTextFormat(Qt.TextFormat.PlainText); v.setWordWrap(True)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if mono:
            v.setFont(QFont("monospace", 9))
        self.form.addRow(k, v)

    def add_finding_row(self, f):
        k = QLabel(security.LABELS[f["severity"]]); k.setStyleSheet(f"color: {sev_color(f['severity'])}; font-weight: 600;")
        text = f["title"] + (f"  (port {f['port']})" if f.get("port") else "") + (f"\nÀ faire : {f['remedy']}" if f["remedy"] else "")
        v = QLabel(text); v.setTextFormat(Qt.TextFormat.PlainText); v.setWordWrap(True)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if f["detail"]:
            v.setToolTip(f["detail"])
        self.form.addRow(k, v)

    def refresh_panel(self):
        while self.form.rowCount():
            self.form.removeRow(0)
        d = self.current_device()
        self.edit_btn.setVisible(bool(d)); self.trust_btn.setVisible(bool(d))
        if d:
            self.trust_btn.setText("Retirer la confiance" if d.get("trusted") else "Marquer comme appareil de confiance")
        if d:
            self.side_icon.setPixmap(type_pixmap(d["type"], 40))
            self.side_title.setText(d["hostname"] or d["ip"])
            self.side_sub.setText(LABELS.get(d["type"], ""))
            if not d.get("online", True):
                self.add_row("Statut", f"Hors ligne · dernière apparition le {time.strftime('%d/%m/%Y %H:%M', time.localtime(d['last_seen']))}")
            elif d.get("new"):
                self.add_row("Statut", "Nouvel appareil (première apparition)")
            self.add_row("Adresse IP", d["ip"], True)
            self.add_row("Adresse MAC", d["mac"], True)
            self.add_row("Réseau", d.get("network", "") + (f"  ·  VLAN {d['vlan']}" if d.get("vlan") else ""), True)
            self.add_row("Fabricant", d["vendor"])
            c = d.get("cert") or {}
            if c:
                who = c.get("cn") or c.get("o") or "certificat sans nom"
                self.add_row("Certificat HTTPS", who + (f"  ·  émis par {c['issuer']}" if c.get("issuer") and not c.get("self_signed") else "  ·  auto-signé")
                             + (f"  ·  expiré le {c['not_after']}" if c.get("expired") else f"  ·  expire le {c['not_after']}" if c.get("not_after") else ""))
            if d.get("switch_port"):
                self.add_row("Switch", f"{d.get('switch', '')}  ·  {d['switch_port']}")
            if d.get("path"):
                self.add_row("Chemin", "  →  ".join(h or "*" for h in d["path"]), True)
            self.add_row("Modèle", models.describe(d.get("model", "")))
            self.add_row("Système", d["os"])
            self.add_row("TTL", str(d["ttl"]) if d["ttl"] else "")
            self.add_row("Services", "  ·  ".join(d["services"]))
            self.add_row("Ports", ", ".join(map(str, d["ports"])), True)
            for p, b in d["banners"].items():
                self.add_row(f"Port {p}", b)
            if d.get("mdns_services"):
                self.add_row("Annonces", "\n".join(d["mdns_services"]), True)
            if d["type"] != "unknown" or d.get("reasons"):
                conf = d.get("confidence", 0)
                self.add_row("Détection", f"{LABELS.get(d['type'], '')} · confiance {fingerprint.confidence_label(conf)} ({conf} %)")
                self.add_row("Indices", "\n".join("• " + r for r in d.get("reasons", [])))
            if d.get("light"):
                self.add_row("Analyse", "Présence confirmée ; détails repris du dernier scan complet")
            self.add_row("Confiance", "De confiance" if d.get("trusted") else "Non vérifié")
            if d.get("security") is not None:
                if d["security"]:
                    for f in d["security"]:
                        self.add_finding_row(f)
                else:
                    self.add_row("Exposition", "Aucun constat")
            try:
                h = history.device_summary(d)
            except (sqlite3.Error, OSError):
                h = None
            if h:
                self.add_row("Première apparition", when(h["first_seen"]))
                self.add_row("Dernière apparition", "à l'instant" if d.get("online", True) else when(h["last_seen"]))
                if h["presence"]:
                    k = QLabel("Présence"); k.setObjectName("key")
                    self.form.addRow(k, PresenceBar(h["presence"]))
                if h["uptime7"] is not None:
                    self.add_row("Disponibilité", f"{h['uptime7']} % sur 7 jours")
                if h["events"]:
                    self.add_row("Historique", "\n".join(f"{when_short(e['ts'])}  {EVENT_LABELS.get(e['kind'], e['kind'])}"
                                                         + (f"  ({e['detail']})" if e["detail"] and e["kind"] != "first_seen" else "")
                                                         for e in h["events"]))
            if d["is_gateway"]:
                self.add_row("Rôle", "Passerelle par défaut")
            if d["is_self"]:
                self.add_row("Rôle", "Machine locale")
        else:
            self.side_icon.setPixmap(type_pixmap("router", 40))
            self.side_title.setText("Réseau local")
            self.side_sub.setText("Aucune sélection")
            if self.network:
                self.add_row("Sous-réseau", self.network["cidr"], True)
                self.add_row("Passerelle", self.network["gateway"], True)
                self.add_row("Interface", self.network["iface"], True)
                on = sum(1 for x in self.devices if x.get("online", True))
                self.add_row("Appareils", f"{on} en ligne" + (f"  ·  {len(self.devices) - on} hors ligne" if len(self.devices) > on else ""))
                kinds = {}
                for x in self.devices:
                    kinds[x["type"]] = kinds.get(x["type"], 0) + 1
                for k, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
                    self.add_row(LABELS[k], str(n))
                if self.last_new:
                    self.add_row("Nouveaux", "\n".join(self.last_new))
                if self.dup_suggestions:
                    self.add_row("Doublons possibles", "\n".join(f"{n['hostname'] or n['ip']} ≈ {o['hostname'] or o['ip']} (hors ligne)"
                                                                 for n, o, _ in self.dup_suggestions))
                if self.security_on and any(x.get("security") is not None for x in self.devices):
                    c = security.count_by_severity(self.devices)
                    self.add_row("Sécurité", " · ".join(f"{n} {security.LABELS[sv].lower()}" for sv, n in c.items() if n) or "Aucun constat")
                ex = self.scan_extra
                for w_ in ex.get("warnings") or []:
                    self.add_row("Attention", w_)
                for i in ex.get("snmp") or []:
                    self.add_row("SNMP", f"{i['name'] or i['host']} : {i['arp']} entrées ARP, {i['fdb']} adresses MAC")
                nb, st = ex.get("neighbors") or [], ex.get("neighbors_status")
                if nb:
                    self.add_row("Voisins", "\n".join(
                        f"{n.get('name') or n.get('chassis') or n.get('src', '')}  ·  {n.get('port', '')}"
                        + (f"  ·  VLAN {n['vlan']}" if n.get("vlan") else "") + f"  ({n['proto']})" for n in nb))
                elif st == "refusé":
                    self.add_row("Voisins", "LLDP/CDP : droits insuffisants (voir le README).")
                elif st == "ok":
                    self.add_row("Voisins", "Aucun voisin LLDP/CDP annoncé.")
            else:
                self.add_row("", "Lancez un scan pour cartographier le réseau auquel vous êtes connecté.")

    # ---------- divers ----------
    def toggle_theme(self, light=None):
        light = self.act_theme.isChecked()
        self.apply_theme("light" if light else "dark")
        self.settings.setValue("theme", "light" if light else "dark")

    def apply_theme(self, name):
        T.update(THEMES[name])
        QApplication.instance().setStyleSheet(make_style())
        if self.devices:
            self.rebuild()
        self.refresh_panel(); self.view.viewport().update()

    def update_netlabel(self):
        n = len(self.targets)
        self.net_btn.setText(f"Réseaux ({n + 1})" if n else "Réseaux…")
        if self.network:
            vlan = f"  ·  VLAN {self.network['vlan']}" if self.network.get("vlan") else ""
            extra = f"  ·  +{n} autre(s) réseau(x)" if n else ""
            gw = f"  ·  passerelle {self.network['gateway']}" if self.network.get("gateway") else "  ·  sans passerelle"
            kind = f" ({networks.LINK_LABELS.get(self.network.get('kind'), '')})" if self.network.get("kind") else ""
            self.netlabel.setText(f"  {self.network['cidr']}{vlan}{gw}  ·  {self.network['iface']}{kind}{extra}")

    def open_networks(self):
        try:
            local = local_network()["cidr"]
        except (RuntimeError, OSError):
            local = None
        dlg = NetworksDialog(local, self.targets, self.snmp, self)
        if dlg.exec():
            self.targets, self.snmp = dlg.selected(), dlg.snmp_sources()
            self.settings.setValue("targets", json.dumps(self.targets))
            self.settings.setValue("snmp", json.dumps(self.snmp))
            self.update_netlabel()
            self.status.setText("Plages mises à jour : relancez le scan pour les prendre en compte.")

    def current_device(self):
        return next((x for x in self.devices if dkey(x) == self.selected), None)

    def table_device(self, row):
        it = self.table.item(row, 0) if row >= 0 else None
        return next((x for x in self.devices if it and dkey(x) == it.data(KEY_ROLE)), None)

    def device_menu(self, dev, pos):
        if not dev or dev.get("virtual"):
            return
        menu = QMenu(self)
        menu.addAction("Modifier le nom / le type…", lambda: self.edit_device(dev))
        menu.addAction("Retirer la confiance" if dev.get("trusted") else "Marquer comme appareil de confiance",
                       lambda: self.toggle_trust(dev))
        menu.addAction("Créer une règle de détection…", lambda: self.create_rule(dev))
        if any(d is not dev and not d.get("virtual") and d.get("online", True) != dev.get("online", True) for d in self.devices):
            menu.addAction("Fusionner avec un appareil hors ligne…" if dev.get("online", True) else "Fusionner dans un appareil en ligne…",
                           lambda: self.open_merge(dev))
        if not dev.get("online", True):
            menu.addAction("Oublier cet appareil", lambda: self.forget_device(dev))
        if dev.get("custom"):
            menu.addAction("Rétablir la détection automatique", lambda: self.reset_device(dev))
        menu.exec(pos.toPoint() if hasattr(pos, "toPoint") else pos)

    def edit_device(self, dev):
        if not dev or dev.get("virtual"):
            return
        dlg = EditDialog(dev, self)
        if dlg.exec():
            name, kind = dlg.values()
            self.commit_override(dev, name, kind)

    def reset_device(self, dev):
        self.commit_override(dev, None, None)

    def commit_override(self, dev, name, kind):
        try:
            data = store.set_override(dev, name, kind)
        except OSError as e:
            QMessageBox.warning(self, "Panther", f"Impossible d'enregistrer le réglage :\n{e}")
            return
        store.apply(dev, data)
        self.selected = dkey(dev)
        self.rebuild(); self.refresh_panel()
        self.status.setText("Réglage enregistré" if (name or kind) else "Détection automatique rétablie")

    def export(self, fmt):
        if not self.devices:
            QMessageBox.information(self, "Export", "Aucun résultat à exporter : lancez d'abord un scan.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter", f"panther-scan.{fmt}", f"*.{fmt}")
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            if fmt == "json":
                json.dump(self.devices, f, indent=2, ensure_ascii=False)
            else:
                w = csv.writer(f)
                w.writerow(["ip", "nom", "type", "mac", "fabricant", "os", "services"])
                for d in self.devices:
                    w.writerow([d["ip"], d["hostname"], LABELS.get(d["type"], ""), d["mac"], d["vendor"], d["os"], " ".join(d["services"])])
        self.status.setText(f"Exporté : {os.path.basename(path)}")


def main():
    fingerprint.load_extra_oui(os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.txt"))
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("Panther")
    app.setDesktopFileName("panther")
    app.setWindowIcon(QIcon(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "panther.svg")))
    w = Main()
    theme = w.settings.value("theme", "dark")
    w.act_theme.setChecked(theme == "light")
    T.update(THEMES["light" if theme == "light" else "dark"])
    app.setStyleSheet(make_style())
    w.refresh_panel()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
