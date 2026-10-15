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
from PyQt6.QtGui import (QAction, QActionGroup, QColor, QDesktopServices, QFont, QGuiApplication, QFontMetrics, QIcon, QImage, QPainter, QPainterPath, QPen,
                         QPixmap)
from PyQt6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QMenu, QFormLayout, QFrame,
                             QGraphicsItem, QGraphicsLineItem, QGraphicsPathItem, QGraphicsScene,
                             QGraphicsView, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                             QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
                             QScrollArea, QSizePolicy, QSpinBox, QSplitter, QStackedWidget, QSystemTrayIcon, QTableWidget, QTableWidgetItem,
                             QTabWidget, QToolBar, QVBoxLayout, QWidget)

from . import alerts
from . import compare
from . import exporter
from . import fingerprint
from . import history
from . import identity
from . import layout
from . import models
from . import networks
from . import ouiupdate
from . import privacy
from . import reportpdf
from . import rules
from . import schedule
from . import secrets
from . import security
from . import store
from . import wol
from . import i18n
from .i18n import N_, TrDict, plural, tr
from .labels import TYPE_LABELS
from .scanner import Scanner, local_network, reclassify

log = logging.getLogger("panther.gui")
LABELS = TYPE_LABELS

THEMES = {
    "dark": dict(bg="#1b1c1f", surface="#222428", panel="#26282d", border="#383b42",
                 fg="#d9dce1", mut="#9397a1", acc="#5895ff", acc_bg="#243652", on_acc="#0b1020",
                 grid="#2b2d32", hover="#2d3036", warn="#d9a441", ok="#4caf7d", bad="#e27878"),
    "light": dict(bg="#f1f2f4", surface="#ffffff", panel="#ffffff", border="#d2d5db",
                  fg="#1f2329", mut="#666c77", acc="#2160eb", acc_bg="#dce7fd", on_acc="#ffffff",
                  grid="#dfe1e6", hover="#eceef1", warn="#926119", ok="#2b7a53", bad="#c53030"),
    # contraste élevé : noir et blanc, contours francs, couleurs vives (rapports de contraste ≥ 7 : WCAG AAA)
    "contrast": dict(bg="#000000", surface="#0a0a0a", panel="#0f0f0f", border="#ffffff",
                     fg="#ffffff", mut="#e0e0e0", acc="#66ccff", acc_bg="#00405c", on_acc="#000000",
                     grid="#262626", hover="#242424", warn="#ffd34d", ok="#6dffa5", bad="#ff8080"),
}
THEME_MODES = ("auto", "dark", "light", "contrast")
TEXT_SIZES = (("small", N_("Petit"), 0.9), ("normal", N_("Normal"), 1.0), ("large", N_("Grand"), 1.2), ("xlarge", N_("Très grand"), 1.4))
FONT_SCALE = 1.0  # taille du texte choisie (menu Affichage) : appliquée à la police de l'application et à celles dessinées sur la carte


def fs(pt):
    """Taille de police (points) mise à l'échelle du réglage « taille du texte »."""
    return pt * FONT_SCALE


_base_font = None


def set_text_scale(scale):
    """Applique la taille du texte : police de l'application + polices dessinées sur la carte (`fs`)."""
    global FONT_SCALE, _base_font
    app = QApplication.instance()
    if _base_font is None:
        _base_font = QFont(app.font())
    FONT_SCALE = scale
    f = QFont(_base_font)
    f.setPointSizeF((_base_font.pointSizeF() if _base_font.pointSizeF() > 0 else 10.0) * scale)
    app.setFont(f)


def text_scale_of(key):
    return next((k_scale for k, _l, k_scale in TEXT_SIZES if k == key), 1.0)


def system_theme():
    """« light » ou « dark » selon le thème du système (Qt ≥ 6.5) ; « dark » si le système ne le dit pas."""
    try:
        scheme = QGuiApplication.styleHints().colorScheme()
    except (AttributeError, RuntimeError):
        return "dark"
    return "light" if scheme == Qt.ColorScheme.Light else "dark"


def resolve_theme(mode):
    """Nom d'un thème de THEMES pour un réglage (« auto » suit le système)."""
    return system_theme() if mode == "auto" else mode if mode in THEMES else "dark"


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
QPushButton:focus, QCheckBox:focus, QRadioButton:focus {{ border: 2px solid {T['acc']}; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border: 2px solid {T['mut']}; border-radius: 4px; background: {T['surface']}; }}
QCheckBox::indicator:checked {{ background: {T['acc']}; border-color: {T['acc']}; }}
QCheckBox::indicator:disabled {{ border-color: {T['border']}; }}
QTabBar::tab:focus {{ border: 1px solid {T['acc']}; }}
QTableWidget:focus, QListWidget:focus, QPlainTextEdit:focus {{ border: 1px solid {T['acc']}; }}
QMenuBar::item:focus {{ background: {T['hover']}; border: 1px solid {T['acc']}; }}
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
QPushButton#primary {{ background: {T['acc']}; border-color: {T['acc']}; color: {T['on_acc']}; font-weight: 600; }}
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
QLabel#title {{ font-size: {16 * FONT_SCALE:.0f}px; font-weight: 600; }}
QLabel#section {{ color: {T['mut']}; font-size: {11 * FONT_SCALE:.0f}px; font-weight: 600; }}
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


EVENT_LABELS = TrDict({"first_seen": N_("Nouvel appareil"), "online": N_("De retour en ligne"), "offline": N_("Hors ligne"),
                       "exposure": N_("Nouvelle exposition"), "exposure_fixed": N_("Exposition corrigée"), "merged": N_("Appareils fusionnés"),
                       "ip_changed": N_("Changement d'adresse IP"), "trusted": N_("Marqué de confiance"), "untrusted": N_("Confiance retirée")})


SECURITY_INFO = N_(
    "L'analyse de sécurité est en lecture seule.\n\n"
    "Elle regarde les ports ouverts et les bannières, et envoie UNE requête de lecture sans identifiant à "
    "certains services pour savoir s'ils répondent sans mot de passe : PING (Redis), version (Memcached), "
    "GET / (Elasticsearch), GET /version (Docker), DESCRIBE (flux vidéo RTSP).\n\n"
    "Elle n'essaie aucun identifiant, ne devine aucun mot de passe et n'exploite aucune faille.\n\n"
    "À n'activer que sur des réseaux dont vous êtes responsable ou que vous avez l'autorisation d'analyser.")


def sev_color(sev):
    return T["bad"] if security.RANK.get(sev, 0) >= security.RANK["élevé"] else T["warn"] if sev == "moyen" else T["mut"]


def human_size(n):
    units = ("B", "KB", "MB", "GB") if i18n.language() == "en" else ("o", "Ko", "Mo", "Go")
    for i, unit in enumerate(units):
        if n < 1024 or i == len(units) - 1:
            return f"{n:.0f} {unit}" if i == 0 else f"{n:.1f} {unit}"
        n /= 1024


def tip(text):
    """Infobulle sûre : Qt affiche en HTML tout texte qui y ressemble, or noms, bannières et certificats viennent du réseau."""
    return "<div style='white-space:pre-wrap'>" + html.escape(str(text), quote=False) + "</div>"


def snmp_secret(host):
    return f"snmp-community:{host}"


def log_path():
    from . import log as _log
    return _log.PATH


def when(ts):
    return time.strftime(i18n.when_format()[0], time.localtime(ts)) if ts else ""


def when_short(ts):
    return time.strftime("%m-%d %H:%M" if i18n.language() == "en" else "%d/%m %H:%M", time.localtime(ts)) if ts else ""


class PresenceBar(QWidget):
    """Présence sur les derniers scans : une case par scan, la plus récente à droite."""

    def __init__(self, flags, parent=None):
        super().__init__(parent)
        self.flags = flags
        self.setFixedHeight(18)
        self.setMinimumWidth(10 * len(flags))
        self.setToolTip(tr("Vu dans {flags_total} des {flags_count} derniers scans (le plus récent est à droite)", flags_total=sum(flags), flags_count=len(flags)))

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
    return time.strftime("%H:%M" if time.strftime("%Y%m%d", t) == time.strftime("%Y%m%d") else "%m-%d" if i18n.language() == "en" else "%d/%m", t)


def status_text(d):
    if not d.get("online", True):
        return tr("Hors ligne (vu {seen})", seen=seen_label(d.get('last_seen')))
    return tr("Nouveau") if d.get("new") else tr("En ligne")


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
        self.setWindowTitle(tr("Modifier l'appareil"))
        self.setMinimumWidth(380)
        auto = dev.get("auto_type", dev["type"])
        self.name = QLineEdit(dev["hostname"] if dev.get("custom") and "auto_hostname" in dev else "")
        self.name.setPlaceholderText(dev.get("auto_hostname", dev["hostname"]) or dev["ip"])
        self.name.setMaxLength(60)
        self.kind = QComboBox()
        self.kind.addItem(tr("Détection automatique ({labels_label})", labels_label=LABELS.get(auto, '')), None)
        for k in fingerprint.KINDS:
            self.kind.addItem(QIcon(type_pixmap(k, 20)), LABELS[k], k)
        if "auto_type" in dev:
            self.kind.setCurrentIndex(self.kind.findData(dev["type"]))
        form = QFormLayout()
        form.addRow(tr("Nom"), self.name)
        form.addRow(tr("Type"), self.kind)
        note = QLabel(tr("Mémorisé pour l'adresse MAC {mac}.", mac=dev['mac'] or dev['ip']))
        note.setObjectName("muted")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Enregistrer"))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
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
        f = QFont(); f.setPointSizeF(fs(9)); f.setBold(True); p.setFont(f)
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
        self.setToolTip(tip(text))
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
        self.setWindowTitle(tr("Comparer deux scans"))
        self.setMinimumSize(780, 540)
        self.a, self.b = QComboBox(), QComboBox()
        for sc in scans:
            label = tr("{when}  ·  {depth}  ·  {count} appareil(s)", when=when(sc['ts']), depth=sc['depth'] or 'normal', count=sc['count'])
            self.a.addItem(label, sc["id"]); self.b.addItem(label, sc["id"])
        self.a.setCurrentIndex(min(1, len(scans) - 1)); self.b.setCurrentIndex(0)
        form = QFormLayout(); form.addRow(tr("Scan de départ"), self.a); form.addRow(tr("Scan d'arrivée"), self.b)
        self.summary = QLabel(); self.summary.setWordWrap(True)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([tr("Changement"), tr("Appareil"), tr("Adresse IP"), tr("Détail")])
        self.table.setAlternatingRowColors(True); self.table.setShowGrid(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide(); self.table.verticalHeader().setDefaultSectionSize(32)
        self.table.horizontalHeader().setStretchLastSection(True)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.button(QDialogButtonBox.StandardButton.Close).setText(tr("Fermer")); close.rejected.connect(self.reject)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(12)
        lay.addLayout(form); lay.addWidget(self.summary); lay.addWidget(self.table, 1); lay.addWidget(close)
        self.a.currentIndexChanged.connect(self.refresh); self.b.currentIndexChanged.connect(self.refresh)
        self.refresh()

    def refresh(self):
        t = self.table
        t.setRowCount(0)
        ia, ib = self.a.currentData(), self.b.currentData()
        if ia == ib:
            self.summary.setText(tr("Choisissez deux scans différents.")); return
        ra, rb = history.load_snapshot(ia), history.load_snapshot(ib)
        if ra is None or rb is None:
            self.summary.setText(tr("Instantané indisponible pour l'un des scans.")); return
        res = compare.compare(ra, rb)
        rows = [("Nouveau", T["ok"], r["name"] or r["ip"], r["ip"], "") for r in res["new"]]
        rows += [(tr("Modifié"), T["acc"], c["rec"]["name"] or c["rec"]["ip"], c["rec"]["ip"],
                  "  ;  ".join(compare.format_change(*ch) for ch in c["changes"])) for c in res["changed"]]
        rows += [(tr("Disparu"), T["warn"], r["name"] or r["ip"], r["ip"], "") for r in res["gone"]]
        t.setRowCount(len(rows))
        for r, (kind, col, name, ip, detail) in enumerate(rows):
            for c, v in enumerate((kind, name, ip, detail)):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setForeground(QColor(col)); f = it.font(); f.setBold(True); it.setFont(f)
                if c == 3:
                    it.setForeground(QColor(T["mut"])); it.setToolTip(tip(v))
                t.setItem(r, c, it)
        for c, w in enumerate((110, 200, 130)):
            t.setColumnWidth(c, w)
        self.summary.setText(tr("{new}  ·  {gone}  ·  {changed}  ·  {same} inchangé(s)", new=plural(len(res['new']), 'nouveau', 'nouveaux'), gone=plural(len(res['gone']), 'disparu', 'disparus'), changed=plural(len(res['changed']), 'modifié', 'modifiés'), same=res['same']))


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
                               tr("{hostname}  ·  {ip}", hostname=d['hostname'] or d['ip'], ip=d['ip']) + ("" if d.get("online", True) else tr("  ·  hors ligne, vu {seen_label}", seen_label=seen_label(d.get('last_seen')))))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Fusionner"))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(14)
        lay.addWidget(info); lay.addWidget(self.combo); lay.addWidget(buttons)

    def chosen(self):
        return self.candidates[self.combo.currentIndex()]


class DuplicatesDialog(QDialog):
    """Doublons probables détectés après un scan : à confirmer un par un."""

    def __init__(self, suggestions, merge_cb, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("Doublons probables"))
        self.setMinimumSize(780, 360)
        self.items, self.merge_cb = list(suggestions), merge_cb
        info = QLabel(tr("Un appareil récent ressemble à un appareil hors ligne (même nom, même type, adresse MAC aléatoire). "
                         "Si c'est le même, fusionnez-les : l'historique, la confiance et les noms seront regroupés."))
        info.setWordWrap(True); info.setObjectName("muted")
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels([tr("Appareil actuel"), tr("Ressemble à (hors ligne)"), tr("Pourquoi")])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide(); self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setShowGrid(False); self.table.setAlternatingRowColors(True)
        self.merge_btn = QPushButton(tr("Fusionner la sélection")); self.merge_btn.setObjectName("primary")
        self.merge_btn.clicked.connect(self.merge_selected)
        close = QPushButton(tr("Fermer")); close.clicked.connect(self.accept)
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


class MetaDialog(QDialog):
    """Étiquettes, note et groupe d'un appareil (enregistrés avec son historique, suivent les fusions)."""

    def __init__(self, dev, groups, parent=None, count=1):
        super().__init__(parent)
        self.multi = count > 1  # plusieurs appareils : on ajoute des étiquettes et on pose un groupe, sans toucher aux notes
        self.setWindowTitle(tr("Étiquettes et groupe : {count} appareils", count=count) if self.multi
                            else tr("Étiquettes et notes : {hostname}", hostname=dev['hostname'] or dev['ip']))
        self.setMinimumWidth(500)
        self.group = QComboBox(); self.group.setEditable(True)
        self.group.addItems([""] + list(groups))
        self.group.setCurrentText("" if self.multi else dev.get("group", ""))
        self.group.lineEdit().setPlaceholderText(tr("ex. Salon, Bureau, Invités…"))
        self.tags = QLineEdit("" if self.multi else ", ".join(dev.get("tags", [])))
        self.tags.setPlaceholderText(tr("étiquettes à ajouter à chacun, séparées par des virgules") if self.multi
                                     else tr("ex. enfants, domotique, à surveiller"))
        self.note = QPlainTextEdit(dev.get("note", ""))
        self.note.setPlaceholderText(tr("Notes libres : emplacement, propriétaire, numéro de série…"))
        self.note.setMinimumHeight(110)
        form = QFormLayout()
        form.addRow(tr("Groupe"), self.group); form.addRow(tr("Étiquettes"), self.tags)
        if not self.multi:
            form.addRow(tr("Notes"), self.note)
        hint = QLabel(tr("Les étiquettes saisies s'ajoutent à celles de chaque appareil ; un groupe vide laisse le groupe actuel."))\
            if self.multi else QLabel(tr("Filtrez ensuite avec « tag:enfants » ou « groupe:salon » dans la barre de recherche. Jusqu'à "
                         "{max_tags} étiquettes de {max_tag_len} caractères.", max_tags=history.MAX_TAGS, max_tag_len=history.MAX_TAG_LEN))
        hint.setWordWrap(True); hint.setObjectName("muted")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Enregistrer"))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(12)
        lay.addLayout(form); lay.addWidget(hint); lay.addWidget(buttons)

    def values(self):
        return self.group.currentText(), self.tags.text(), None if self.multi else self.note.toPlainText()


class RuleFromDeviceDialog(QDialog):
    """Crée une règle de détection à partir d'un appareil : on choisit le type et les critères à retenir."""

    CRITERIA = (("hostname", N_("Nom de l'appareil")), ("vendor", N_("Fabricant")), ("ports", N_("Ports ouverts")),
                ("mdns", N_("Services annoncés (mDNS)")), ("mac", N_("Préfixe de l'adresse MAC (fabricant)")))

    def __init__(self, dev, parent=None):
        super().__init__(parent)
        self.dev = dev
        self.setWindowTitle(tr("Créer une règle de détection"))
        self.setMinimumWidth(520)
        self.kind = QComboBox()
        for k in fingerprint.KINDS:
            self.kind.addItem(QIcon(type_pixmap(k, 20)), LABELS[k], k)
        cur = dev.get("auto_type", dev["type"])
        self.kind.setCurrentIndex(max(self.kind.findData(cur if cur != "unknown" else "iot"), 0))
        self.name = QLineEdit(f"{dev['hostname'] or dev['ip']}")
        self.boxes = {}
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(12)
        intro = QLabel(tr("Quand un appareil ressemble à « {hostname} », Panther le classera dans le type choisi. Cochez ce "
                          "qui doit être commun (plus de critères = règle plus précise).", hostname=dev['hostname'] or dev['ip']))
        intro.setWordWrap(True); intro.setObjectName("muted")
        form = QFormLayout(); form.addRow(tr("Type"), self.kind); form.addRow(tr("Nom de la règle"), self.name)
        lay.addWidget(intro); lay.addLayout(form)
        for key, label in self.CRITERIA:
            b = QCheckBox(tr(label)); b.setChecked(key in ("hostname", "ports"))
            b.stateChanged.connect(self.preview); self.boxes[key] = b; lay.addWidget(b)
        self.kind.currentIndexChanged.connect(self.preview); self.name.textChanged.connect(self.preview)
        self.view = QLabel(); self.view.setWordWrap(True); self.view.setTextFormat(Qt.TextFormat.PlainText)
        self.view.setObjectName("muted")
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Enregistrer la règle"))
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
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
            self.view.setText(tr("Règle : ") + rules.describe(r))
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
        except rules.RuleError as e:
            self.view.setText(str(e))
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)


class RulesDialog(QDialog):
    """Règles de détection personnalisées : liste, avertissements, import / export, édition du fichier."""

    def __init__(self, devices, on_change, parent=None):
        super().__init__(parent)
        self.devices, self.on_change = devices, on_change
        self.setWindowTitle(tr("Règles de détection personnalisées"))
        self.setMinimumSize(720, 520)
        self.info = QLabel(); self.info.setWordWrap(True); self.info.setTextFormat(Qt.TextFormat.PlainText); self.info.setObjectName("muted")
        self.warn = QLabel(); self.warn.setWordWrap(True); self.warn.setTextFormat(Qt.TextFormat.PlainText)
        self.warn.setStyleSheet(f"color: {T['warn']};")
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([tr("Règle"), tr("Type"), tr("Conditions"), tr("Appareils")])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide(); self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setShowGrid(False); self.table.setAlternatingRowColors(True)
        btns = []
        for text, fn in ((tr("Modifier le fichier"), self.open_file), (tr("Recharger"), self.reload), (tr("Créer un exemple"), self.example),
                         (tr("Supprimer la règle"), self.remove), (tr("Exporter…"), self.export), (tr("Importer…"), self.import_)):
            b = QPushButton(text); b.clicked.connect(fn); btns.append(b)
        self.example_btn = btns[2]
        row = QHBoxLayout()
        for b in btns:
            row.addWidget(b)
        close = QPushButton(tr("Fermer")); close.setObjectName("primary"); close.clicked.connect(self.accept)
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
        self.info.setText(tr("Fichier : {path}\n{rules} · {models}. Chaque règle ajoute des points au type indiqué ; la détection "
                             "intégrée garde son rôle (\"force\": true impose le type).", path=rules.PATH, rules=plural(len(rs.rules), 'règle valide', 'règles valides'), models=plural(len(rs.models), 'modèle personnalisé', 'modèles personnalisés')))
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
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'écrire le fichier :\n{e}", e=e)); return
        self.reload()

    def remove(self):
        name = self.selected_name()
        if name and QMessageBox.question(self, tr("Supprimer"), tr("Supprimer la règle « {name} » ?", name=name)) == QMessageBox.StandardButton.Yes:
            try:
                rules.remove_rule(name)
            except (OSError, rules.RuleError) as e:
                QMessageBox.warning(self, tr("Panther"), tr("Impossible de modifier le fichier :\n{e}", e=e)); return
            self.reload()

    def export(self):
        path, _ = QFileDialog.getSaveFileName(self, tr("Exporter les règles"), "regles-panther.json", "JSON (*.json)")
        if path:
            try:
                rules.export_to(path)
            except (OSError, rules.RuleError) as e:
                QMessageBox.warning(self, tr("Panther"), tr("Export impossible :\n{e}", e=e))

    def import_(self):
        path, _ = QFileDialog.getOpenFileName(self, tr("Importer des règles"), "", "JSON (*.json)")
        if not path:
            return
        try:
            added, warnings = rules.import_from(path)
        except (OSError, rules.RuleError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Import impossible :\n{e}", e=e)); return
        QMessageBox.information(self, tr("Import"), tr("{count}.", count=plural(added, 'règle importée', 'règles importées'))
                                + (tr("\n\nÉcartées :\n") + "\n".join(warnings) if warnings else ""))
        self.reload()


class DataDialog(QDialog):
    """Taille de l'historique, durée de conservation et purge."""

    def __init__(self, scans_days, events_days, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("Historique et données"))
        self.setMinimumWidth(500)
        self.info = QLabel(); self.info.setTextFormat(Qt.TextFormat.PlainText)
        self.sp_scans, self.sp_events = QSpinBox(), QSpinBox()
        for sp, v in ((self.sp_scans, scans_days), (self.sp_events, events_days)):
            sp.setRange(7, 3650); sp.setValue(v); sp.setSuffix(tr(" jours"))
        form = QFormLayout()
        form.addRow(tr("Conserver la présence détaillée"), self.sp_scans)
        form.addRow(tr("Conserver le journal"), self.sp_events)
        note = QLabel(tr("La purge supprime aussi les instantanés qui servent à comparer deux scans. Les appareils connus, "
                         "leur confiance et leurs noms sont conservés."))
        note.setWordWrap(True); note.setObjectName("muted")
        self.result = QLabel(""); self.result.setObjectName("muted")
        purge = QPushButton(tr("Purger maintenant")); purge.clicked.connect(self.purge)
        self.erase_names = QCheckBox(tr("Effacer aussi les noms et types choisis à la main")); self.erase_names.setChecked(True)
        self.erase_log = QCheckBox(tr("Effacer aussi le journal d'erreurs (adresses et noms d'appareils)")); self.erase_log.setChecked(True)
        erase = QPushButton(tr("Tout effacer…")); erase.clicked.connect(self.erase_everything)
        close = QPushButton(tr("Enregistrer et fermer")); close.setObjectName("primary"); close.clicked.connect(self.accept)
        row = QHBoxLayout(); row.addWidget(purge); row.addStretch(1); row.addWidget(close)
        self.erased = False
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(14)
        for w in (self.info,):
            lay.addWidget(w)
        lay.addLayout(form); lay.addWidget(note); lay.addWidget(self.result); lay.addLayout(row)
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        danger = QLabel(tr("Effacer l'historique supprime les appareils connus, la présence, le journal, les comparaisons, les "
                           "positions de la carte, les étiquettes et les alias. Les règles de détection, les alertes et les "
                           "secrets ne sont pas touchés."))
        danger.setWordWrap(True); danger.setObjectName("muted")
        lay.addWidget(sep); lay.addWidget(danger); lay.addWidget(self.erase_names); lay.addWidget(self.erase_log)
        erow = QHBoxLayout(); erow.addStretch(1); erow.addWidget(erase); lay.addLayout(erow)
        self.refresh()

    def erase_everything(self):
        if QMessageBox.question(self, tr("Tout effacer ?"), tr("Supprimer définitivement tout l'historique de Panther ?\n\nCette action est irréversible.")) \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            n = history.erase_all()
        except (sqlite3.Error, OSError) as e:
            self.result.setText(tr("Effacement impossible : {e}", e=e)); return
        extra = []
        if self.erase_names.isChecked():
            extra.append(plural(store.erase(), "nom choisi effacé", "noms choisis effacés"))
        if self.erase_log.isChecked():
            extra.append(tr("journal vidé ({size})", size=human_size(privacy.erase_file(log_path(), backups=2))))
        self.erased = True
        self.result.setText(f"{plural(n, 'ligne supprimée', 'lignes supprimées')}" + ("  ·  " + "  ·  ".join(extra) if extra else ""))
        self.refresh()

    def refresh(self):
        try:
            st = history.db_stats()
        except (sqlite3.Error, OSError) as e:
            self.info.setText(tr("Historique indisponible : {e}", e=e)); return
        oldest = tr("  (le plus ancien : {when})", when=when(st['oldest_scan'])) if st["oldest_scan"] else ""
        self.info.setText(tr("Fichier : {path}\nTaille : {human_size}\nAppareils connus : {devices}\nScans conservés : "
                             "{scans}{oldest}\nÉvénements du journal : {events}", path=history.PATH, human_size=human_size(st['size']), devices=st['devices'], scans=st['scans'], oldest=oldest, events=st['events']))

    def purge(self):
        try:
            r = history.purge(self.sp_scans.value(), self.sp_events.value())
        except (sqlite3.Error, OSError) as e:
            self.result.setText(tr("Purge impossible : {e}", e=e)); return
        self.result.setText(tr("{scans}, {events}.", scans=plural(r['scans'], 'scan supprimé', 'scans supprimés'), events=plural(r['events'], 'événement supprimé', 'événements supprimés')))
        self.refresh()

    def values(self):
        return self.sp_scans.value(), self.sp_events.value()


class AlertWorker(QThread):
    """Envoie les alertes en arrière-plan (un serveur lent ne doit jamais figer la fenêtre)."""
    finished_with = pyqtSignal(list)

    def __init__(self, cfg, events, parent=None, webhook_url=None, smtp_password=None):
        super().__init__(parent)
        self.cfg, self.events, self.webhook_url, self.smtp_password = cfg, events, webhook_url, smtp_password

    def run(self):
        try:
            res = alerts.dispatch(self.cfg, self.events, webhook_url=self.webhook_url, smtp_password=self.smtp_password)
        except Exception as e:  # noqa: BLE001 - jamais d'exception qui remonte d'un thread d'alerte
            log.exception("Envoi des alertes")
            res = [("alertes", False, str(e))]
        self.finished_with.emit(res)


class AlertsDialog(QDialog):
    """Réglages des alertes : événements, webhook, e-mail. Les secrets vont dans le trousseau, pas dans le fichier de réglages."""

    FORMAT_LABELS = (("generic", N_("JSON générique (Home Assistant, scripts…)")), ("discord", "Discord"), ("slack", "Slack"), ("ntfy", "ntfy"))

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("Alertes : webhook et e-mail"))
        self.setMinimumWidth(600)
        cfg = alerts.load()
        self.test_worker = None
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(10)
        self.enabled = QCheckBox(tr("Activer les alertes")); self.enabled.setChecked(cfg["enabled"])
        lay.addWidget(self.enabled)
        ev = cfg["events"]
        self.ev_new = QCheckBox(tr("Nouvel appareil sur le réseau")); self.ev_new.setChecked(ev["new_device"])
        self.ev_exp = QCheckBox(tr("Nouvelle exposition de sécurité, à partir de la gravité :")); self.ev_exp.setChecked(ev["new_exposure"])
        self.sev = QComboBox()
        for s in ("moyen", "élevé", "critique"):
            self.sev.addItem(security.LABELS[s], s)
        self.sev.setCurrentIndex(max(self.sev.findData(ev["exposure_min"]), 0))
        self.ev_off = QCheckBox(tr("Appareil de confiance passé hors ligne")); self.ev_off.setChecked(ev["trusted_offline"])
        self.auto_only = QCheckBox(tr("Seulement pour les scans automatiques (pas quand je scanne moi-même)")); self.auto_only.setChecked(ev["auto_only"])
        row = QHBoxLayout(); row.addWidget(self.ev_exp); row.addWidget(self.sev); row.addStretch(1)
        for w in (self.ev_new,):
            lay.addWidget(w)
        lay.addLayout(row); lay.addWidget(self.ev_off); lay.addWidget(self.auto_only)
        sep = QFrame(); sep.setObjectName("sep"); lay.addWidget(sep)
        wh = cfg["webhook"]
        self.wh_on = QCheckBox(tr("Envoyer par webhook")); self.wh_on.setChecked(wh["enabled"])
        self.wh_fmt = QComboBox()
        for k, label in self.FORMAT_LABELS:
            label = tr(label)
            self.wh_fmt.addItem(label, k)
        self.wh_fmt.setCurrentIndex(max(self.wh_fmt.findData(wh["format"]), 0))
        self.wh_url = QLineEdit(); self.wh_url.setEchoMode(QLineEdit.EchoMode.Password)
        self.wh_url.setPlaceholderText(tr("URL du webhook (déjà enregistrée : laisser vide pour la garder)") if secrets.get(alerts.SECRET_WEBHOOK) else tr("https://…"))
        wf = QFormLayout(); wf.addRow(tr("Format"), self.wh_fmt); wf.addRow(tr("URL"), self.wh_url)
        lay.addWidget(self.wh_on); lay.addLayout(wf)
        em = cfg["email"]
        self.em_on = QCheckBox(tr("Envoyer par e-mail (SMTP)")); self.em_on.setChecked(em["enabled"])
        self.em_host = QLineEdit(em["host"]); self.em_port = QSpinBox(); self.em_port.setRange(1, 65535); self.em_port.setValue(em["port"])
        self.em_sec = QComboBox()
        for k, label in (("starttls", "STARTTLS (587)"), ("ssl", "SSL/TLS (465)"), ("none", tr("Aucune (réseau de confiance uniquement)"))):
            self.em_sec.addItem(label, k)
        self.em_sec.setCurrentIndex(max(self.em_sec.findData(em["security"]), 0))
        self.em_user = QLineEdit(em["user"])
        self.em_pw = QLineEdit(); self.em_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.em_pw.setPlaceholderText(tr("Mot de passe (déjà enregistré : laisser vide pour le garder)") if secrets.get(alerts.SECRET_SMTP) else tr("Mot de passe"))
        self.em_from = QLineEdit(em["from"]); self.em_to = QLineEdit(", ".join(em["to"]))
        ef = QFormLayout()
        ef.addRow(tr("Serveur"), self.em_host); ef.addRow(tr("Port"), self.em_port); ef.addRow(tr("Sécurité"), self.em_sec); ef.addRow(tr("Identifiant"), self.em_user)
        ef.addRow(tr("Mot de passe"), self.em_pw); ef.addRow(tr("Expéditeur"), self.em_from); ef.addRow(tr("Destinataire(s)"), self.em_to)
        lay.addWidget(self.em_on); lay.addLayout(ef)
        note = QLabel(tr("Secrets (URL du webhook, mot de passe) : {backend}, jamais dans le fichier de réglages. Les "
                         "messages contiennent les noms et adresses de vos appareils : ne les envoyez qu'à un service de "
                         "confiance.", backend=secrets.backend()))
        note.setWordWrap(True); note.setObjectName("muted")
        self.result = QLabel(""); self.result.setWordWrap(True); self.result.setTextFormat(Qt.TextFormat.PlainText)
        test = QPushButton(tr("Envoyer un test")); test.clicked.connect(self.send_test)
        clear = QPushButton(tr("Effacer les secrets")); clear.clicked.connect(self.clear_secrets)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Enregistrer")); buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject)
        brow = QHBoxLayout(); brow.addWidget(test); brow.addWidget(clear); brow.addStretch(1); brow.addWidget(buttons)
        lay.addWidget(note); lay.addWidget(self.result); lay.addLayout(brow)

    def collect(self):
        """Réglages saisis (validés). Lève alerts.AlertError si une adresse est invalide."""
        return alerts.validate({"enabled": self.enabled.isChecked(),
                                "events": {"new_device": self.ev_new.isChecked(), "new_exposure": self.ev_exp.isChecked(), "exposure_min": self.sev.currentData(),
                                           "trusted_offline": self.ev_off.isChecked(), "auto_only": self.auto_only.isChecked()},
                                "webhook": {"enabled": self.wh_on.isChecked(), "format": self.wh_fmt.currentData()},
                                "email": {"enabled": self.em_on.isChecked(), "host": self.em_host.text(), "port": self.em_port.value(),
                                          "security": self.em_sec.currentData(), "user": self.em_user.text(), "from": self.em_from.text(), "to": self.em_to.text()}})

    def send_test(self):
        try:
            cfg = self.collect()
        except alerts.AlertError as e:
            self.result.setText(str(e)); return
        cfg["webhook"]["enabled"] = cfg["webhook"]["enabled"] or bool(self.wh_url.text().strip())
        if not (cfg["webhook"]["enabled"] or cfg["email"]["enabled"]):
            self.result.setText(tr("Activez le webhook ou l'e-mail pour envoyer un test.")); return
        self.result.setText(tr("Envoi du test…"))
        self.test_worker = AlertWorker(cfg, alerts.test_message(), self, webhook_url=self.wh_url.text().strip() or None,
                                       smtp_password=self.em_pw.text() or None)
        self.test_worker.finished_with.connect(self.show_result)
        self.test_worker.start()

    def show_result(self, results):
        self.result.setText("\n".join(f"{c} : " + (tr("envoyé") if ok else tr("échec ({err})", err=err)) for c, ok, err in results) or tr("Aucun canal actif."))

    def clear_secrets(self):
        secrets.delete(alerts.SECRET_WEBHOOK); secrets.delete(alerts.SECRET_SMTP)
        self.wh_url.clear(); self.em_pw.clear()
        self.wh_url.setPlaceholderText(tr("https://…")); self.em_pw.setPlaceholderText(tr("Mot de passe"))
        self.result.setText(tr("Secrets effacés."))

    def accept(self):
        try:
            cfg = self.collect()
        except alerts.AlertError as e:
            self.result.setText(str(e)); return
        try:
            alerts.save(cfg)
            if self.wh_url.text().strip():
                secrets.set(alerts.SECRET_WEBHOOK, self.wh_url.text().strip())
            if self.em_pw.text():
                secrets.set(alerts.SECRET_SMTP, self.em_pw.text())
        except OSError as e:
            self.result.setText(tr("Enregistrement impossible : {e}", e=e)); return
        super().accept()


class ReportScheduleDialog(QDialog):
    """Rapport PDF produit automatiquement (tous les jours ou toutes les semaines) dans un dossier."""

    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.main, self.generated = parent, False
        self.setWindowTitle(tr("Rapports planifiés"))
        self.setMinimumWidth(540)
        self.enabled = QCheckBox(tr("Produire un rapport PDF automatiquement")); self.enabled.setChecked(cfg["enabled"])
        self.freq = QComboBox()
        for k, label in schedule.LABELS.items():
            self.freq.addItem(label, k)
        self.freq.setCurrentIndex(max(self.freq.findData(cfg["freq"]), 0))
        self.folder = QLineEdit(cfg["folder"])
        browse = QPushButton(tr("Parcourir…")); browse.clicked.connect(self.browse)
        frow = QHBoxLayout(); frow.addWidget(self.folder, 1); frow.addWidget(browse)
        self.keep = QSpinBox(); self.keep.setRange(1, schedule.MAX_KEEP); self.keep.setValue(cfg["keep"]); self.keep.setSuffix(tr(" rapports"))
        form = QFormLayout()
        form.addRow(tr("Fréquence"), self.freq); form.addRow(tr("Dossier"), frow); form.addRow(tr("Conserver les"), self.keep)
        last = tr("Dernier rapport : {when}", when=when(cfg['last'])) if cfg["last"] else tr("Aucun rapport produit pour l'instant.")
        note = QLabel(last + "\n" + tr("Un rapport n'est produit que si Panther est ouvert et qu'un scan a eu lieu (activez le scan automatique "
                                      "pour qu'il soit à jour). Seuls les fichiers « rapport-panther-….pdf » de ce dossier sont renouvelés : "
                                      "rien d'autre n'y est supprimé."))
        note.setWordWrap(True); note.setObjectName("muted")
        self.result = QLabel(""); self.result.setWordWrap(True); self.result.setTextFormat(Qt.TextFormat.PlainText)
        now_btn = QPushButton(tr("Générer un rapport maintenant")); now_btn.clicked.connect(self.generate_now)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Enregistrer")); buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject)
        row = QHBoxLayout(); row.addWidget(now_btn); row.addStretch(1); row.addWidget(buttons)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(12)
        lay.addWidget(self.enabled); lay.addLayout(form); lay.addWidget(note); lay.addWidget(self.result); lay.addLayout(row)

    def browse(self):
        d = QFileDialog.getExistingDirectory(self, tr("Dossier des rapports"), self.folder.text() or os.path.expanduser("~"))
        if d:
            self.folder.setText(d)

    def values(self):
        return self.enabled.isChecked(), self.freq.currentData(), self.folder.text().strip(), self.keep.value()

    def generate_now(self):
        if not self.main.devices:
            self.result.setText(tr("Aucun résultat : lancez d'abord un scan.")); return
        self.main.save_report_settings(*self.values())  # le rapport utilise les réglages affichés
        try:
            path = self.main.generate_scheduled_report()
        except OSError as e:
            self.result.setText(tr("Impossible : {e}", e=e)); return
        self.generated = True
        self.result.setText(tr("Rapport enregistré : {path}", path=path))


class OuiWorker(QThread):
    """Télécharge et convertit la base des fabricants sans figer la fenêtre."""
    done = pyqtSignal(int)
    failed = pyqtSignal(str)

    def run(self):
        try:
            self.done.emit(ouiupdate.update())
        except ouiupdate.UpdateError as e:
            self.failed.emit(str(e))
        except Exception as e:  # noqa: BLE001
            log.exception("Mise à jour de la base des fabricants")
            self.failed.emit(str(e))


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
        self.setWindowTitle(tr("Réseaux à scanner"))
        self.setMinimumSize(580, 640)
        self.local, self.detector = local_cidr, None
        intro = QLabel(tr("Le réseau local est toujours scanné. Cochez d'autres plages (autres VLAN, sous-réseaux routés) ou "
                          "ajoutez-les à la main. Panther refuse les plages publiques."))
        intro.setWordWrap(True); intro.setObjectName("muted")
        self.list = QListWidget()
        self.edit = QLineEdit(); self.edit.setPlaceholderText(tr("Ajouter une plage, par exemple 192.168.20.0/24"))
        self.edit.returnPressed.connect(self.add_custom)
        add = QPushButton(tr("Ajouter")); add.clicked.connect(self.add_custom)
        row = QHBoxLayout(); row.addWidget(self.edit, 1); row.addWidget(add)
        self.msg = QLabel(""); self.msg.setObjectName("muted"); self.msg.setWordWrap(True)
        self.detect = QPushButton(tr("Détecter les réseaux joignables")); self.detect.clicked.connect(self.start_detect)
        note = QLabel(tr("La détection sonde les passerelles .1 et .254 des plages 192.168.X.0/24 et 10.0.X.0/24 (environ 1 "
                         "000 adresses). Au-delà d'un routeur, les adresses MAC ne sont pas visibles. Ne cochez que des "
                         "réseaux dont vous êtes responsable."))
        note.setWordWrap(True); note.setObjectName("muted")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Enregistrer"))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 16); lay.setSpacing(12)
        for w in (intro, self.list):
            lay.addWidget(w)
        lay.addLayout(row); lay.addWidget(self.msg); lay.addWidget(self.detect); lay.addWidget(note)
        sep = QFrame(); sep.setObjectName("sep"); lay.addWidget(sep)
        snmp_title = QLabel(tr("SNMP (optionnel, lecture seule)")); snmp_title.setObjectName("section")
        snmp_note = QLabel(tr("Interroge un routeur ou un switch que vous désignez : sa table ARP donne les adresses MAC et les "
                              "appareils des autres VLAN, sa table de ports donne le port et le VLAN de chaque appareil."))
        snmp_note.setWordWrap(True); snmp_note.setObjectName("muted")
        self.snmp_host = QLineEdit(); self.snmp_host.setPlaceholderText(tr("IP du routeur / switch"))
        self.snmp_comm = QLineEdit(); self.snmp_comm.setPlaceholderText(tr("Communauté (lecture)"))
        self.snmp_comm.setEchoMode(QLineEdit.EchoMode.Password)
        snmp_add = QPushButton(tr("Ajouter")); snmp_add.clicked.connect(self.add_snmp)
        snmp_del = QPushButton(tr("Retirer")); snmp_del.clicked.connect(self.remove_snmp)
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
        self.snmp_list.addItem(tr("{host}  ·  communauté {dots}", host=src['host'], dots='•' * min(len(src['community']), 8)))

    def add_snmp(self):
        host, comm = self.snmp_host.text().strip(), self.snmp_comm.text().strip()
        try:
            if not ipaddress.ip_address(host).is_private:
                raise ValueError(tr("Seules les adresses privées sont acceptées."))
        except ValueError as e:
            self.msg.setText(str(e) if tr("Seules les adresses privées sont acceptées.") in str(e) else tr("« {host} » n'est pas une adresse IP valide.", host=host)); return
        if not comm:
            self.msg.setText(tr("Indiquez la communauté SNMP en lecture seule.")); return
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
        label = networks.describe(net) + {"local": tr("  (réseau local)"), "découvert": tr("  (détecté)"),
                                           "manuel": tr("  (ajouté)"), "interface": tr("  (autre interface)")}.get(net.get("kind"), "")
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
        self.detect.setEnabled(False); self.detect.setText(tr("Détection en cours…"))
        self.detector = Detector([c for c in [self.local] if c], self)
        self.detector.found.connect(self.on_detected)
        self.detector.start()

    def on_detected(self, found):
        for n in found:
            self.add_item(n, False)  # jamais coché d'office : à l'utilisateur de décider
        self.msg.setText(tr("{found_count} réseau(x) joignable(s) trouvé(s).", found_count=len(found)) if found else
                         tr("Aucun autre réseau joignable détecté (routage ou pare-feu entre les VLAN ?)."))
        self.detect.setEnabled(True); self.detect.setText(tr("Détecter les réseaux joignables"))

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
        self.setToolTip(tip(f"{dev['hostname'] or dev['ip']}\n{dev['ip']}  ·  {LABELS.get(dev['type'], '')}"
                            + (f"\n{dev['mac']}" if dev["mac"] else "")
                            + (tr("\nSwitch : {switch}  ·  {port}", switch=dev.get('switch', ''), port=dev['switch_port']) if dev.get("switch_port") else "")))

    def boundingRect(self):
        return QRectF(-110, -self.r - 8, 220, 2 * self.r + 26 + fs(34))

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
        f = QFont(); f.setPointSizeF(fs(9)); p.setFont(f)
        name = QFontMetrics(f).elidedText(d["hostname"] or d["ip"], Qt.TextElideMode.ElideRight, 200)
        p.setPen(QColor(T["fg"]))
        p.drawText(QRectF(-105, r + 5, 210, fs(16)), Qt.AlignmentFlag.AlignCenter, name)
        m = QFont("monospace"); m.setPointSizeF(fs(8)); p.setFont(m)
        p.setPen(QColor(T["mut"]))
        p.drawText(QRectF(-105, r + 5 + fs(16), 210, fs(14)), Qt.AlignmentFlag.AlignCenter,
                   d.get("sub", "") if d.get("virtual") else tr("cette machine") if d["is_self"] else tr("hors ligne · vu {seen}", seen=seen_label(d.get('last_seen'))) if offline else d["ip"])

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
        self.show_minimap, self._mm_drag = True, False
        self.fit_cb, self.auto_fit = None, False
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAccessibleName(tr("Carte du réseau"))
        self.setAccessibleDescription(tr("Flèches : changer d'appareil. Maj + flèches : ajouter à la sélection. + et − : zoom. "
                                         "Entrée : modifier l'appareil. Échap : tout désélectionner. L'onglet Appareils liste les mêmes appareils."))
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

    # ---- mini-carte : toute la scène en petit, avec le cadre de ce qui est visible ; clic ou glisser pour se déplacer
    MM_W, MM_H = 200, 130

    def minimap_rect(self):
        return QRectF(self.viewport().width() - self.MM_W - 14, self.viewport().height() - self.MM_H - 14, self.MM_W, self.MM_H)

    def minimap_scale(self):
        """(rectangle de scène couvert, échelle, origine x, origine y) ou None s'il n'y a rien à montrer."""
        whole = self.scene().itemsBoundingRect()
        if whole.width() <= 0 and whole.height() <= 0:
            return None
        scene_rect = whole.adjusted(-50, -50, 50, 50)
        box = self.minimap_rect().adjusted(6, 6, -6, -6)
        k = min(box.width() / scene_rect.width(), box.height() / scene_rect.height())
        ox = box.left() + (box.width() - scene_rect.width() * k) / 2
        oy = box.top() + (box.height() - scene_rect.height() * k) / 2
        return scene_rect, k, ox, oy

    def minimap_visible(self):
        """La mini-carte n'apparaît que si elle sert : quand la carte entière n'est pas déjà à l'écran."""
        if not self.show_minimap or not self.scene().items():
            return False
        whole = self.scene().itemsBoundingRect()
        return not self.mapToScene(self.viewport().rect()).boundingRect().contains(whole)

    def _mm_move(self, pos):
        m = self.minimap_scale()
        if m:
            scene_rect, k, ox, oy = m
            self.centerOn(QPointF(scene_rect.left() + (pos.x() - ox) / k, scene_rect.top() + (pos.y() - oy) / k))

    def mousePressEvent(self, e):
        self.auto_fit = False
        pos = e.position()
        if e.button() == Qt.MouseButton.LeftButton and self.minimap_visible() and self.minimap_rect().contains(pos):
            self._mm_drag = True
            self._mm_move(pos)
            return
        if (e.button() == Qt.MouseButton.LeftButton and e.modifiers() & Qt.KeyboardModifier.ShiftModifier
                and self.itemAt(pos.toPoint()) is None):
            self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)  # Maj + glisser dans le vide : sélection au lasso
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e):
        if self._mm_drag:
            self._mm_move(e.position())
            return
        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e):
        self._mm_drag = False
        super().mouseReleaseEvent(e)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)

    def wheelEvent(self, e):
        self.auto_fit = False
        z = 1.12 if e.angleDelta().y() > 0 else 1 / 1.12
        self.scale(z, z)

    # ---- clavier : la carte se parcourt sans souris
    def device_nodes(self):
        return [i for i in self.scene().items() if isinstance(i, Node) and not i.dev.get("virtual")]

    def neighbour_node(self, node, dx, dy):
        """Nœud le plus proche dans la direction (dx, dy) : dans un cône de ±60°, sinon aucun."""
        best, best_score = None, None
        for n in self.device_nodes():
            if n is node:
                continue
            vx, vy = n.pos().x() - node.pos().x(), n.pos().y() - node.pos().y()
            dist = math.hypot(vx, vy)
            along = (vx * dx + vy * dy) / dist if dist else 0
            if along < 0.5:                                            # cos 60° : hors du cône
                continue
            score = dist * (2 - along)                                 # plus proche et mieux aligné d'abord
            if best_score is None or score < best_score:
                best, best_score = n, score
        return best

    def move_selection(self, dx, dy, extend=False):
        nodes = [n for n in self.device_nodes() if n.isSelected()]
        if not nodes:                                                  # rien de sélectionné : on part du nœud le plus proche du centre
            centre = self.mapToScene(self.viewport().rect().center())
            cands = self.device_nodes()
            target = min(cands, key=lambda n: math.hypot(n.pos().x() - centre.x(), n.pos().y() - centre.y()), default=None)
        else:
            target = self.neighbour_node(nodes[-1], dx, dy)
        if target is None:
            return
        if not extend:
            self.scene().clearSelection()
        target.setSelected(True)
        self.ensureVisible(target, 80, 80)

    def keyPressEvent(self, e):
        k, mods = e.key(), e.modifiers()
        arrows = {Qt.Key.Key_Left: (-1, 0), Qt.Key.Key_Right: (1, 0), Qt.Key.Key_Up: (0, -1), Qt.Key.Key_Down: (0, 1)}
        selected = [n for n in self.device_nodes() if n.isSelected()]
        if k in arrows:
            self.move_selection(*arrows[k], extend=bool(mods & Qt.KeyboardModifier.ShiftModifier))
        elif k in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
            self.auto_fit = False; self.scale(1.2, 1.2)
        elif k in (Qt.Key.Key_Minus, Qt.Key.Key_Underscore):
            self.auto_fit = False; self.scale(1 / 1.2, 1 / 1.2)
        elif k == Qt.Key.Key_Escape:
            self.scene().clearSelection()
        elif k in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and len(selected) == 1 and selected[0].edit_cb:
            selected[0].edit_cb(selected[0].dev)
        elif k == Qt.Key.Key_A and mods & Qt.KeyboardModifier.ControlModifier:
            for n in self.device_nodes():
                n.setSelected(True)
        else:
            super().keyPressEvent(e)
            return
        e.accept()

    def paint_minimap(self, p):
        m = self.minimap_scale()
        if not m:
            return
        scene_rect, k, ox, oy = m
        box = self.minimap_rect()
        p.setBrush(QColor(T["panel"])); p.setPen(QPen(QColor(T["border"]), 1))
        p.drawRoundedRect(box, 8, 8)
        p.setClipRect(box.adjusted(2, 2, -2, -2))
        to_mm = lambda pt: QPointF(ox + (pt.x() - scene_rect.left()) * k, oy + (pt.y() - scene_rect.top()) * k)
        p.setPen(Qt.PenStyle.NoPen)
        for it in self.scene().items():
            if isinstance(it, Node):
                p.setBrush(QColor(T["mut"] if it.dev.get("virtual") else type_color(it.dev["type"])))
                p.drawEllipse(to_mm(it.pos()), 2.6 if it.isSelected() else 2.0, 2.6 if it.isSelected() else 2.0)
        vis = self.mapToScene(self.viewport().rect()).boundingRect()
        a, b = to_mm(vis.topLeft()), to_mm(vis.bottomRight())
        frame = QRectF(a, b).intersected(box.adjusted(3, 3, -3, -3))
        fill = QColor(T["acc"]); fill.setAlpha(40)
        p.setBrush(fill); p.setPen(QPen(QColor(T["acc"]), 1.4))
        p.drawRect(frame)
        p.setClipping(False)

    def paintEvent(self, e):
        super().paintEvent(e)
        if self.hasFocus():                                            # focus clavier visible
            q = QPainter(self.viewport())
            q.setPen(QPen(QColor(T["acc"]), 3)); q.setBrush(Qt.BrushStyle.NoBrush)
            q.drawRect(self.viewport().rect().adjusted(1, 1, -2, -2))
            q.end()
        if self.minimap_visible():
            q = QPainter(self.viewport())
            q.setRenderHint(QPainter.RenderHint.Antialiasing)
            self.paint_minimap(q)
            q.end()
        if not self.legend or not self.show_legend:
            return
        p = QPainter(self.viewport())
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        f = QFont(); f.setPointSizeF(fs(8.5)); p.setFont(f)
        rows = self.legend
        cols = 2 if len(rows) > 7 else 1          # légende longue : deux colonnes pour ne pas cacher la carte
        per = -(-len(rows) // cols)
        rh, cw = int(20 * FONT_SCALE), int(176 * FONT_SCALE)   # lignes et colonnes suivent la taille du texte
        w, h = cw * cols, 12 + rh * per
        box = QRectF(14, self.viewport().height() - h - 14, w, h)
        p.setBrush(QColor(T["panel"])); p.setPen(QPen(QColor(T["border"]), 1))
        p.drawRoundedRect(box, 8, 8)
        for i, (kind, n) in enumerate(rows):
            x0, y = box.left() + (i // per) * cw, box.top() + 6 + (i % per) * rh
            p.drawPixmap(int(x0 + 10), int(y + (rh - 16) / 2), type_pixmap(kind, 16))
            p.setPen(QColor(T["fg"]))
            p.drawText(QRectF(x0 + 34, y, cw - 56, rh), Qt.AlignmentFlag.AlignVCenter, LABELS[kind])
            p.setPen(QColor(T["mut"]))
            p.drawText(QRectF(x0 + cw - 40, y, 30, rh), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, str(n))


class WelcomeWizard(QDialog):
    """Assistant de premier lancement : langue, usage responsable, apparence, façon de scanner. Rien n'est lancé : il ne fait que
    régler les options (modifiables ensuite dans les menus). Aide → « Assistant de premier lancement… » le rouvre."""

    AUTO_CHOICES = (0, 15, 30, 60)

    def __init__(self, settings=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Panther")
        self.setMinimumSize(560, 430)
        self.settings = settings
        self.lang = i18n.language()
        self.stack = QStackedWidget()
        self.back_btn, self.next_btn, self.skip_btn = QPushButton(), QPushButton(), QPushButton()
        self.back_btn.clicked.connect(lambda: self.go(self.stack.currentIndex() - 1))
        self.next_btn.clicked.connect(self.on_next)
        self.skip_btn.clicked.connect(self.reject)
        row = QHBoxLayout(); row.addWidget(self.skip_btn); row.addStretch(1); row.addWidget(self.back_btn); row.addWidget(self.next_btn)
        lay = QVBoxLayout(self); lay.setContentsMargins(24, 22, 24, 18); lay.setSpacing(14)
        self.step = QLabel(); self.step.setObjectName("muted")
        lay.addWidget(self.step); lay.addWidget(self.stack, 1); lay.addLayout(row)
        self.build_language_page()
        self.build_pages()
        self.go(0)

    # ---- pages
    def page(self, title, *widgets):
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(0, 0, 0, 0); l.setSpacing(12)
        t = QLabel(title); t.setObjectName("title"); t.setWordWrap(True); l.addWidget(t)
        for x in widgets:
            l.addWidget(x) if isinstance(x, QWidget) else l.addLayout(x)
        l.addStretch(1)
        return w

    @staticmethod
    def check(text):
        """Case à cocher dont le texte passe à la ligne (QCheckBox ne le fait pas) ; cliquer le texte coche la case. -> (case, ligne)."""
        box = QCheckBox()
        lab = QLabel(text); lab.setWordWrap(True); lab.setTextFormat(Qt.TextFormat.PlainText)
        lab.mousePressEvent = lambda _e: box.toggle()
        row = QWidget(); l = QHBoxLayout(row); l.setContentsMargins(0, 0, 0, 0); l.setSpacing(8)
        l.addWidget(box, 0, Qt.AlignmentFlag.AlignTop); l.addWidget(lab, 1)
        box.setAccessibleName(text)  # lecteur d'écran : le texte est porté par la case
        return box, row

    @staticmethod
    def note(text, muted=True):
        lab = QLabel(text); lab.setWordWrap(True); lab.setTextFormat(Qt.TextFormat.PlainText)
        if muted:
            lab.setObjectName("muted")
        return lab

    def build_language_page(self):
        """Première page : bilingue, car la langue n'est pas encore choisie."""
        self.lang_buttons = {}
        row = QHBoxLayout()
        for code, label in i18n.LANGUAGES.items():
            b = QPushButton(label); b.setCheckable(True); b.setMinimumHeight(44)
            b.clicked.connect(lambda _c, c=code: self.choose_language(c))
            row.addWidget(b); self.lang_buttons[code] = b
        self.lang_buttons[self.lang].setChecked(True)
        self.stack.addWidget(self.page("Bienvenue  ·  Welcome", self.note("Choisissez votre langue  ·  Choose your language", muted=False), row))

    def choose_language(self, code):
        """Change la langue du reste de l'assistant tout de suite (les pages suivantes sont reconstruites)."""
        self.lang = i18n.set_language(code)
        for c, b in self.lang_buttons.items():
            b.setChecked(c == self.lang)
        while self.stack.count() > 1:
            w = self.stack.widget(1); self.stack.removeWidget(w); w.deleteLater()
        self.build_pages()
        self.go(0)

    def build_pages(self):
        self.agree, agree_row = self.check(tr("Je n'utiliserai Panther que sur des réseaux dont j'ai la responsabilité ou l'autorisation."))
        self.agree.stateChanged.connect(lambda _s: self.go(self.stack.currentIndex()))
        self.stack.addWidget(self.page(tr("Un outil à utiliser avec discernement"), self.note(tr(
            "Panther envoie des paquets aux appareils d'un réseau pour les reconnaître. Scanner un réseau qui n'est pas le vôtre peut être "
            "illégal. Il refuse les plages publiques et n'essaie jamais de mot de passe."), muted=False), agree_row))
        self.theme = QComboBox()
        for mode, label in (("auto", tr("Automatique (suit le système)")), ("dark", tr("Sombre")), ("light", tr("Clair")), ("contrast", tr("Contraste élevé"))):
            self.theme.addItem(label, mode)
        self.size = QComboBox()
        for key, label, _scale in TEXT_SIZES:
            self.size.addItem(tr(label), key)
        self.size.setCurrentIndex(1)
        form = QFormLayout(); form.addRow(tr("Thème"), self.theme); form.addRow(tr("Taille du texte"), self.size)
        self.stack.addWidget(self.page(tr("Apparence"), form, self.note(tr("Le thème et la taille du texte se changent à tout moment dans le menu Affichage."))))
        self.depth = QComboBox()
        for key, label in (("presence", tr("Présence")), ("rapide", tr("Rapide")), ("normal", tr("Normal")), ("approfondi", tr("Approfondi"))):
            self.depth.addItem(label, key)
        self.depth.setCurrentIndex(2)
        self.auto = QComboBox()
        for minutes, label in ((0, tr("Désactivé")), (15, tr("Toutes les 15 minutes")), (30, tr("Toutes les 30 minutes")), (60, tr("Toutes les heures"))):
            self.auto.addItem(label, minutes)
        self.passive, passive_row = self.check(tr("Écoute seule : ne rien envoyer sur le réseau"))
        self.security, security_row = self.check(tr("Analyse de sécurité en lecture seule (ports ouverts, services sans mot de passe)"))
        form2 = QFormLayout(); form2.addRow(tr("Profondeur"), self.depth); form2.addRow(tr("Scan automatique"), self.auto)
        self.stack.addWidget(self.page(tr("Façon de scanner"), form2, passive_row, security_row,
                                       self.note(tr(SECURITY_INFO)), self.note(tr("Rien n'est lancé tant que vous n'appuyez pas sur « Lancer le scan »."))))

    # ---- navigation
    def on_next(self):
        if self.stack.currentIndex() == self.stack.count() - 1:
            self.accept()
        else:
            self.go(self.stack.currentIndex() + 1)

    def go(self, i):
        i = max(0, min(i, self.stack.count() - 1))
        self.stack.setCurrentIndex(i)
        last = i == self.stack.count() - 1
        self.step.setText(tr("Étape {i} sur {n}", i=i + 1, n=self.stack.count()))
        self.back_btn.setText(tr("Précédent")); self.back_btn.setEnabled(i > 0)
        self.next_btn.setText(tr("Terminer") if last else tr("Suivant")); self.next_btn.setObjectName("primary")
        self.skip_btn.setText(tr("Passer"))
        self.next_btn.setEnabled(not (i == 1 and not self.agree.isChecked()))   # la page « usage responsable » demande une case cochée
        self.next_btn.style().unpolish(self.next_btn); self.next_btn.style().polish(self.next_btn)

    def values(self):
        return {"language": self.lang, "theme": self.theme.currentData(), "text_size": self.size.currentData(), "depth": self.depth.currentData(),
                "auto_minutes": self.auto.currentData(), "passive": self.passive.isChecked(), "security": self.security.isChecked()}


def first_run_needed(settings):
    return str(settings.value("welcome_done", False)).lower() not in ("true", "1")


def apply_welcome_settings(settings, v):
    """Enregistre les choix de l'assistant (jamais de secret ni de réseau) ; cocher l'analyse de sécurité vaut consentement, puisque
    son fonctionnement est expliqué sur la page."""
    settings.setValue("language", v["language"] if v["language"] in i18n.LANGUAGES else "fr")
    settings.setValue("theme", v["theme"] if v["theme"] in THEME_MODES else "auto")
    settings.setValue("text_size", v["text_size"] if v["text_size"] in {k for k, _l, _s in TEXT_SIZES} else "normal")
    settings.setValue("depth", v["depth"] if v["depth"] in ("presence", "rapide", "normal", "approfondi") else "normal")
    settings.setValue("auto_minutes", v["auto_minutes"] if v["auto_minutes"] in WelcomeWizard.AUTO_CHOICES else 0)
    settings.setValue("passive", bool(v["passive"]))
    settings.setValue("security", bool(v["security"]) and not v["passive"])  # l'écoute seule n'envoie rien : pas d'analyse active
    if v["security"] and not v["passive"]:
        settings.setValue("security_consent", True)
    settings.setValue("welcome_done", True)


class Main(QMainWindow):
    def __init__(self, scanner=None, demo=False):
        super().__init__()
        self.demo = demo  # réseau fictif : rien n'est envoyé, rien n'est écrit hors du dossier temporaire
        self.setWindowTitle(tr("Panther — démonstration") if demo else tr("Panther"))
        self.resize(1320, 820)
        self.scanner = scanner or Scanner()
        self.settings = QSettings("Panther", "Panther")
        self.devices, self.nodes, self.selected, self.network = [], {}, None, None
        self.selected_keys = []  # sélection multiple : clés de tous les appareils sélectionnés sur la carte
        self.networks_info, self.scan_extra = [], {}
        self.snmp = self.load_snmp()
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
        self.passive_on = str(self.settings.value("passive", False)).lower() in ("true", "1")
        self.security_consent = str(self.settings.value("security_consent", False)).lower() in ("true", "1")
        self.layout_mode = self.settings.value("layout", "etoile") if self.settings.value("layout", "etoile") in ("etoile", "hierarchique", "types") else "etoile"
        self.show_offline = str(self.settings.value("show_offline", True)).lower() in ("true", "1")
        mode = str(self.settings.value("theme", "auto"))
        self.theme_mode = mode if mode in THEME_MODES else "auto"
        size = str(self.settings.value("text_size", "normal"))
        self.text_size = size if size in {k for k, _l, _s in TEXT_SIZES} else "normal"

        self._build_menu()
        self._build_toolbar()

        self.scene = QGraphicsScene()
        self.scene.setSceneRect(-3000, -3000, 6000, 6000)
        self.scene.selectionChanged.connect(self.on_scene_selection)
        self.view = MapView(self.scene)
        self.view.fit_cb = self.fit

        self.table = QTableWidget(0, 13)
        self.table.setHorizontalHeaderLabels([tr("Appareil"), tr("Adresse IP"), tr("Adresse MAC"), tr("Fabricant"), tr("Type"), tr("Système"), tr("Services"), tr("Réseau"), tr("Statut"), tr("Confiance"), tr("Exposition"), tr("Groupe"), tr("Étiquettes")])
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
        self.journal.setHorizontalHeaderLabels([tr("Date"), tr("Appareil"), tr("Événement"), tr("Détail")])
        self.journal.setAlternatingRowColors(True); self.journal.setShowGrid(False)
        self.journal.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.journal.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.journal.verticalHeader().hide(); self.journal.verticalHeader().setDefaultSectionSize(32)
        self.journal.horizontalHeader().setStretchLastSection(True)
        self.journal.cellDoubleClicked.connect(self.journal_open)
        tabs = self.tabs = QTabWidget()
        tabs.addTab(self.view, tr("Carte réseau"))
        tabs.addTab(self.table, tr("Appareils"))
        tabs.addTab(self.journal, tr("Journal"))
        self.sec_label = QLabel(); self.sec_label.setWordWrap(True); self.sec_label.setObjectName("muted")
        self.sec_label.setContentsMargins(16, 12, 16, 8)
        self.sec_table = QTableWidget(0, 5)
        self.sec_table.setHorizontalHeaderLabels([tr("Gravité"), tr("Appareil"), tr("Adresse IP"), tr("Constat"), tr("Recommandation")])
        self.sec_table.setAlternatingRowColors(True); self.sec_table.setShowGrid(False)
        self.sec_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sec_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sec_table.verticalHeader().hide(); self.sec_table.verticalHeader().setDefaultSectionSize(34)
        self.sec_table.horizontalHeader().setStretchLastSection(True)
        self.sec_table.cellDoubleClicked.connect(self.security_open)
        sec_page = QWidget(); sl_ = QVBoxLayout(sec_page); sl_.setContentsMargins(0, 0, 0, 0); sl_.setSpacing(0)
        sl_.addWidget(self.sec_label); sl_.addWidget(self.sec_table)
        tabs.addTab(sec_page, tr("Sécurité"))
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
        self.edit_btn = QPushButton(tr("Modifier le nom / le type…"))
        self.edit_btn.clicked.connect(lambda: self.edit_device(self.current_device()))
        self.trust_btn = QPushButton()
        self.trust_btn.clicked.connect(self.on_trust_button)
        self.meta_btn = QPushButton(tr("Étiquettes, notes et groupe…"))
        self.meta_btn.clicked.connect(self.on_meta_button)
        body = QWidget(); bl = QVBoxLayout(body); bl.setContentsMargins(0, 0, 4, 0); bl.setSpacing(14)
        bl.addLayout(head); bl.addWidget(sep); bl.addLayout(self.form); bl.addStretch(1)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff); scroll.setWidget(body)
        sl.addWidget(scroll, 1); sl.addWidget(self.edit_btn); sl.addWidget(self.meta_btn); sl.addWidget(self.trust_btn)

        split = QSplitter(); split.addWidget(tabs); split.addWidget(self.side)
        split.setStretchFactor(0, 1); split.setSizes([980, 340]); split.setChildrenCollapsible(False)
        self.setCentralWidget(split)

        self.status = QLabel(tr("Prêt"))
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
        self.report_timer = QTimer(self); self.report_timer.timeout.connect(self.report_tick); self.report_timer.start(60000)
        try:
            QGuiApplication.styleHints().colorSchemeChanged.connect(self.on_system_theme)  # thème « automatique » : suit le système en direct
        except AttributeError:
            pass
        self.update_netlabel()
        w_rules = rules.current().warnings
        if w_rules:
            self.status.setText(tr("Règles de détection : {count} (menu Détection)", count=plural(len(w_rules), 'avertissement', 'avertissements')))
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
        m = mb.addMenu(tr("Fichier"))
        for text, fn in ((tr("Exporter le rapport en PDF…"), self.export_pdf), (tr("Exporter la carte (PNG, SVG)…"), self.export_map),
                         (tr("Exporter en JSON…"), lambda: self.export("json")), (tr("Exporter en CSV…"), lambda: self.export("csv"))):
            m.addAction(QAction(text, self, triggered=fn))
        m.addSeparator()
        m.addAction(QAction(tr("Comparer deux scans…"), self, triggered=self.compare_scans))
        m.addAction(QAction(tr("Rapports planifiés…"), self, triggered=self.open_report_schedule))
        m.addAction(QAction(tr("Historique et données…"), self, triggered=self.open_data))
        m.addSeparator()
        quit_ = QAction(tr("Quitter"), self, triggered=self.close); quit_.setShortcut("Ctrl+Q"); m.addAction(quit_)
        m = mb.addMenu(tr("Scan"))
        self.act_scan = QAction(tr("Lancer le scan"), self, triggered=self.on_scan_button); self.act_scan.setShortcut("Ctrl+R")
        self.act_stop = QAction(tr("Arrêter le scan"), self, triggered=self.stop_scan); self.act_stop.setShortcut("Ctrl+.")
        self.act_stop.setEnabled(False)
        m.addAction(self.act_scan); m.addAction(self.act_stop); m.addSeparator()
        m.addAction(QAction(tr("Faire confiance à tous les appareils en ligne…"), self, triggered=self.trust_all))
        m.addAction(QAction(tr("Fusionner des doublons…"), self, triggered=self.show_duplicates))
        m.addAction(QAction(tr("Alertes (webhook, e-mail)…"), self, triggered=lambda: AlertsDialog(self).exec()))
        m.addSeparator()
        auto = m.addMenu(tr("Scan automatique")); group = QActionGroup(self); self.auto_actions = {}
        for minutes, label in ((0, tr("Désactivé")), (5, tr("Toutes les 5 minutes")), (15, tr("Toutes les 15 minutes")),
                               (30, tr("Toutes les 30 minutes")), (60, tr("Toutes les heures"))):
            a = QAction(label, self, checkable=True); group.addAction(a); auto.addAction(a)
            a.triggered.connect(lambda _checked, mm=minutes: self.set_auto(mm)); self.auto_actions[minutes] = a
        m = mb.addMenu(tr("Affichage"))
        fit = QAction(tr("Recentrer la carte"), self, triggered=self.fit); fit.setShortcut("Ctrl+0"); m.addAction(fit)
        center = QAction(tr("Centrer sur la sélection"), self, triggered=self.center_on_selection); center.setShortcut("Ctrl+Shift+0"); m.addAction(center)
        select_all = QAction(tr("Sélectionner tous les appareils"), self, triggered=self.select_all_nodes); select_all.setShortcut("Ctrl+Shift+A")
        m.addAction(select_all)
        mini = QAction(tr("Mini-carte"), self, checkable=True, checked=True, triggered=lambda on: (setattr(self.view, "show_minimap", on), self.view.viewport().update()))
        m.addAction(mini)
        lay = m.addMenu(tr("Disposition")); lgroup = QActionGroup(self); self.layout_actions = {}
        for mode, label in (("etoile", tr("Étoile (autour de cette machine)")), ("hierarchique", tr("Hiérarchique (Internet → box → switch → appareils)")),
                            ("types", tr("Regroupée par type d'appareil"))):
            a = QAction(label, self, checkable=True); lgroup.addAction(a); lay.addAction(a)
            a.triggered.connect(lambda _c, mm=mode: self.set_layout(mm)); self.layout_actions[mode] = a
        self.layout_actions[self.layout_mode].setChecked(True)
        lay.addSeparator()
        lay.addAction(QAction(tr("Réinitialiser les positions de cette disposition"), self, triggered=self.reset_positions))
        leg = QAction(tr("Légende de la carte"), self, checkable=True, checked=True, triggered=lambda on: (setattr(self.view, "show_legend", on), self.view.viewport().update()))
        m.addAction(leg)
        off = QAction(tr("Afficher les appareils hors ligne"), self, checkable=True, checked=self.show_offline, triggered=self.toggle_offline)
        m.addAction(off)
        theme_menu = m.addMenu(tr("Thème")); tgroup = QActionGroup(self); self.theme_actions = {}
        for mode, label in (("auto", tr("Automatique (suit le système)")), ("dark", tr("Sombre")), ("light", tr("Clair")),
                            ("contrast", tr("Contraste élevé"))):
            a = QAction(label, self, checkable=True); tgroup.addAction(a); theme_menu.addAction(a)
            a.triggered.connect(lambda _c, mm=mode: self.set_theme_mode(mm)); self.theme_actions[mode] = a
        self.theme_actions[self.theme_mode].setChecked(True)
        size_menu = m.addMenu(tr("Taille du texte")); sgroup = QActionGroup(self); self.size_actions = {}
        for key, label, scale in TEXT_SIZES:
            a = QAction(tr(label), self, checkable=True); sgroup.addAction(a); size_menu.addAction(a)
            a.triggered.connect(lambda _c, kk=key: self.set_text_size(kk)); self.size_actions[key] = a
        self.size_actions[self.text_size].setChecked(True)
        lang_menu = m.addMenu(tr("Langue"))
        lang_group = QActionGroup(self)
        for code, label in i18n.LANGUAGES.items():
            act = QAction(label, self, checkable=True, checked=(code == i18n.language()))
            act.triggered.connect(lambda _on, c=code: self.choose_language(c))
            lang_group.addAction(act); lang_menu.addAction(act)
        m = mb.addMenu(tr("Sécurité"))
        self.act_passive = QAction(tr("Écoute seule (aucune sonde active)"), self, checkable=True, checked=self.passive_on)
        self.act_passive.triggered.connect(self.toggle_passive)
        m.addAction(self.act_passive)
        m.addSeparator()
        self.act_security = QAction(tr("Analyse de sécurité (lecture seule)"), self, checkable=True, checked=self.security_on)
        self.act_security.triggered.connect(self.toggle_security)
        m.addAction(self.act_security)
        m.addAction(QAction(tr("Voir le rapport de sécurité"), self, triggered=lambda: self.tabs.setCurrentIndex(3)))
        m.addAction(QAction(tr("Exporter le rapport (Markdown)…"), self, triggered=self.export_security))
        m.addSeparator()
        m.addAction(QAction(tr("Ce que fait l'analyse…"), self, triggered=lambda: QMessageBox.information(self, tr("Analyse de sécurité"), SECURITY_INFO)))
        m = mb.addMenu(tr("Détection"))
        m.addAction(QAction(tr("Règles personnalisées…"), self, triggered=self.open_rules))
        m.addAction(QAction(tr("Créer une règle pour l'appareil sélectionné…"), self, triggered=lambda: self.create_rule(self.current_device())))
        m = mb.addMenu(tr("Aide"))
        m.addAction(QAction(tr("Assistant de premier lancement…"), self, triggered=self.open_welcome))
        m.addAction(QAction(tr("Mettre à jour la base des fabricants…"), self, triggered=self.update_oui))
        m.addAction(QAction(tr("Ouvrir le journal d'erreurs"), self, triggered=self.open_log))
        m.addAction(QAction(tr("À propos de Panther"), self, triggered=lambda: QMessageBox.about(
            self, tr("Panther"), tr("Panther – scanner et cartographie de réseau local.\n\nMoteur de scan maison (TCP, ARP, NetBIOS, "
                                "mDNS), sans dépendance externe.\nÀ n'utiliser que sur des réseaux dont vous avez l'autorisation."))))

    def _build_toolbar(self):
        tb = QToolBar(); tb.setMovable(False); tb.setFloatable(False); self.addToolBar(tb)
        self.btn = QPushButton(tr("Lancer le scan")); self.btn.setObjectName("primary"); self.btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn.clicked.connect(self.on_scan_button); tb.addWidget(self.btn)
        self.net_btn = QPushButton(); self.net_btn.clicked.connect(self.open_networks); tb.addWidget(self.net_btn)
        lab = QLabel(tr("  Profondeur")); lab.setObjectName("muted"); tb.addWidget(lab)
        self.depth = QComboBox()
        for key, label in (("presence", tr("Présence")), ("rapide", tr("Rapide")), ("normal", tr("Normal")), ("approfondi", tr("Approfondi"))):
            self.depth.addItem(label, key)
        self.depth.setToolTip(tr("Présence : qui est là ? (réutilise les détails du dernier scan complet, très discret).\nRapide : "
                                 "ports courants.\nNormal : bon équilibre.\nApprofondi : plus de ports et des délais plus longs.\nLes "
                                 "scans automatiques utilisent la présence, avec un scan complet au plus toutes les heures."))
        self.depth.setCurrentIndex(max(self.depth.findData(self.settings.value("depth", "normal")), 0))
        self.depth.currentIndexChanged.connect(lambda _i: self.settings.setValue("depth", self.depth.currentData()))
        self.depth.setEnabled(not self.passive_on)
        tb.addWidget(self.depth)
        lab2 = QLabel(tr("  Interface")); lab2.setObjectName("muted"); tb.addWidget(lab2)
        self.iface_combo = RefreshCombo()
        self.iface_combo.setToolTip(tr("Réseau à scanner. « Automatique » suit la route par défaut ; choisissez une interface pour scanner "
                                       "un autre réseau (Ethernet, VPN…)."))
        self.iface_combo.about_to_show.connect(self.populate_ifaces)
        self.populate_ifaces()
        self.iface_combo.currentIndexChanged.connect(lambda _i: self.settings.setValue("iface", self.iface_combo.currentData() or ""))
        tb.addWidget(self.iface_combo)
        self.netlabel = ElidedLabel(tr("  Aucun scan effectué")); self.netlabel.setObjectName("muted"); tb.addWidget(self.netlabel)
        self.search = QLineEdit(); self.search.setPlaceholderText(tr("Filtrer : nom, IP, type…  tag:xxx  groupe:xxx"))
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
            self.status.setText(tr("Arrêt en cours…")); self.btn.setEnabled(False); self.act_stop.setEnabled(False)

    FULL_SCAN_EVERY = 3600  # secondes : au plus un scan complet par heure pendant les scans automatiques

    def choose_depth(self, auto=False, now=None):
        """Profondeur réellement utilisée et appareils connus. Le scan de présence réutilise les détails du dernier
        scan complet : il n'a de sens que s'il y en a un, et les scans automatiques refont un scan complet toutes les heures.
        En écoute seule, on ne sonde rien : on lit la table du noyau et on reprend les détails du dernier scan complet."""
        if self.passive_on:
            try:
                return "ecoute", history.last_snapshot_map()
            except (sqlite3.Error, OSError):
                return "ecoute", {}
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
        if self.scanner.start(self.targets, self.snmp, depth, self.security_on and not self.passive_on, self.iface_combo.currentData() or None, known, aliases):
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
            phase = tr("Découverte des hôtes") if s["progress"] < 60 else tr("Analyse des appareils")
            if self.btn.isEnabled():
                self.btn.setText(tr("Arrêter le scan ({progress} %)", progress=s['progress']))
            self.status.setText(tr("{phase}  ·  {elapsed} s  ·  profondeur {depth}", phase=phase, elapsed=elapsed, depth=s['depth']))
            return
        self.timer.stop(); self.progress.hide()
        self.btn.setEnabled(True); self.act_scan.setEnabled(True); self.act_stop.setEnabled(False)
        self.btn.setText(tr("Relancer le scan"))
        if s["status"] == "error":
            self.status.setText(tr("Erreur : {error}", error=s['error']))
        elif s["status"] == "stopped":
            self.devices = s["devices"]; self.rebuild(); self.update_count()
            self.status.setText(tr("Scan interrompu : {devices_count} appareil(s) analysé(s) avant l'arrêt", devices_count=len(self.devices)) if self.devices
                                else tr("Scan interrompu pendant la découverte : aucun appareil n'avait encore été analysé"))
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
            log.warning(tr("Historique indisponible"), exc_info=True)
            note = tr("  ·  historique indisponible ({e})", e=e)
        self.devices = online + offline
        self.rebuild(); self.update_count(); self.refresh_journal(); self.refresh_security()
        self.last_new = [f"{d['hostname'] or d['ip']}  ·  {d['ip']}" for d in online if d.get("new")]
        light = s.get("depth") in ("presence", "ecoute")
        if not light:
            self.last_full_scan = time.time()
            self.settings.setValue("last_full_scan", self.last_full_scan)
        msg = (tr("Écoute terminée en {elapsed} s", elapsed=elapsed) if s.get("depth") == "ecoute" else tr("Scan de présence terminé en {elapsed} s", elapsed=elapsed)
               if light else tr("Scan terminé en {elapsed} s", elapsed=elapsed))
        if res["baseline"]:
            msg += tr("  ·  première analyse : {online_count} appareil(s) enregistrés comme connus", online_count=len(online))
        elif self.last_new:
            msg += tr("  ·  {last_new_count} nouvel appareil", last_new_count=len(self.last_new)) + ("s" if len(self.last_new) > 1 else "")
            if self.last_scan_auto:
                first = [d["hostname"] or d["ip"] for d in online if d.get("new")][:3]
                self.notify(tr("Panther : nouvel appareil sur le réseau"), ", ".join(first) + ("…" if len(self.last_new) > 3 else ""))
        if self.security_on and fr["baseline"]:
            msg += tr("  ·  analyse de sécurité : référence enregistrée")
        if fr["new"]:
            msg += "  ·  " + plural(len(fr["new"]), "nouvelle exposition", "nouvelles expositions")
            bad = [(d, f) for d, f in fr["new"] if security.RANK[f["severity"]] >= security.RANK["élevé"]]
            if bad and self.last_scan_auto:
                d, f = bad[0]
                self.notify(tr("Panther : nouvelle exposition"), tr("{hostname} : {title}", hostname=d['hostname'] or d['ip'], title=f['title']) + ("…" if len(bad) > 1 else ""))
        if fr["fixed"]:
            msg += "  ·  " + plural(len(fr["fixed"]), "exposition corrigée", "expositions corrigées")
        self.send_alerts(online, res, fr, auto=self.last_scan_auto)
        self.dup_suggestions = identity.suggest_duplicates(self.devices)
        if self.dup_suggestions:
            msg += "  ·  " + plural(len(self.dup_suggestions), "doublon possible", "doublons possibles") + tr(" (menu Scan)")
        w = len(self.scan_extra.get("warnings") or [])
        self.status.setText(msg + (tr("  ·  {w} avertissement(s)", w=w) if w else "") + note)
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
        cb.addItem(tr("Automatique"), "")
        for it in networks.interfaces():
            cb.addItem(tr("{iface}  ·  {link_labels_label}", iface=it['iface'], link_labels_label=networks.LINK_LABELS.get(it['kind'], '')), it["iface"])
            cb.setItemData(cb.count() - 1, f"{it['ip']}  ({it['cidr']})", Qt.ItemDataRole.ToolTipRole)
        cb.setCurrentIndex(max(cb.findData(cur), 0))
        cb.blockSignals(False)

    def edit_meta(self, dev):
        if not dev or dev.get("virtual"):
            return
        try:
            groups = history.meta_groups()
        except (sqlite3.Error, OSError):
            groups = []
        dlg = MetaDialog(dev, groups, self)
        if dlg.exec():
            group, tags, note = dlg.values()
            try:
                history.set_meta(dev, note=note, tags=tags, group=group)
            except (sqlite3.Error, OSError) as e:
                QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer :\n{e}", e=e)); return
            self.refresh_views()
            self.status.setText(tr("Étiquettes et notes enregistrées"))

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
            QMessageBox.information(self, tr("Règle de détection"), tr("Sélectionnez d'abord un appareil."))
            return
        dlg = RuleFromDeviceDialog(dev, self)
        if dlg.exec():
            try:
                rules.add_rule(dlg.build())
            except (OSError, rules.RuleError) as e:
                QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer la règle :\n{e}", e=e)); return
            self.reclassify_all()
            self.status.setText(tr("Règle enregistrée et appliquée aux appareils affichés"))

    def send_alerts(self, online, res, fr, auto):
        """Après un scan : alerte (webhook / e-mail) sur les événements choisis, en arrière-plan. Jamais pour la première analyse."""
        try:
            cfg = alerts.load()
            if not cfg["enabled"] or (cfg["events"]["auto_only"] and not auto) or not (cfg["webhook"]["enabled"] or cfg["email"]["enabled"]):
                return
            events = alerts.build_events(online, res, fr, cfg, res.get("event_list", []))
        except Exception:  # noqa: BLE001 - les alertes ne doivent jamais gêner l'affichage du scan
            log.exception("Préparation des alertes")
            return
        if not events:
            return
        worker = AlertWorker(cfg, events, self)
        worker.finished_with.connect(self.on_alerts_sent)
        self._alert_workers = [w for w in getattr(self, "_alert_workers", []) if w.isRunning()] + [worker]
        worker.start()

    def on_alerts_sent(self, results):
        bad = [f"{c} : {err}" for c, ok, err in results if not ok]
        self.status.setText((tr("Alerte envoyée (") + ", ".join(c for c, ok, _ in results if ok) + ")") if not bad
                            else tr("Alerte non envoyée : ") + " ; ".join(bad))

    def apply_retention(self, scans_days, events_days):
        history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS = int(scans_days), int(events_days)
        self.settings.setValue("keep_scans_days", int(scans_days)); self.settings.setValue("keep_events_days", int(events_days))

    def open_data(self):
        dlg = DataDialog(history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS, self)
        accepted = dlg.exec()
        if dlg.erased:
            self.after_erase()
        if accepted:
            self.apply_retention(*dlg.values())
            if not dlg.erased:
                self.status.setText(tr("Durée de conservation enregistrée"))

    def after_erase(self):
        """L'historique vient d'être effacé : la fenêtre repart de zéro (la prochaine analyse sera une nouvelle référence)."""
        self.devices, self.selected, self.dup_suggestions, self.last_new = [], None, [], []
        self.last_full_scan = 0.0
        self.settings.setValue("last_full_scan", 0.0)
        self.rebuild(); self.update_count(); self.refresh_journal(); self.refresh_security(); self.refresh_panel()
        self.status.setText(tr("Historique effacé"))

    def compare_scans(self):
        try:
            scans = history.list_scans()
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Historique indisponible :\n{e}", e=e)); return
        if len(scans) < 2:
            QMessageBox.information(self, tr("Comparer deux scans"), tr("Il faut au moins deux scans enregistrés. Lancez un scan (ou deux) : chaque scan terminé est "
                                                                    "conservé pour la comparaison."))
            return
        CompareDialog(scans, self).exec()

    def paint_map(self, painter, target, source, theme="light"):
        """Dessine la carte dans `painter` (image, SVG…) avec le thème demandé, sans modifier l'affichage ni la sélection."""
        saved, sel = dict(T), list(self.scene.selectedItems())
        self._building = True
        self.scene.clearSelection()
        T.update(THEMES[theme])
        try:
            painter.fillRect(target, QColor(T["surface"] if theme == "light" else T["bg"]))
            self.scene.render(painter, target, source)
        finally:
            T.clear(); T.update(saved)
            for i in sel:
                i.setSelected(True)
            self._building = False

    def render_map_image(self, width=1600, theme="light"):
        """Image de la carte (thème clair par défaut : adapté au papier)."""
        r = self.scene.itemsBoundingRect()
        if r.isEmpty():
            return None
        r = r.adjusted(-40, -40, 40, 40)
        h = max(1, int(width * r.height() / r.width()))
        img = QImage(width, h, QImage.Format.Format_ARGB32)
        p = QPainter(img); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        try:
            self.paint_map(p, QRectF(0, 0, width, h), r, theme)
        finally:
            p.end()
        return img

    def write_map(self, path, theme="light", width=2000):
        """Exporte la carte en PNG ou en SVG (selon l'extension). SVG : vectoriel, à retoucher dans Inkscape ou à insérer dans un document."""
        r = self.scene.itemsBoundingRect()
        if r.isEmpty():
            raise OSError(tr("la carte est vide : lancez d'abord un scan"))
        r = r.adjusted(-40, -40, 40, 40)
        if path.lower().endswith(".svg"):
            from PyQt6.QtSvg import QSvgGenerator
            h = max(1, int(width * r.height() / r.width()))
            gen = QSvgGenerator()
            gen.setFileName(path); gen.setSize(QSize(width, h)); gen.setViewBox(QRectF(0, 0, width, h)); gen.setTitle(tr("Panther – carte du réseau"))
            p = QPainter(gen)
            try:
                self.paint_map(p, QRectF(0, 0, width, h), r, theme)
            finally:
                p.end()
            return
        img = self.render_map_image(width, theme)
        if img is None or not img.save(path, "PNG"):
            raise OSError(tr("impossible d'écrire {path}", path=path))

    def export_map(self):
        if not self.nodes:
            QMessageBox.information(self, tr("Exporter la carte"), tr("La carte est vide : lancez d'abord un scan.")); return
        path, flt = QFileDialog.getSaveFileName(self, tr("Exporter la carte"), "carte-panther.png",
                                               tr("Image PNG (*.png);;Image vectorielle SVG (*.svg)"))
        if not path:
            return
        if not path.lower().endswith((".png", ".svg")):
            path += ".svg" if "SVG" in flt else ".png"
        try:
            self.write_map(path, theme="dark" if T["bg"] == THEMES["dark"]["bg"] else "light")
        except OSError as e:
            QMessageBox.warning(self, tr("Panther"), tr("Export impossible :\n{e}", e=e)); return
        self.status.setText(tr("Carte exportée : {basename}", basename=os.path.basename(path)))

    def write_pdf_report(self, path):
        """Rapport PDF complet (résumé, carte, changements depuis le scan précédent, appareils, exposition, avertissements)."""
        changes = None
        try:  # évolution depuis le scan précédent, si on en a un
            scans = history.list_scans(2)
            if len(scans) == 2:
                changes = compare.compare(history.load_snapshot(scans[1]["id"]), history.load_snapshot(scans[0]["id"]))
        except (sqlite3.Error, OSError):
            log.debug("Comparaison avec le scan précédent indisponible", exc_info=True)
        img = self.render_map_image()
        page = reportpdf.build_html(self.devices, [n["cidr"] for n in self.networks_info], time.time(), "map" if img else None,
                                    self.security_on, self.scan_extra.get("warnings") or [], changes,
                                    image_width=reportpdf.map_width(img))
        reportpdf.write_pdf(path, page, img)

    def export_pdf(self):
        if not self.devices:
            QMessageBox.information(self, tr("Rapport PDF"), tr("Aucun résultat à exporter : lancez d'abord un scan.")); return
        path, _ = QFileDialog.getSaveFileName(self, tr("Exporter le rapport"), "rapport-panther.pdf", "PDF (*.pdf)")
        if not path:
            return
        try:
            self.write_pdf_report(path)
        except OSError as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'écrire le PDF :\n{e}", e=e)); return
        self.status.setText(tr("Rapport PDF exporté : {basename}", basename=os.path.basename(path)))

    # ---------- rapports planifiés
    def report_settings(self):
        s = self.settings
        try:
            keep = int(s.value("report_keep", 10))
            last = float(s.value("report_last", 0))
        except (TypeError, ValueError):
            keep, last = 10, 0.0
        return {"enabled": str(s.value("report_enabled", False)).lower() in ("true", "1"),
                "freq": s.value("report_freq", "weekly") if s.value("report_freq", "weekly") in schedule.PERIODS else "weekly",
                "folder": str(s.value("report_folder", os.path.join(os.path.dirname(history.PATH), "rapports") if self.demo
                                      else os.path.join(os.path.expanduser("~"), "Panther-rapports"))), "keep": max(1, min(keep, schedule.MAX_KEEP)),
                "last": last}

    def save_report_settings(self, enabled, freq, folder, keep):
        s = self.settings
        s.setValue("report_enabled", bool(enabled)); s.setValue("report_freq", freq if freq in schedule.PERIODS else "weekly")
        s.setValue("report_folder", folder); s.setValue("report_keep", int(keep))

    def generate_scheduled_report(self, now=None):
        """Écrit un rapport dans le dossier choisi et supprime les plus anciens. -> chemin du fichier. Lève OSError."""
        cfg = self.report_settings()
        folder = schedule.ensure_folder(cfg["folder"])
        now = time.time() if now is None else now
        path = os.path.join(folder, schedule.filename(now))
        self.write_pdf_report(path)
        removed = schedule.prune(folder, cfg["keep"])
        self.settings.setValue("report_last", now)
        if removed:
            log.info("Rapports planifiés : %d ancien(s) supprimé(s) dans %s", len(removed), folder)
        return path

    def report_tick(self, now=None):
        """Appelé chaque minute : produit le rapport planifié s'il est dû, qu'un scan a eu lieu et qu'aucun scan n'est en cours."""
        cfg = self.report_settings()
        now = time.time() if now is None else now
        if not cfg["enabled"] or not self.devices or self.scanner.snapshot()["status"] == "scanning":
            return None
        if not schedule.is_due(cfg["last"], now, cfg["freq"]):
            return None
        try:
            path = self.generate_scheduled_report(now)
        except OSError as e:
            log.warning(tr("Rapport planifié impossible : %s"), e)
            self.status.setText(tr("Rapport planifié impossible : {e}", e=e))
            self.settings.setValue("report_last", now)  # on réessaiera à la prochaine échéance, pas à chaque minute
            return None
        self.status.setText(tr("Rapport planifié enregistré : {basename}", basename=os.path.basename(path)))
        return path

    def open_report_schedule(self):
        dlg = ReportScheduleDialog(self.report_settings(), self)
        if dlg.exec():
            self.save_report_settings(*dlg.values())
            self.status.setText(tr("Rapports planifiés : réglages enregistrés"))
        elif dlg.generated:
            self.refresh_panel()

    def merge_into(self, keep, drop):
        """Regroupe l'historique de `drop` (hors ligne) dans `keep`. Retourne True si la fusion a eu lieu."""
        if not keep or not drop or drop.get("online", True) or keep is drop:
            QMessageBox.information(self, tr("Fusion"), tr("Seul un appareil hors ligne peut être fusionné dans un autre appareil."))
            return False
        try:
            history.merge_devices(dkey(keep), dkey(drop))
            history.annotate([keep])
        except (ValueError, sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Fusion impossible :\n{e}", e=e))
            return False
        store.apply(keep, store.load(), history.alias_map())
        self.devices = [d for d in self.devices if d is not drop]
        self.dup_suggestions = [t for t in self.dup_suggestions if t[0] is not drop and t[1] is not drop]
        self.selected = dkey(keep)
        self.rebuild(); self.update_count(); self.refresh_panel(); self.refresh_journal()
        self.status.setText(tr("{name} fusionné dans {other}", name=drop['hostname'] or drop['ip'], other=keep['hostname'] or keep['ip']))
        return True

    def open_merge(self, dev):
        if dev.get("online", True):
            cands = [d for d in self.devices if not d.get("online", True) and not d.get("virtual")]
            text = tr("Choisissez l'appareil hors ligne qui est en réalité « {name} » (par exemple avec une ancienne adresse MAC). "
                      "Son historique, sa confiance et ses noms seront regroupés ici.", name=dev['hostname'] or dev['ip'])
        else:
            cands = [d for d in self.devices if d.get("online", True) and not d.get("virtual") and not d.get("is_self")]
            text = tr("« {name} » (hors ligne) est-il un appareil actuellement en ligne ? Choisissez-le : "
                      "l'historique de l'appareil hors ligne sera regroupé avec le sien.", name=dev['hostname'] or dev['ip'])
        if not cands:
            QMessageBox.information(self, tr("Fusion"), tr("Aucun appareil à fusionner.")); return
        dlg = MergeDialog(tr("Fusionner des appareils"), text, cands, self)
        if dlg.exec():
            other = dlg.chosen()
            self.merge_into(dev, other) if dev.get("online", True) else self.merge_into(other, dev)

    def show_duplicates(self):
        if not self.dup_suggestions:
            QMessageBox.information(self, tr("Doublons"), tr("Aucun doublon probable : aucun appareil récent ne ressemble à un appareil hors ligne."))
            return
        DuplicatesDialog(self.dup_suggestions, self.merge_into, self).exec()
        self.refresh_panel()

    def wake_device(self, dev):
        """Envoie un paquet Wake-on-LAN à un appareil hors ligne (si son adresse MAC est la vraie, pas une adresse privée)."""
        name = dev["hostname"] or dev["ip"]
        if self.demo:
            QMessageBox.information(self, tr("Démonstration"), tr("Mode démonstration : aucun paquet n'est envoyé sur le réseau.")); return
        if fingerprint.is_random_mac(dev.get("mac", "")):
            QMessageBox.information(self, tr("Wake-on-LAN"), tr("« {name} » utilise une adresse MAC aléatoire (adresse privée Wi-Fi) : elle ne peut pas servir à le "
                                                            "réveiller. Seule l'adresse matérielle d'origine de la carte réseau le peut.", name=name))
            return
        targets = ["255.255.255.255"]
        if dev.get("network"):
            try:
                targets.insert(0, wol.broadcast_for(dev["network"]))
            except ValueError:
                pass
        try:
            n = wol.send(dev["mac"], targets)
        except ValueError as e:
            QMessageBox.warning(self, tr("Wake-on-LAN"), str(e)); return
        self.status.setText(tr("Paquet de réveil envoyé à {name} ({mac}) : {n} envoi(s). Il faut que Wake-on-LAN soit activé sur "
                               "l'appareil (en général en Ethernet, rarement en Wi-Fi).", name=name, mac=dev['mac'], n=n))

    def update_oui(self):
        if getattr(self, "oui_worker", None) and self.oui_worker.isRunning():
            return
        if self.demo:
            QMessageBox.information(self, tr("Démonstration"), tr("Mode démonstration : aucun téléchargement n'est effectué.")); return
        ok = QMessageBox.question(self, tr("Mettre à jour la base des fabricants"),
                                  tr("Panther va télécharger le registre officiel des fabricants (IEEE) depuis\n{url}\n(environ 6 Mo) et "
                                     "l'enregistrer dans :\n{user_path}\n\nAucune donnée de votre réseau n'est envoyée. Continuer ?", url=ouiupdate.URL, user_path=ouiupdate.USER_PATH)) == QMessageBox.StandardButton.Yes
        if not ok:
            return
        self.status.setText(tr("Téléchargement de la base des fabricants…"))
        self.oui_worker = OuiWorker(self)
        self.oui_worker.done.connect(self.on_oui_done)
        self.oui_worker.failed.connect(self.on_oui_failed)
        self.oui_worker.start()

    def on_oui_done(self, n):
        self.status.setText(tr("Base des fabricants mise à jour : {n} entrées", n=n))
        QMessageBox.information(self, tr("Base des fabricants"), tr("{n} fabricants enregistrés. Les nouveaux noms apparaîtront au prochain scan.", n=n))

    def on_oui_failed(self, message):
        self.status.setText(tr("Mise à jour de la base des fabricants impossible"))
        QMessageBox.warning(self, tr("Base des fabricants"), tr("La base n'a pas été modifiée.\n\n{message}", message=message))

    def open_log(self):
        from . import log as plog
        if os.path.exists(plog.PATH):
            QDesktopServices.openUrl(QUrl.fromLocalFile(plog.PATH))
        else:
            QMessageBox.information(self, tr("Journal d'erreurs"), tr("Aucune erreur enregistrée pour le moment.\n\nEmplacement : {path}", path=plog.PATH))

    def toggle_trust(self, dev):
        if not dev:
            return
        flag = not dev.get("trusted")
        try:
            history.set_trusted([dev], flag)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer la confiance :\n{e}", e=e)); return
        self.refresh_views(); self.refresh_journal()
        self.status.setText(tr("{hostname} : ", hostname=dev['hostname'] or dev['ip']) + (tr("marqué de confiance") if flag else tr("confiance retirée")))

    def trust_all(self):
        todo = [d for d in self.devices if d.get("online", True) and not d.get("trusted")]
        if not todo:
            QMessageBox.information(self, tr("Panther"), tr("Aucun appareil en ligne à valider.")); return
        names = "\n".join(f"• {d['hostname'] or d['ip']}  ({d['ip']})" for d in todo[:12]) + ("\n…" if len(todo) > 12 else "")
        if QMessageBox.question(self, tr("Faire confiance"), tr("Marquer ces {todo_count} appareil(s) comme de confiance ?\n\n{names}\n\nVérifiez qu'ils sont tous "
                                                            "reconnus : un intrus présent maintenant serait validé.", todo_count=len(todo), names=names)) \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            history.set_trusted(todo, True)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer la confiance :\n{e}", e=e)); return
        self.refresh_views(); self.refresh_journal()
        self.status.setText(tr("{todo_count} appareil(s) marqués de confiance", todo_count=len(todo)))

    def forget_device(self, dev):
        if not dev or QMessageBox.question(self, tr("Oublier"), tr("Oublier {hostname} et son historique ?", hostname=dev['hostname'] or dev['ip'])) \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            history.forget(dev)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'oublier l'appareil :\n{e}", e=e)); return
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
            log.warning(tr("Journal des événements illisible"), exc_info=True)
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
            self.tabs.setCurrentIndex(0); self.scene.clearSelection(); n.setSelected(True); self.view.centerOn(n.pos())

    def open_welcome(self):
        """Rouvre l'assistant : les choix s'appliquent tout de suite (sauf la langue, au prochain démarrage)."""
        old_lang = i18n.language()
        wiz = WelcomeWizard(parent=self)
        accepted = wiz.exec()
        v = wiz.values()
        i18n.set_language(old_lang)  # l'assistant a pu changer la langue le temps de son affichage : on la rétablit
        if not accepted:
            return
        apply_welcome_settings(self.settings, v)
        self.set_theme_mode(v["theme"], save=False); self.set_text_size(v["text_size"], save=False)
        self.depth.setCurrentIndex(max(self.depth.findData(v["depth"]), 0))
        self.act_passive.setChecked(v["passive"]); self.toggle_passive(v["passive"])
        self.security_on = v["security"] and not v["passive"]
        self.act_security.setChecked(self.security_on)
        self.security_consent = self.security_consent or self.security_on
        self.refresh_security()
        self.auto_actions[v["auto_minutes"]].setChecked(True); self.set_auto(v["auto_minutes"])
        if v["language"] != old_lang:
            QMessageBox.information(self, tr("Langue"), tr("La langue sera appliquée au prochain démarrage de Panther."))
        self.status.setText(tr("Réglages enregistrés"))

    def choose_language(self, code):
        """Mémorise la langue ; elle s'applique au prochain démarrage (tous les textes sont construits au lancement)."""
        if code == i18n.language() and self.settings.value("language", "") == code:
            return
        self.settings.setValue("language", code)
        if code != i18n.language():
            QMessageBox.information(self, tr("Langue"), tr("La langue sera appliquée au prochain démarrage de Panther."))

    def toggle_passive(self, on):
        self.passive_on = on
        self.settings.setValue("passive", on)
        self.depth.setEnabled(not on)
        self.status.setText(tr("Écoute seule : Panther n'enverra plus rien sur le réseau (il lit la table des voisins du noyau et "
                               "les baux DHCP)") if on
                            else tr("Écoute seule désactivée"))

    def toggle_security(self, on):
        if on and not self.security_consent:
            ok = QMessageBox.question(self, tr("Activer l'analyse de sécurité ?"), SECURITY_INFO + tr("\n\nActiver l'analyse ?")) \
                == QMessageBox.StandardButton.Yes
            if not ok:
                self.act_security.setChecked(False); return
            self.security_consent = True
            self.settings.setValue("security_consent", True)
        self.security_on = on
        self.settings.setValue("security", on)
        self.status.setText(tr("Analyse de sécurité activée : elle sera effectuée au prochain scan") if on else tr("Analyse de sécurité désactivée"))
        self.refresh_security()

    def refresh_security(self):
        t = self.sec_table
        analysed = [d for d in self.devices if d.get("security") is not None and d.get("online", True)]
        rows = sorted(((f, d) for d in analysed for f in d["security"]),
                      key=lambda fd: (-security.RANK[fd[0]["severity"]], fd[1].get("hostname") or fd[1]["ip"]))
        t.setRowCount(len(rows))
        for r, (f, d) in enumerate(rows):
            cells = [security.LABELS[f["severity"]], d["hostname"] or d["ip"], d["ip"],
                     f["title"] + (tr("  (port {port})", port=f['port']) if f.get("port") else ""), f["remedy"]]
            for c, v in enumerate(cells):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setForeground(QColor(sev_color(f["severity"]))); it.setData(KEY_ROLE, dkey(d))
                    ft = it.font(); ft.setBold(True); it.setFont(ft)
                if c == 4:
                    it.setForeground(QColor(T["mut"]))
                if c == 3 and f["detail"]:
                    it.setToolTip(tip(f["detail"]))
                t.setItem(r, c, it)
        for c, w in enumerate((90, 180, 120, 380)):
            t.setColumnWidth(c, w)
        if not self.security_on:
            self.sec_label.setText(tr("L'analyse de sécurité est désactivée. Activez-la dans le menu Sécurité (lecture seule), puis lancez "
                                      "un scan."))
        elif not analysed:
            self.sec_label.setText(tr("Lancez un scan pour analyser l'exposition des appareils."))
        elif not rows:
            self.sec_label.setText(tr("Aucun constat sur {analysed_count} appareil(s) analysé(s).", analysed_count=len(analysed)))
        else:
            c = security.count_by_severity(analysed)
            self.sec_label.setText(tr("{rows_count} constat(s) sur {value_count} appareil(s) ({analysed_count} analysés) : ", rows_count=len(rows), value_count=len({dkey(d) for _, d in rows}), analysed_count=len(analysed)) + " · ".join(f"{n} {security.LABELS[sv].lower()}" for sv, n in c.items() if n)
                                   + tr("   —   double-clic pour voir l'appareil sur la carte."))

    def security_open(self, row, _col):
        key = self.sec_table.item(row, 0).data(KEY_ROLE)
        n = self.nodes.get(key)
        if n:
            self.tabs.setCurrentIndex(0); self.scene.clearSelection(); n.setSelected(True); self.view.centerOn(n.pos())

    def export_security(self):
        if not any(d.get("security") is not None for d in self.devices):
            QMessageBox.information(self, tr("Rapport"), tr("Aucun résultat d'analyse : activez l'analyse de sécurité (menu Sécurité) puis lancez un scan."))
            return
        path, _ = QFileDialog.getSaveFileName(self, tr("Exporter le rapport"), "rapport-securite.md", "Markdown (*.md)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(security.report_markdown(self.devices, [n["cidr"] for n in self.networks_info]))
            self.status.setText(tr("Rapport exporté : {basename}", basename=os.path.basename(path)))

    def update_count(self):
        on = sum(1 for d in self.devices if d.get("online", True))
        off = len(self.devices) - on
        self.count.setText(tr("{on} en ligne", on=on) + (tr("  ·  {off} hors ligne", off=off) if off else "") + "   ")

    def set_auto(self, minutes):
        self.settings.setValue("auto_minutes", minutes)
        self.auto_timer.stop()
        if minutes:
            self.auto_timer.start(minutes * 60000)
        self.auto_label.setText(tr("Scan auto : toutes les {minutes} min   ", minutes=minutes) if minutes else "")

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
        elif self.layout_mode == "types":
            self.build_types()
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

    def build_types(self):
        """Un amas par type d'appareil, sans liens : pour voir d'un coup ce que le réseau contient."""
        pos, clusters = layout.type_clusters(self.devices)
        self._live_ok = False
        for c in clusters:
            zone = Zone(c["r"], f"{LABELS.get(c['kind'], c['kind'])}  ·  {c['count']}")
            zone.setPos(c["x"], c["y"]); self.scene.addItem(zone)
        for d in self.devices:
            if dkey(d) in pos:
                self.add_node(d, *pos[dkey(d)])

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
            zone = Zone(rz + 70, cidr + (f"  ·  VLAN {vlan}" if vlan else "") + ("" if devs else tr("  ·  aucun appareil"))); zone.setPos(zc); self.scene.addItem(zone)
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
            QMessageBox.warning(self, tr("Panther"), tr("Impossible de réinitialiser les positions :\n{e}", e=e)); return
        if self.devices:
            self.rebuild(); self.fit()
        self.status.setText(tr("Positions de cette disposition réinitialisées"))

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
                SortItem(tr("De confiance") if d.get("trusted") else ""), self.exposure_item(d),
                SortItem(d.get("group", "")), SortItem(", ".join(d.get("tags", [])))]
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
        toks = self.search.text().strip().lower().split()
        def match(d):
            hay = " ".join([d["ip"], d.get("network", ""), status_text(d), tr("de confiance") if d.get("trusted") else tr("non vérifié"), security.worst(d.get("security")), d["mac"], d["vendor"], d["hostname"], d["os"], LABELS.get(d["type"], ""), " ".join(d["services"]),
                            d.get("group", ""), " ".join(d.get("tags", [])), d.get("note", "")]).lower()
            tags = [t.lower() for t in d.get("tags", [])]
            for t in toks:
                if t.startswith("tag:"):                       # tag:enfants : étiquette exacte
                    if t[4:] not in tags:
                        return False
                elif t.startswith(("groupe:", "group:")):      # groupe:salon : le groupe contient ce texte
                    if t.split(":", 1)[1] not in d.get("group", "").lower():
                        return False
                elif t not in hay:
                    return False
            return True
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
        real = [i for i in items if not i.dev.get("virtual")]
        self.selected_keys = [dkey(i.dev) for i in real]
        self.selected = self.selected_keys[0] if len(real) == 1 else (dkey(items[0].dev) if items and not real else None)
        self.sync_table(self.selected); self.refresh_panel()

    def on_table_selection(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        n = self.nodes.get(self.table.item(rows[0].row(), 0).data(KEY_ROLE))
        if n:
            self.scene.clearSelection(); n.setSelected(True); self.view.centerOn(n.pos())

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
        text = f["title"] + (tr("  (port {port})", port=f['port']) if f.get("port") else "") + (tr("\nÀ faire : {remedy}", remedy=f['remedy']) if f["remedy"] else "")
        v = QLabel(text); v.setTextFormat(Qt.TextFormat.PlainText); v.setWordWrap(True)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if f["detail"]:
            v.setToolTip(tip(f["detail"]))
        self.form.addRow(k, v)

    def on_trust_button(self):
        if len(self.selected_keys) > 1:
            self.trust_selection()
        else:
            self.toggle_trust(self.current_device())

    def on_meta_button(self):
        if len(self.selected_keys) > 1:
            self.edit_meta_selection()
        else:
            self.edit_meta(self.current_device())

    def trust_selection(self):
        """Sélection multiple : si tous sont de confiance on retire la confiance, sinon on l'accorde à tous."""
        devs = self.selected_devices()
        if not devs:
            return
        flag = not all(d.get("trusted") for d in devs)
        try:
            history.set_trusted(devs, flag)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer la confiance :\n{e}", e=e)); return
        self.refresh_views(); self.refresh_journal()
        self.status.setText(tr("{count} marqués de confiance", count=plural(len(devs), "appareil", "appareils")) if flag
                            else tr("Confiance retirée à {count}", count=plural(len(devs), "appareil", "appareils")))

    def edit_meta_selection(self):
        devs = self.selected_devices()
        if not devs:
            return
        try:
            groups = history.meta_groups()
        except (sqlite3.Error, OSError):
            groups = []
        dlg = MetaDialog(devs[0], groups, self, count=len(devs))
        if not dlg.exec():
            return
        group, tags, _note = dlg.values()
        added = [t for t in tags.replace(";", ",").split(",") if t.strip()]
        try:
            for d in devs:
                history.set_meta(d, tags=list(d.get("tags", [])) + added if added else None, group=group if group.strip() else None)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer :\n{e}", e=e)); return
        self.refresh_views()
        self.status.setText(tr("Étiquettes et groupe enregistrés pour {count}", count=plural(len(devs), "appareil", "appareils")))

    def refresh_multi_panel(self, devs):
        """Panneau d'une sélection multiple : résumé par type, liste des appareils, actions groupées."""
        kinds = {}
        for d in devs:
            kinds[d["type"]] = kinds.get(d["type"], 0) + 1
        self.edit_btn.setVisible(False); self.trust_btn.setVisible(True); self.meta_btn.setVisible(True)
        self.trust_btn.setText(tr("Retirer la confiance à la sélection") if all(d.get("trusted") for d in devs)
                               else tr("Marquer la sélection comme de confiance"))
        self.meta_btn.setText(tr("Étiquettes et groupe de la sélection…"))
        self.side_icon.setPixmap(type_pixmap("net", 40))
        self.side_title.setText(tr("{count} sélectionnés", count=plural(len(devs), "appareil", "appareils")))
        self.side_sub.setText("  ·  ".join(f"{LABELS.get(k, k)} {n}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])))
        self.add_row(tr("Appareils"), "\n".join(f"• {d['hostname'] or d['ip']}  ({d['ip']})" for d in devs[:15]) + ("\n…" if len(devs) > 15 else ""))
        self.add_row(tr("Confiance"), tr("{trusted} sur {total} de confiance", trusted=sum(1 for d in devs if d.get("trusted")), total=len(devs)))
        groups = sorted({d.get("group", "") for d in devs if d.get("group")})
        self.add_row(tr("Groupe"), ", ".join(groups))
        worst = max((security.worst(d.get("security")) for d in devs if d.get("security")), key=lambda w: security.RANK.get(w, -1), default="")
        if worst:
            self.add_row(tr("Exposition"), tr("Gravité maximale : {severity}", severity=security.LABELS[worst]))

    def refresh_panel(self):
        while self.form.rowCount():
            self.form.removeRow(0)
        self.meta_btn.setText(tr("Étiquettes, notes et groupe…"))
        if len(self.selected_keys) > 1:
            self.refresh_multi_panel(self.selected_devices())
            return
        d = self.current_device()
        self.edit_btn.setVisible(bool(d)); self.trust_btn.setVisible(bool(d)); self.meta_btn.setVisible(bool(d))
        if d:
            self.trust_btn.setText(tr("Retirer la confiance") if d.get("trusted") else tr("Marquer comme appareil de confiance"))
        if d:
            self.side_icon.setPixmap(type_pixmap(d["type"], 40))
            self.side_title.setText(d["hostname"] or d["ip"])
            self.side_sub.setText(LABELS.get(d["type"], ""))
            if not d.get("online", True):
                self.add_row(tr("Statut"), tr("Hors ligne · dernière apparition le {date}", date=when(d['last_seen'])))
            elif d.get("new"):
                self.add_row(tr("Statut"), tr("Nouvel appareil (première apparition)"))
            self.add_row(tr("Adresse IP"), d["ip"], True)
            self.add_row(tr("Adresse MAC"), d["mac"], True)
            self.add_row(tr("Réseau"), d.get("network", "") + (tr("  ·  VLAN {vlan}", vlan=d['vlan']) if d.get("vlan") else ""), True)
            self.add_row(tr("Fabricant"), d["vendor"])
            c = d.get("cert") or {}
            if c:
                who = c.get("cn") or c.get("o") or tr("certificat sans nom")
                self.add_row(tr("Certificat HTTPS"), who + (tr("  ·  émis par {issuer}", issuer=c['issuer']) if c.get("issuer") and not c.get("self_signed") else tr("  ·  auto-signé"))
                             + (tr("  ·  expiré le {not_after}", not_after=c['not_after']) if c.get("expired") else tr("  ·  expire le {not_after}", not_after=c['not_after']) if c.get("not_after") else ""))
            if d.get("switch_port"):
                self.add_row(tr("Switch"), tr("{switch}  ·  {switch_port}", switch=d.get('switch', ''), switch_port=d['switch_port']))
            if d.get("path"):
                self.add_row(tr("Chemin"), "  →  ".join(h or "*" for h in d["path"]), True)
            self.add_row(tr("Modèle"), models.describe(d.get("model", "")))
            self.add_row(tr("Système"), d["os"])
            self.add_row(tr("TTL"), str(d["ttl"]) if d["ttl"] else "")
            self.add_row(tr("Services"), "  ·  ".join(d["services"]))
            self.add_row(tr("Ports"), ", ".join(map(str, d["ports"])), True)
            for p, b in d["banners"].items():
                self.add_row(tr("Port {p}", p=p), b)
            if d.get("mdns_services"):
                self.add_row(tr("Annonces"), "\n".join(d["mdns_services"]), True)
            if d["type"] != "unknown" or d.get("reasons"):
                conf = d.get("confidence", 0)
                self.add_row(tr("Détection"), tr("{labels_label} · confiance {confidence_label} ({conf} %)", labels_label=LABELS.get(d['type'], ''), confidence_label=fingerprint.confidence_label(conf), conf=conf))
                self.add_row(tr("Indices"), "\n".join("• " + r for r in d.get("reasons", [])))
            if d.get("light"):
                self.add_row(tr("Analyse"), tr("Présence confirmée ; détails repris du dernier scan complet"))
            self.add_row(tr("Confiance"), tr("De confiance") if d.get("trusted") else tr("Non vérifié"))
            self.add_row(tr("Groupe"), d.get("group", ""))
            self.add_row(tr("Étiquettes"), "  ·  ".join(d.get("tags", [])))
            self.add_row(tr("Notes"), d.get("note", ""))
            if d.get("security") is not None:
                if d["security"]:
                    for f in d["security"]:
                        self.add_finding_row(f)
                else:
                    self.add_row(tr("Exposition"), tr("Aucun constat"))
            try:
                h = history.device_summary(d)
            except (sqlite3.Error, OSError):
                h = None
            if h:
                self.add_row(tr("Première apparition"), when(h["first_seen"]))
                self.add_row(tr("Dernière apparition"), tr("à l'instant") if d.get("online", True) else when(h["last_seen"]))
                if h["presence"]:
                    k = QLabel(tr("Présence")); k.setObjectName("key")
                    self.form.addRow(k, PresenceBar(h["presence"]))
                if h["uptime7"] is not None:
                    self.add_row(tr("Disponibilité"), tr("{uptime} % sur 7 jours", uptime=h['uptime7']))
                if h["events"]:
                    self.add_row(tr("Historique"), "\n".join(f"{when_short(e['ts'])}  {EVENT_LABELS.get(e['kind'], e['kind'])}"
                                                         + (f"  ({e['detail']})" if e["detail"] and e["kind"] != "first_seen" else "")
                                                         for e in h["events"]))
            if d["is_gateway"]:
                self.add_row(tr("Rôle"), tr("Passerelle par défaut"))
            if d["is_self"]:
                self.add_row(tr("Rôle"), tr("Machine locale"))
        else:
            self.side_icon.setPixmap(type_pixmap("router", 40))
            self.side_title.setText(tr("Réseau local"))
            self.side_sub.setText(tr("Aucune sélection"))
            if self.network:
                self.add_row(tr("Sous-réseau"), self.network["cidr"], True)
                self.add_row(tr("Passerelle"), self.network["gateway"], True)
                self.add_row(tr("Interface"), self.network["iface"], True)
                on = sum(1 for x in self.devices if x.get("online", True))
                self.add_row(tr("Appareils"), tr("{on} en ligne", on=on) + (tr("  ·  {devices_count} hors ligne", devices_count=len(self.devices) - on) if len(self.devices) > on else ""))
                kinds = {}
                for x in self.devices:
                    kinds[x["type"]] = kinds.get(x["type"], 0) + 1
                for k, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
                    self.add_row(LABELS[k], str(n))
                if self.last_new:
                    self.add_row(tr("Nouveaux"), "\n".join(self.last_new))
                if self.dup_suggestions:
                    self.add_row(tr("Doublons possibles"), "\n".join(f"{n['hostname'] or n['ip']} ≈ {o['hostname'] or o['ip']} (hors ligne)"
                                                                 for n, o, _ in self.dup_suggestions))
                if self.security_on and any(x.get("security") is not None for x in self.devices):
                    c = security.count_by_severity(self.devices)
                    self.add_row(tr("Sécurité"), " · ".join(f"{n} {security.LABELS[sv].lower()}" for sv, n in c.items() if n) or tr("Aucun constat"))
                ex = self.scan_extra
                for w_ in ex.get("warnings") or []:
                    self.add_row(tr("Attention"), w_)
                for i in ex.get("snmp") or []:
                    self.add_row(tr("SNMP"), tr("{name} : {arp} entrées ARP, {fdb} adresses MAC", name=i['name'] or i['host'], arp=i['arp'], fdb=i['fdb']))
                nb, st = ex.get("neighbors") or [], ex.get("neighbors_status")
                if nb:
                    self.add_row(tr("Voisins"), "\n".join(
                        f"{n.get('name') or n.get('chassis') or n.get('src', '')}  ·  {n.get('port', '')}"
                        + (f"  ·  VLAN {n['vlan']}" if n.get("vlan") else "") + f"  ({n['proto']})" for n in nb))
                elif st == "refusé":
                    self.add_row(tr("Voisins"), tr("LLDP/CDP : droits insuffisants (voir le README)."))
                elif st == "ok":
                    self.add_row(tr("Voisins"), tr("Aucun voisin LLDP/CDP annoncé."))
            else:
                self.add_row("", tr("Lancez un scan pour cartographier le réseau auquel vous êtes connecté."))

    # ---------- divers ----------
    def set_theme_mode(self, mode, save=True):
        """Thème : automatique (suit le système), sombre, clair ou contraste élevé."""
        self.theme_mode = mode if mode in THEME_MODES else "auto"
        if save:
            self.settings.setValue("theme", self.theme_mode)
        if self.theme_actions.get(self.theme_mode):
            self.theme_actions[self.theme_mode].setChecked(True)
        self.apply_theme(resolve_theme(self.theme_mode))

    def on_system_theme(self, *_args):
        if self.theme_mode == "auto":
            self.apply_theme(resolve_theme("auto"))

    def set_text_size(self, key, save=True):
        """Taille du texte (petit, normal, grand, très grand) : interface et carte."""
        self.text_size = key if key in self.size_actions else "normal"
        if save:
            self.settings.setValue("text_size", self.text_size)
        self.size_actions[self.text_size].setChecked(True)
        set_text_scale(text_scale_of(self.text_size))
        QApplication.instance().setStyleSheet(make_style())
        if self.devices:
            self.rebuild()
        self.refresh_panel(); self.view.viewport().update()

    def apply_theme(self, name):
        T.update(THEMES[name])
        QApplication.instance().setStyleSheet(make_style())
        if self.devices:
            self.rebuild()
        self.refresh_panel(); self.view.viewport().update()

    def update_netlabel(self):
        n = len(self.targets)
        self.net_btn.setText(tr("Réseaux ({n})", n=n + 1) if n else tr("Réseaux…"))
        if self.network:
            vlan = f"  ·  VLAN {self.network['vlan']}" if self.network.get("vlan") else ""
            extra = tr("  ·  +{n} autre(s) réseau(x)", n=n) if n else ""
            gw = tr("  ·  passerelle {gateway}", gateway=self.network['gateway']) if self.network.get("gateway") else tr("  ·  sans passerelle")
            kind = f" ({networks.LINK_LABELS.get(self.network.get('kind'), '')})" if self.network.get("kind") else ""
            self.netlabel.setText(tr("  {cidr}{vlan}{gw}  ·  {iface}{kind}{extra}", cidr=self.network['cidr'], vlan=vlan, gw=gw, iface=self.network['iface'], kind=kind, extra=extra))

    def load_snmp(self):
        """Sources SNMP : les hôtes sont dans les réglages, les communautés dans le trousseau (`secrets`).
        Une ancienne configuration (communauté en clair) est migrée vers le trousseau puis effacée des réglages."""
        try:
            raw = json.loads(self.settings.value("snmp", "[]"))
            items = [(str(x["host"]), x.get("community")) for x in raw if isinstance(x, dict)]
        except (ValueError, TypeError, KeyError, AttributeError):
            return []
        sources, legacy = [], False
        for host, comm in items:
            if comm is not None:
                legacy = True
                secrets.set(snmp_secret(host), str(comm))
            sources.append({"host": host, "community": secrets.get(snmp_secret(host)) or ""})
        if legacy:
            self.save_snmp(sources, [])
            log.info("Communautés SNMP déplacées dans %s", secrets.backend())
        return sources

    def save_snmp(self, sources, previous):
        """Enregistre les hôtes (réglages) et les communautés (trousseau) ; oublie celles des hôtes retirés."""
        for host in {s["host"] for s in previous} - {s["host"] for s in sources}:
            secrets.delete(snmp_secret(host))
        for s in sources:
            secrets.set(snmp_secret(s["host"]), s["community"])
        self.settings.setValue("snmp", json.dumps([{"host": s["host"]} for s in sources]))

    def open_networks(self):
        try:
            local = local_network()["cidr"]
        except (RuntimeError, OSError):
            local = None
        dlg = NetworksDialog(local, self.targets, self.snmp, self)
        if dlg.exec():
            previous = self.snmp
            self.targets, self.snmp = dlg.selected(), dlg.snmp_sources()
            self.settings.setValue("targets", json.dumps(self.targets))
            self.save_snmp(self.snmp, previous)
            self.update_netlabel()
            self.status.setText(tr("Plages mises à jour : relancez le scan pour les prendre en compte."))

    def current_device(self):
        if len(self.selected_keys) > 1:
            return None
        return next((x for x in self.devices if dkey(x) == self.selected), None)

    def selected_devices(self):
        keys = set(self.selected_keys)
        return [d for d in self.devices if dkey(d) in keys]

    def center_on_selection(self):
        """Centre la carte sur l'appareil sélectionné (ou cadre la sélection multiple, sans zoom excessif)."""
        nodes = [self.nodes[k] for k in (self.selected_keys or ([self.selected] if self.selected else [])) if k in self.nodes]
        if not nodes:
            self.status.setText(tr("Sélectionnez d'abord un appareil."))
            return
        self.view.auto_fit = False
        if len(nodes) == 1:
            self.view.centerOn(nodes[0].pos())
            return
        rect = nodes[0].sceneBoundingRect()
        for n in nodes[1:]:
            rect = rect.united(n.sceneBoundingRect())
        self.view.fitInView(rect.adjusted(-60, -60, 60, 60), Qt.AspectRatioMode.KeepAspectRatio)
        if self.view.transform().m11() > 1.3:                 # quelques appareils proches : pas de zoom écrasant
            self.view.resetTransform(); self.view.centerOn(rect.center())

    def select_all_nodes(self):
        for n in self.nodes.values():
            if not n.dev.get("virtual"):
                n.setSelected(True)

    def table_device(self, row):
        it = self.table.item(row, 0) if row >= 0 else None
        return next((x for x in self.devices if it and dkey(x) == it.data(KEY_ROLE)), None)

    def device_menu(self, dev, pos):
        if not dev or dev.get("virtual"):
            return
        menu = QMenu(self)
        menu.addAction(tr("Modifier le nom / le type…"), lambda: self.edit_device(dev))
        menu.addAction(tr("Retirer la confiance") if dev.get("trusted") else tr("Marquer comme appareil de confiance"),
                       lambda: self.toggle_trust(dev))
        menu.addAction(tr("Étiquettes, notes et groupe…"), lambda: self.edit_meta(dev))
        menu.addAction(tr("Créer une règle de détection…"), lambda: self.create_rule(dev))
        if any(d is not dev and not d.get("virtual") and d.get("online", True) != dev.get("online", True) for d in self.devices):
            menu.addAction(tr("Fusionner avec un appareil hors ligne…") if dev.get("online", True) else tr("Fusionner dans un appareil en ligne…"),
                           lambda: self.open_merge(dev))
        if not dev.get("online", True) and dev.get("mac"):
            menu.addAction(tr("Réveiller (Wake-on-LAN)"), lambda: self.wake_device(dev))
        if not dev.get("online", True):
            menu.addAction(tr("Oublier cet appareil"), lambda: self.forget_device(dev))
        if dev.get("custom"):
            menu.addAction(tr("Rétablir la détection automatique"), lambda: self.reset_device(dev))
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
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer le réglage :\n{e}", e=e))
            return
        store.apply(dev, data)
        self.selected = dkey(dev)
        self.rebuild(); self.refresh_panel()
        self.status.setText(tr("Réglage enregistré") if (name or kind) else tr("Détection automatique rétablie"))

    def export(self, fmt):
        if not self.devices:
            QMessageBox.information(self, tr("Export"), tr("Aucun résultat à exporter : lancez d'abord un scan."))
            return
        path, _ = QFileDialog.getSaveFileName(self, tr("Exporter"), f"panther-scan.{fmt}", f"*.{fmt}")
        if not path:
            return
        try:
            self.write_export(path, fmt)
        except OSError as e:
            QMessageBox.warning(self, tr("Panther"), tr("Export impossible :\n{e}", e=e)); return
        self.status.setText(tr("Exporté : {basename}", basename=os.path.basename(path)))

    def write_export(self, path, fmt):
        """CSV ou JSON complet (confiance, groupe, étiquettes, notes, historique, exposition, certificat…)."""
        text = exporter.to_json(self.devices, [n["cidr"] for n in self.networks_info]) if fmt == "json" else exporter.to_csv(self.devices)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)


def start_demo(w):
    """Charge le réseau fictif : trois scans passés dans l'historique temporaire, puis le dernier affiché."""
    from . import demo
    demo.seed_history()
    w.notify = lambda *a: None
    w.network, w.networks_info, w.scan_extra = dict(demo.NETWORK), demo.NETS, demo.extra()
    w.targets = [demo.VLAN]
    w.update_netlabel()
    w.last_scan_auto = False
    w.finish_scan({"devices": demo.online_devices(sec=w.security_on), "networks": demo.NETS, "depth": "normal"}, 0)
    w.status.setText(tr("Démonstration : réseau fictif, rien n'est scanné ni envoyé. Lancez le scan pour voir la "
                        "progression, essayez les cartes, le journal et la comparaison."))


def main(demo=False, lang=None):
    fingerprint.load_all_oui(os.path.dirname(os.path.abspath(__file__)))
    app = QApplication(sys.argv)
    settings = QSettings("Panther", "Panther")
    # langue : --lang, sinon le choix enregistré (menu Affichage), sinon celle du système
    saved = settings.value("language", "")
    i18n.set_language(lang or (saved if saved in i18n.LANGUAGES else i18n.detect()))
    app.setStyle("Fusion")
    app.setApplicationName("Panther")
    app.setDesktopFileName("panther")
    app.setWindowIcon(QIcon(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "panther.svg")))

    def look():
        """Apparence enregistrée, appliquée avant d'afficher quoi que ce soit : thème (auto = système) et taille du texte."""
        mode, size = str(settings.value("theme", "auto")), str(settings.value("text_size", "normal"))
        set_text_scale(text_scale_of(size))
        T.update(THEMES[resolve_theme(mode if mode in THEME_MODES else "auto")])
        app.setStyleSheet(make_style())
    look()
    if not demo and first_run_needed(settings):
        wiz = WelcomeWizard(settings)
        if wiz.exec():
            apply_welcome_settings(settings, wiz.values())
        else:
            settings.setValue("welcome_done", True)  # « Passer » : valeurs par défaut, et on ne redemande pas
            settings.setValue("language", i18n.language())
        look()
    if demo:
        from . import demo as demo_mod
        w = Main(scanner=demo_mod.DemoScanner(), demo=True)
        start_demo(w)
        import signal
        signal.signal(signal.SIGTERM, lambda *a: app.quit())  # le dossier temporaire est supprimé même si on arrête le processus
        wake = QTimer(); wake.timeout.connect(lambda: None); wake.start(500)  # laisse Python traiter le signal
    else:
        w = Main()
    w.refresh_panel()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
