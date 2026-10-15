"""Thèmes, couleurs, taille du texte et feuille de style de l'interface."""
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QGuiApplication
from PyQt6.QtWidgets import QApplication

from .. import security
from ..i18n import N_

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


TYPE_COLORS = {"router": "#7ea2cf", "printer": "#c4a574", "phone": "#a591c0", "tablet": "#a591c0", "console": "#b59a6d", "speaker": "#8fb3b8", "tv": "#c28d98", "settop": "#c79b8b",
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


def sev_color(sev):
    return T["bad"] if security.RANK.get(sev, 0) >= security.RANK["élevé"] else T["warn"] if sev == "moyen" else T["mut"]
