"""Petits widgets réutilisables : présence, tri, libellé tronqué, liste déroulante rafraîchie."""
from PyQt6.QtCore import QRectF, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFontMetrics, QPainter
from PyQt6.QtWidgets import QComboBox, QLabel, QSizePolicy, QTableWidgetItem, QWidget

from ..i18n import tr
from .theme import T
from .util import tip


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


class SortItem(QTableWidgetItem):
    def __lt__(self, other):
        a, b = self.data(Qt.ItemDataRole.UserRole), other.data(Qt.ItemDataRole.UserRole)
        if a is not None and b is not None:
            return a < b
        return self.text().lower() < other.text().lower()


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
