"""Petits widgets réutilisables : présence, tri, libellé tronqué, liste déroulante rafraîchie."""
from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFontMetrics, QPainter, QPen
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


class LatencyChart(QWidget):
    """Courbe de latence (ms) sur les derniers scans ; un trait rouge en bas marque un scan où l'appareil n'a pas répondu, un point
    pâle une présence sans mesure (scan de présence). La ligne se coupe aux trous au lieu d'inventer des valeurs."""

    def __init__(self, series, parent=None):
        super().__init__(parent)
        self.series = series
        self.setFixedHeight(54)
        self.setMinimumWidth(180)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setAccessibleName(tr("Latence"))
        vals = [ms for _ts, ms, _p in series if ms is not None]
        self.setToolTip(tr("Latence sur les {n} derniers scans : de {low} à {high} ms (en bas : scans sans réponse)", n=len(series),
                           low=f"{min(vals):.1f}" if vals else "–", high=f"{max(vals):.1f}" if vals else "–"))

    def points(self, w, h, pad=6):
        """[(x, y, état)] ; état : « ms » mesure, « absent », « sans mesure »."""
        vals = [ms for _ts, ms, _p in self.series if ms is not None]
        top = max(vals) if vals else 1.0
        top = max(top, 1.0)
        n = len(self.series)
        out = []
        for i, (_ts, ms, present) in enumerate(self.series):
            x = pad + (w - 2 * pad) * (i / (n - 1) if n > 1 else 0.5)
            if ms is not None:
                out.append((x, h - pad - (h - 2 * pad) * ms / top, "ms"))
            else:
                out.append((x, h - pad, "sans mesure" if present else "absent"))
        return out

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.setPen(QPen(QColor(T["border"]), 1))
        p.drawLine(6, h - 6, w - 6, h - 6)
        line, prev = QPen(QColor(T["acc"]), 1.8), None
        for x, y, state in self.points(w, h):
            if state == "ms":
                if prev is not None:
                    p.setPen(line); p.drawLine(QPointF(*prev), QPointF(x, y))
                p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(T["acc"])); p.drawEllipse(QPointF(x, y), 2.2, 2.2)
                prev = (x, y)
            else:
                prev = None                                            # trou : la ligne se coupe
                if state == "absent":
                    p.setPen(QPen(QColor(T["bad"]), 2)); p.drawLine(QPointF(x, h - 6), QPointF(x, h - 14))
                else:
                    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(T["mut"])); p.drawEllipse(QPointF(x, h - 6), 1.6, 1.6)


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
