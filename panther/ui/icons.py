"""Icônes vectorielles des types d'appareils."""
from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QPainter, QPen, QPixmap

from .theme import type_color


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
    elif kind == "settop":  # boîtier plat : lecture, voyant, pieds
        R(-10, -5, 20, 11, 2); p.drawPolyline([QPointF(-6 * u, -1.5 * u), QPointF(-3 * u, 0.5 * u), QPointF(-6 * u, 2.5 * u), QPointF(-6 * u, -1.5 * u)]); L(0, 0.5, 4, 0.5); p.drawEllipse(QPointF(7 * u, 0.5 * u), 0.9 * u, 0.9 * u); L(-6, 6, -6, 8); L(6, 6, 6, 8)
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
