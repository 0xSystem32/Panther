"""La carte : nœuds, liens, zones et vue (mini-carte, lasso, clavier)."""
import math

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QFrame, QGraphicsItem, QGraphicsLineItem, QGraphicsPathItem, QGraphicsView

from .. import security
from ..i18n import tr
from . import theme
from .icons import draw_icon, type_pixmap
from .theme import T, fs, sev_color, type_color
from .util import LABELS, seen_label, tip


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
        rh, cw = int(20 * theme.FONT_SCALE), int(176 * theme.FONT_SCALE)   # lignes et colonnes suivent la taille du texte
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
