"""Fenêtre principale – mapctl."""
import math
import os
import sqlite3
import time

from PyQt6.QtCore import QEasingCurve, QPointF, QRectF, QSize, Qt, QVariantAnimation
from PyQt6.QtGui import QColor, QImage, QPainter
from PyQt6.QtWidgets import QFileDialog, QMessageBox

from .. import history, layout, security
from ..i18n import tr
from .mapview import ElbowLink, Hub, Link, Node, Zone
from .theme import THEMES, T
from .util import KEY_ROLE, LABELS, dkey, log, status_text


class MapMixin:
    """Méthodes de la fenêtre principale : mapctl."""

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

    def stop_animation(self):
        anim = getattr(self, "_anim", None)
        if anim is not None:
            anim.stop()
            self._anim = None

    def animate_nodes(self, start, duration=380):
        """Les nœuds partent de `start` ({clé: position}) et glissent vers leur place définitive, au lieu d'y sauter d'un coup."""
        moves = []
        for k, n in self.nodes.items():
            a = start.get(k)
            if a is not None and (a - n.pos()).manhattanLength() > 2:
                moves.append((n, a, QPointF(n.pos())))
                n.setPos(a)
        if not moves:
            return
        anim = QVariantAnimation(self)
        anim.setDuration(duration); anim.setStartValue(0.0); anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        def step(t):
            for n, a, b in moves:
                n.setPos(a + (b - a) * float(t))
        anim.valueChanged.connect(step)
        anim.finished.connect(lambda: [n.setPos(b) for n, _a, b in moves])  # position exacte à la fin
        self._anim = anim
        anim.start()

    def rebuild(self, animate=False):
        self._last_rebuild = time.time()
        self.stop_animation()
        before = {k: QPointF(n.pos()) for k, n in self.nodes.items()} if (animate and getattr(self, "animations", False)) else {}
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
        if before:
            self.animate_nodes(before)
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
