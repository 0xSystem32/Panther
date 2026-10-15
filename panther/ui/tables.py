"""Fenêtre principale – tables."""
import os
import sqlite3

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QIcon
from PyQt6.QtWidgets import QFileDialog, QMessageBox, QTableWidgetItem

from .. import history, security
from ..i18n import tr
from .theme import T, sev_color
from .icons import type_pixmap
from .util import EVENT_LABELS, KEY_ROLE, LABELS, SECURITY_INFO, dkey, ip_key, log, status_text, tip, when
from .widgets import SortItem


class TablesMixin:
    """Méthodes de la fenêtre principale : tables."""

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

    def table_device(self, row):
        it = self.table.item(row, 0) if row >= 0 else None
        return next((x for x in self.devices if it and dkey(x) == it.data(KEY_ROLE)), None)
