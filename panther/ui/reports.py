"""Fenêtre principale – reports."""
import os
import sqlite3
import time

from PyQt6.QtWidgets import QFileDialog, QMessageBox

from .. import compare, exporter, history, reportpdf, schedule
from ..i18n import tr
from .settings_dialogs import ReportScheduleDialog
from .util import log


class ReportsMixin:
    """Méthodes de la fenêtre principale : reports."""

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
