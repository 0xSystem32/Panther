"""Fenêtres de dialogue : appareil, comparaison, fusion, doublons, étiquettes, règles, données."""
import os
import sqlite3

from PyQt6.QtCore import QUrl, Qt
from PyQt6.QtGui import QColor, QDesktopServices, QIcon
from PyQt6.QtWidgets import QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout

from .. import compare, fingerprint, history, privacy, rules, store
from ..i18n import N_, plural, tr
from .theme import T
from .icons import type_pixmap
from .util import LABELS, human_size, seen_label, tip, when


def log_path():
    from .. import log as _log
    return _log.PATH


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
