"""Dialogues de réglages : alertes, rapports planifiés, base des fabricants, réseaux et SNMP."""
import ipaddress
import os

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from .. import alerts, networks, ouiupdate, schedule, secrets, security, snmpv3
from ..i18n import N_, tr
from .util import log, when


class AlertWorker(QThread):
    """Envoie les alertes en arrière-plan (un serveur lent ne doit jamais figer la fenêtre)."""
    finished_with = pyqtSignal(list)

    def __init__(self, cfg, events, parent=None, webhook_url=None, smtp_password=None):
        super().__init__(parent)
        self.cfg, self.events, self.webhook_url, self.smtp_password = cfg, events, webhook_url, smtp_password

    def run(self):
        try:
            res = alerts.dispatch(self.cfg, self.events, webhook_url=self.webhook_url, smtp_password=self.smtp_password)
        except Exception as e:
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
        except Exception as e:
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
        self.snmp_ver = QComboBox(); self.snmp_ver.addItem("v2c", "v2c"); self.snmp_ver.addItem(tr("v3 (authentification)"), "v3")
        self.snmp_ver.setToolTip(tr("v3 : utilisateur et mot de passe (HMAC SHA ou MD5), sans chiffrement : les réponses circulent en clair."))
        self.snmp_pass = QLineEdit(); self.snmp_pass.setPlaceholderText(tr("Mot de passe (8 caractères au moins)"))
        self.snmp_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.snmp_proto = QComboBox()
        for key, label in (("sha1", "SHA-1"), ("sha256", "SHA-256"), ("md5", "MD5")):
            self.snmp_proto.addItem(label, key)
        self.snmp_ver.currentIndexChanged.connect(self.on_snmp_version)
        snmp_add = QPushButton(tr("Ajouter")); snmp_add.clicked.connect(self.add_snmp)
        snmp_del = QPushButton(tr("Retirer")); snmp_del.clicked.connect(self.remove_snmp)
        srow = QHBoxLayout(); srow.addWidget(self.snmp_host, 1); srow.addWidget(self.snmp_ver); srow.addWidget(self.snmp_comm, 1); srow.addWidget(snmp_add); srow.addWidget(snmp_del)
        srow3 = QHBoxLayout(); srow3.addWidget(self.snmp_pass, 1); srow3.addWidget(self.snmp_proto)
        self.snmp_v3_row = QWidget(); self.snmp_v3_row.setLayout(srow3); srow3.setContentsMargins(0, 0, 0, 0)
        self.snmp_v3_row.setVisible(False)
        self.snmp_list = QListWidget(); self.snmp_list.setMaximumHeight(84)
        self.sources = []
        for src in snmp_sources:
            self._add_snmp_item(src)
        for w in (snmp_title, snmp_note):
            lay.addWidget(w)
        lay.addLayout(srow); lay.addWidget(self.snmp_v3_row); lay.addWidget(self.snmp_list); lay.addWidget(buttons)
        for n in networks.known_networks(local_cidr):
            self.add_item(n, n["cidr"] in selected)
        for c in selected:
            self.add_item({"cidr": c, "kind": "manuel"}, True)

    def on_snmp_version(self):
        v3 = self.snmp_ver.currentData() == "v3"
        self.snmp_v3_row.setVisible(v3)
        self.snmp_comm.setEchoMode(QLineEdit.EchoMode.Normal if v3 else QLineEdit.EchoMode.Password)
        self.snmp_comm.setPlaceholderText(tr("Utilisateur") if v3 else tr("Communauté (lecture)"))

    def _add_snmp_item(self, src):
        self.sources.append(src)
        if src.get("user"):
            self.snmp_list.addItem(tr("{host}  ·  v3 {user} ({proto})", host=src['host'], user=src['user'], proto={"sha1": "SHA-1", "sha256": "SHA-256", "md5": "MD5"}.get(src.get("auth_proto", "sha1"), "?")))
        else:
            self.snmp_list.addItem(tr("{host}  ·  communauté {dots}", host=src['host'], dots='•' * min(len(src['community']), 8)))

    def add_snmp(self):
        host, comm = self.snmp_host.text().strip(), self.snmp_comm.text().strip()
        try:
            if not ipaddress.ip_address(host).is_private:
                raise ValueError(tr("Seules les adresses privées sont acceptées."))
        except ValueError as e:
            self.msg.setText(str(e) if tr("Seules les adresses privées sont acceptées.") in str(e) else tr("« {host} » n'est pas une adresse IP valide.", host=host)); return
        if self.snmp_ver.currentData() == "v3":
            try:
                snmpv3.V3User(comm, self.snmp_pass.text(), self.snmp_proto.currentData())  # valide l'utilisateur et le mot de passe
            except ValueError:
                self.msg.setText(tr("SNMP v3 : indiquez un utilisateur et un mot de passe de 8 caractères au moins.")); return
            self._add_snmp_item({"host": host, "user": comm, "auth_proto": self.snmp_proto.currentData(), "auth_password": self.snmp_pass.text()})
            self.snmp_pass.clear()
        else:
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
