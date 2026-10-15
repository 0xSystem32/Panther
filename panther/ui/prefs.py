"""Fenêtre principale – prefs."""
import json

from PyQt6.QtWidgets import QApplication, QMessageBox

from .. import i18n, networks, ouiupdate, secrets
from ..i18n import tr
from ..scanner import local_network
from .theme import T, THEMES, THEME_MODES, make_style, resolve_theme, set_text_scale, text_scale_of
from .util import log, snmp_secret
from .settings_dialogs import NetworksDialog, OuiWorker
from .wizard import WelcomeWizard, apply_welcome_settings


class PrefsMixin:
    """Méthodes de la fenêtre principale : prefs."""

    def update_oui(self):
        if getattr(self, "oui_worker", None) and self.oui_worker.isRunning():
            return
        if self.demo:
            QMessageBox.information(self, tr("Démonstration"), tr("Mode démonstration : aucun téléchargement n'est effectué.")); return
        ok = QMessageBox.question(self, tr("Mettre à jour la base des fabricants"),
                                  tr("Panther va télécharger le registre officiel des fabricants (IEEE) depuis\n{url}\n(environ 6 Mo) et "
                                     "l'enregistrer dans :\n{user_path}\n\nAucune donnée de votre réseau n'est envoyée. Continuer ?", url=ouiupdate.URL, user_path=ouiupdate.USER_PATH)) == QMessageBox.StandardButton.Yes
        if not ok:
            return
        self.status.setText(tr("Téléchargement de la base des fabricants…"))
        self.oui_worker = OuiWorker(self)
        self.oui_worker.done.connect(self.on_oui_done)
        self.oui_worker.failed.connect(self.on_oui_failed)
        self.oui_worker.start()

    def on_oui_done(self, n):
        self.status.setText(tr("Base des fabricants mise à jour : {n} entrées", n=n))
        QMessageBox.information(self, tr("Base des fabricants"), tr("{n} fabricants enregistrés. Les nouveaux noms apparaîtront au prochain scan.", n=n))

    def on_oui_failed(self, message):
        self.status.setText(tr("Mise à jour de la base des fabricants impossible"))
        QMessageBox.warning(self, tr("Base des fabricants"), tr("La base n'a pas été modifiée.\n\n{message}", message=message))

    def open_welcome(self):
        """Rouvre l'assistant : les choix s'appliquent tout de suite (sauf la langue, au prochain démarrage)."""
        old_lang = i18n.language()
        wiz = WelcomeWizard(parent=self)
        accepted = wiz.exec()
        v = wiz.values()
        i18n.set_language(old_lang)  # l'assistant a pu changer la langue le temps de son affichage : on la rétablit
        if not accepted:
            return
        apply_welcome_settings(self.settings, v)
        self.set_theme_mode(v["theme"], save=False); self.set_text_size(v["text_size"], save=False)
        self.depth.setCurrentIndex(max(self.depth.findData(v["depth"]), 0))
        self.act_passive.setChecked(v["passive"]); self.toggle_passive(v["passive"])
        self.security_on = v["security"] and not v["passive"]
        self.act_security.setChecked(self.security_on)
        self.security_consent = self.security_consent or self.security_on
        self.refresh_security()
        self.auto_actions[v["auto_minutes"]].setChecked(True); self.set_auto(v["auto_minutes"])
        if v["language"] != old_lang:
            QMessageBox.information(self, tr("Langue"), tr("La langue sera appliquée au prochain démarrage de Panther."))
        self.status.setText(tr("Réglages enregistrés"))

    def choose_language(self, code):
        """Mémorise la langue ; elle s'applique au prochain démarrage (tous les textes sont construits au lancement)."""
        if code == i18n.language() and self.settings.value("language", "") == code:
            return
        self.settings.setValue("language", code)
        if code != i18n.language():
            QMessageBox.information(self, tr("Langue"), tr("La langue sera appliquée au prochain démarrage de Panther."))

    # ---------- divers ----------
    def set_theme_mode(self, mode, save=True):
        """Thème : automatique (suit le système), sombre, clair ou contraste élevé."""
        self.theme_mode = mode if mode in THEME_MODES else "auto"
        if save:
            self.settings.setValue("theme", self.theme_mode)
        if self.theme_actions.get(self.theme_mode):
            self.theme_actions[self.theme_mode].setChecked(True)
        self.apply_theme(resolve_theme(self.theme_mode))

    def on_system_theme(self, *_args):
        if self.theme_mode == "auto":
            self.apply_theme(resolve_theme("auto"))

    def set_text_size(self, key, save=True):
        """Taille du texte (petit, normal, grand, très grand) : interface et carte."""
        self.text_size = key if key in self.size_actions else "normal"
        if save:
            self.settings.setValue("text_size", self.text_size)
        self.size_actions[self.text_size].setChecked(True)
        set_text_scale(text_scale_of(self.text_size))
        QApplication.instance().setStyleSheet(make_style())
        if self.devices:
            self.rebuild()
        self.refresh_panel(); self.view.viewport().update()

    def apply_theme(self, name):
        T.update(THEMES[name])
        QApplication.instance().setStyleSheet(make_style())
        if self.devices:
            self.rebuild()
        self.refresh_panel(); self.view.viewport().update()

    def update_netlabel(self):
        n = len(self.targets)
        self.net_btn.setText(tr("Réseaux ({n})", n=n + 1) if n else tr("Réseaux…"))
        if self.network:
            vlan = f"  ·  VLAN {self.network['vlan']}" if self.network.get("vlan") else ""
            extra = tr("  ·  +{n} autre(s) réseau(x)", n=n) if n else ""
            gw = tr("  ·  passerelle {gateway}", gateway=self.network['gateway']) if self.network.get("gateway") else tr("  ·  sans passerelle")
            kind = f" ({networks.LINK_LABELS.get(self.network.get('kind'), '')})" if self.network.get("kind") else ""
            self.netlabel.setText(tr("  {cidr}{vlan}{gw}  ·  {iface}{kind}{extra}", cidr=self.network['cidr'], vlan=vlan, gw=gw, iface=self.network['iface'], kind=kind, extra=extra))

    def load_snmp(self):
        """Sources SNMP : les hôtes sont dans les réglages, les communautés dans le trousseau (`secrets`).
        Une ancienne configuration (communauté en clair) est migrée vers le trousseau puis effacée des réglages."""
        try:
            raw = json.loads(self.settings.value("snmp", "[]"))
            items = [(str(x["host"]), x.get("community")) for x in raw if isinstance(x, dict)]
        except (ValueError, TypeError, KeyError, AttributeError):
            return []
        sources, legacy = [], False
        for host, comm in items:
            if comm is not None:
                legacy = True
                secrets.set(snmp_secret(host), str(comm))
            sources.append({"host": host, "community": secrets.get(snmp_secret(host)) or ""})
        if legacy:
            self.save_snmp(sources, [])
            log.info("Communautés SNMP déplacées dans %s", secrets.backend())
        return sources

    def save_snmp(self, sources, previous):
        """Enregistre les hôtes (réglages) et les communautés (trousseau) ; oublie celles des hôtes retirés."""
        for host in {s["host"] for s in previous} - {s["host"] for s in sources}:
            secrets.delete(snmp_secret(host))
        for s in sources:
            secrets.set(snmp_secret(s["host"]), s["community"])
        self.settings.setValue("snmp", json.dumps([{"host": s["host"]} for s in sources]))

    def open_networks(self):
        try:
            local = local_network()["cidr"]
        except (RuntimeError, OSError):
            local = None
        dlg = NetworksDialog(local, self.targets, self.snmp, self)
        if dlg.exec():
            previous = self.snmp
            self.targets, self.snmp = dlg.selected(), dlg.snmp_sources()
            self.settings.setValue("targets", json.dumps(self.targets))
            self.save_snmp(self.snmp, previous)
            self.update_netlabel()
            self.status.setText(tr("Plages mises à jour : relancez le scan pour les prendre en compte."))
