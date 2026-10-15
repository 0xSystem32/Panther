"""Fenêtre principale – prefs."""
import json

from PyQt6.QtWidgets import QApplication, QMessageBox

from .. import i18n, networks, ouiupdate, secrets
from ..i18n import tr
from ..scanner import local_network
from .settings_dialogs import NetworksDialog, OuiWorker
from .theme import THEME_MODES, THEMES, T, make_style, resolve_theme, set_text_scale, text_scale_of
from .util import log, snmp_secret, snmp_v3_secret


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

    def choose_language(self, code):
        """Mémorise la langue ; elle s'applique au prochain démarrage (tous les textes sont construits au lancement)."""
        if code == i18n.language() and self.settings.value("language", "") == code:
            return
        self.settings.setValue("language", code)
        if code != i18n.language():
            QMessageBox.information(self, tr("Langue"), tr("La langue sera appliquée au prochain démarrage de Panther."))

    # ---------- divers ----------
    def toggle_animations(self, on):
        """Animation de la carte (les nœuds glissent à leur place à la fin d'un scan). À couper si le mouvement gêne."""
        self.animations = bool(on)
        self.settings.setValue("animations", self.animations)
        if not on:
            self.stop_animation()

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

    def effective_targets(self):
        """Plages à scanner en plus du réseau local : celles que vous avez ajoutées, plus (si l'option est active) les autres réseaux
        auxquels cette machine est déjà reliée (autres interfaces, routes, VLAN)."""
        extra = []
        if self.auto_networks:
            try:
                local = (self.network or local_network())["cidr"]
                extra = [c for c in networks.auto_targets(local) if c not in self.targets]
            except (RuntimeError, OSError, KeyError):
                extra = []
        return list(self.targets) + extra

    def update_netlabel(self):
        n = len(self.effective_targets())
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
            items = [x for x in raw if isinstance(x, dict) and "host" in x]
        except (ValueError, TypeError, KeyError, AttributeError):
            return []
        sources, legacy = [], False
        for x in items:
            host, comm = str(x["host"]), x.get("community")
            if x.get("user"):  # SNMP v3 : l'utilisateur et l'algorithme sont dans les réglages, le mot de passe dans le trousseau
                sources.append({"host": host, "user": str(x["user"]), "auth_proto": str(x.get("proto") or "sha1"),
                                "auth_password": secrets.get(snmp_v3_secret(host)) or ""})
                continue
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
            secrets.delete(snmp_secret(host)); secrets.delete(snmp_v3_secret(host))
        entries = []
        for s in sources:
            if s.get("user"):
                secrets.set(snmp_v3_secret(s["host"]), s.get("auth_password", ""))
                secrets.delete(snmp_secret(s["host"]))
                entries.append({"host": s["host"], "user": s["user"], "proto": s.get("auth_proto", "sha1")})
            else:
                secrets.set(snmp_secret(s["host"]), s.get("community", ""))
                secrets.delete(snmp_v3_secret(s["host"]))
                entries.append({"host": s["host"]})
        self.settings.setValue("snmp", json.dumps(entries))

    def open_networks(self):
        try:
            local = local_network()["cidr"]
        except (RuntimeError, OSError):
            local = None
        dlg = NetworksDialog(local, self.targets, self.snmp, self, auto=self.auto_networks)
        if dlg.exec():
            previous = self.snmp
            self.targets, self.snmp = dlg.selected(), dlg.snmp_sources()
            self.auto_networks = dlg.auto_enabled()
            self.settings.setValue("targets", json.dumps(self.targets))
            self.settings.setValue("auto_networks", self.auto_networks)
            self.save_snmp(self.snmp, previous)
            self.update_netlabel()
            self.status.setText(tr("Plages mises à jour : relancez le scan pour les prendre en compte."))
