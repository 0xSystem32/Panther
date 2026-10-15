"""Fenêtre principale – scan."""
import html
import shutil
import sqlite3
import subprocess
import time

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QInputDialog, QMessageBox, QSystemTrayIcon

from .. import alerts, history, identity, networks, profiles, security, store
from ..i18n import plural, tr
from .icons import type_pixmap
from .settings_dialogs import AlertWorker
from .util import dkey, log


class ScanMixin:
    """Méthodes de la fenêtre principale : scan."""

    # ---------- scan ----------
    def on_scan_button(self):
        if self.scanner.snapshot()["status"] == "scanning":
            self.stop_scan()
        else:
            self.start_scan()

    def stop_scan(self):
        if self.scanner.stop():
            self.status.setText(tr("Arrêt en cours…")); self.btn.setEnabled(False); self.act_stop.setEnabled(False)

    FULL_SCAN_EVERY = 3600  # secondes : au plus un scan complet par heure pendant les scans automatiques

    def sync_depth_menu(self):
        """Le menu Scan → Profondeur suit la liste déroulante de la barre d'outils (et inversement)."""
        actions = getattr(self, "depth_actions", None)
        if actions and self.depth.currentData() in actions:
            actions[self.depth.currentData()].setChecked(True)

    # ---- profils de scan enregistrés (plages, profondeur, interface, hôtes SNMP, options)
    def load_profiles(self):
        import json
        try:
            return profiles.clean(json.loads(self.settings.value("profiles", "[]")))
        except (ValueError, TypeError):
            return []

    def store_profiles(self, plist):
        import json
        self.settings.setValue("profiles", json.dumps(plist))

    def rebuild_profile_menu(self):
        m = self.profile_menu
        m.clear()
        plist = self.load_profiles()
        for p in plist:
            m.addAction(p["name"], lambda p=p: self.apply_profile(p))
        if plist:
            m.addSeparator()
        m.addAction(tr("Enregistrer la configuration actuelle…"), self.save_profile)
        rm = m.addMenu(tr("Supprimer un profil"))
        rm.setEnabled(bool(plist))
        for p in plist:
            rm.addAction(p["name"], lambda n=p["name"]: self.delete_profile(n))

    def current_profile(self, name):
        return profiles.make(name, self.targets, self.depth.currentData(), self.iface_combo.currentData() or "", [s["host"] for s in self.snmp],
                             self.security_on, self.passive_on)

    def save_profile(self, name=None):
        if name is None:
            name, ok = QInputDialog.getText(self, tr("Profil de scan"), tr("Nom du profil :"))
            if not ok:
                return
        try:
            prof = self.current_profile(name)
            self.store_profiles(profiles.upsert(self.load_profiles(), prof))
        except ValueError as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer le profil : {e}", e=e)); return
        self.rebuild_profile_menu()
        self.status.setText(tr("Profil « {name} » enregistré", name=prof["name"]))

    def delete_profile(self, name):
        self.store_profiles(profiles.remove(self.load_profiles(), name))
        self.rebuild_profile_menu()
        self.status.setText(tr("Profil « {name} » supprimé", name=name))

    def apply_profile(self, p):
        """Applique un profil : plages, profondeur, interface, hôtes SNMP (communauté relue dans le trousseau) et options. Le consentement
        à l'analyse de sécurité n'est jamais donné par un profil : sans lui, l'option est ignorée."""
        self.targets = list(p["targets"])
        self.settings.setValue("targets", __import__("json").dumps(self.targets))
        self.depth.setCurrentIndex(max(self.depth.findData(p["depth"]), 0))
        i = self.iface_combo.findData(p["iface"] or None)
        if i >= 0:
            self.iface_combo.setCurrentIndex(i)
        previous = self.snmp
        known = {s["host"]: s for s in self.load_snmp()}  # communauté ou utilisateur v3 déjà enregistrés pour cet hôte (secrets du trousseau)
        self.snmp = [known.get(h) or {"host": h, "community": ""} for h in p["snmp"]]
        self.save_snmp(self.snmp, previous)
        missing = [s["host"] for s in self.snmp if not (s.get("auth_password") if s.get("user") else s.get("community"))]
        self.act_passive.setChecked(p["passive"]); self.toggle_passive(p["passive"])
        want_security = p["security"] and not p["passive"] and self.security_consent
        self.security_on = want_security
        self.act_security.setChecked(want_security); self.settings.setValue("security", want_security)
        self.update_netlabel(); self.refresh_security()
        note = []
        if p["security"] and not want_security and not p["passive"]:
            note.append(tr("analyse de sécurité non activée (consentement à donner dans le menu Sécurité)"))
        if missing:
            note.append(tr("communauté SNMP inconnue pour {hosts}", hosts=", ".join(missing)))
        self.status.setText(tr("Profil « {name} » appliqué : relancez le scan", name=p["name"]) + ("  ·  " + " ; ".join(note) if note else ""))

    def choose_depth(self, auto=False, now=None):
        """Profondeur réellement utilisée et appareils connus. Le scan de présence réutilise les détails du dernier
        scan complet : il n'a de sens que s'il y en a un, et les scans automatiques refont un scan complet toutes les heures.
        En écoute seule, on ne sonde rien : on lit la table du noyau et on reprend les détails du dernier scan complet."""
        if self.passive_on:
            try:
                return "ecoute", history.last_snapshot_map()
            except (sqlite3.Error, OSError):
                return "ecoute", {}
        chosen = self.depth.currentData()
        now = time.time() if now is None else now
        want_presence = chosen == "presence" or (auto and now - self.last_full_scan < self.FULL_SCAN_EVERY)
        if want_presence:
            try:
                known = history.last_snapshot_map()
            except (sqlite3.Error, OSError):
                known = {}
            if known:
                return "presence", known
        return ("normal" if chosen == "presence" else chosen), None

    def start_scan(self, auto=False):
        depth, known = self.choose_depth(auto)
        try:
            aliases = history.alias_map()
        except (sqlite3.Error, OSError):
            aliases = {}
        if self.scanner.start(self.targets, self.snmp, depth, self.security_on and not self.passive_on, self.iface_combo.currentData() or None, known, aliases):
            self.t0, self.last_scan_auto, self.last_new = time.time(), auto, []
            self.act_scan.setEnabled(False); self.act_stop.setEnabled(True)
            self.progress.setValue(0); self.progress.show(); self.timer.start(700)

    def poll(self):
        s = self.scanner.snapshot()
        self.progress.setValue(s["progress"])
        if s["network"]:
            self.network = s["network"]; self.networks_info = s.get("networks", [])
            self.scan_extra = {k: s.get(k) for k in ("neighbors", "neighbors_status", "paths", "warnings", "snmp")}
            self.update_netlabel()
        busy = s["status"] == "scanning"
        if busy:
            self.live_update(s["devices"])
        elapsed = int(time.time() - self.t0)
        self.update_count()
        if busy:
            phase = tr("Découverte des hôtes") if s["progress"] < 60 else tr("Analyse des appareils")
            if self.btn.isEnabled():
                self.btn.setText(tr("Arrêter le scan ({progress} %)", progress=s['progress']))
            self.status.setText(tr("{phase}  ·  {elapsed} s  ·  profondeur {depth}", phase=phase, elapsed=elapsed, depth=s['depth']))
            return
        self.timer.stop(); self.progress.hide()
        self.btn.setEnabled(True); self.act_scan.setEnabled(True); self.act_stop.setEnabled(False)
        self.btn.setText(tr("Relancer le scan"))
        if s["status"] == "error":
            self.status.setText(tr("Erreur : {error}", error=s['error']))
        elif s["status"] == "stopped":
            self.devices = s["devices"]; self.rebuild(); self.update_count()
            self.status.setText(tr("Scan interrompu : {devices_count} appareil(s) analysé(s) avant l'arrêt", devices_count=len(self.devices)) if self.devices
                                else tr("Scan interrompu pendant la découverte : aucun appareil n'avait encore été analysé"))
            self.fit()
        else:
            self.finish_scan(s, elapsed)
        self.refresh_panel()

    def finish_scan(self, s, elapsed):
        """Scan terminé : mémorisation, nouveaux appareils, appareils hors ligne, notification."""
        online, res, offline, note = list(s["devices"]), {"new": [], "baseline": False}, [], ""
        fr = {"new": [], "fixed": [], "baseline": False}
        try:
            res = history.record_scan(online, networks=[n["cidr"] for n in s["networks"]], depth=s["depth"])
            history.annotate(online)
            fr = history.record_findings(online)
            new = set(res["new"])
            for d in online:
                d["new"] = dkey(d) in new
            offline = self.load_offline(online, s["networks"])
        except (sqlite3.Error, OSError) as e:
            log.warning(tr("Historique indisponible"), exc_info=True)
            note = tr("  ·  historique indisponible ({e})", e=e)
        self.devices = online + offline
        self.rebuild(animate=True); self.update_count(); self.refresh_journal(); self.refresh_security()
        self.last_new = [f"{d['hostname'] or d['ip']}  ·  {d['ip']}" for d in online if d.get("new")]
        light = s.get("depth") in ("presence", "ecoute")
        if not light:
            self.last_full_scan = time.time()
            self.settings.setValue("last_full_scan", self.last_full_scan)
        msg = (tr("Écoute terminée en {elapsed} s", elapsed=elapsed) if s.get("depth") == "ecoute" else tr("Scan de présence terminé en {elapsed} s", elapsed=elapsed)
               if light else tr("Scan terminé en {elapsed} s", elapsed=elapsed))
        if res["baseline"]:
            msg += tr("  ·  première analyse : {online_count} appareil(s) enregistrés comme connus", online_count=len(online))
        elif self.last_new:
            msg += tr("  ·  {last_new_count} nouvel appareil", last_new_count=len(self.last_new)) + ("s" if len(self.last_new) > 1 else "")
            if self.last_scan_auto:
                first = [d["hostname"] or d["ip"] for d in online if d.get("new")][:3]
                self.notify(tr("Panther : nouvel appareil sur le réseau"), ", ".join(first) + ("…" if len(self.last_new) > 3 else ""))
        if self.security_on and fr["baseline"]:
            msg += tr("  ·  analyse de sécurité : référence enregistrée")
        if fr["new"]:
            msg += "  ·  " + plural(len(fr["new"]), "nouvelle exposition", "nouvelles expositions")
            bad = [(d, f) for d, f in fr["new"] if security.RANK[f["severity"]] >= security.RANK["élevé"]]
            if bad and self.last_scan_auto:
                d, f = bad[0]
                self.notify(tr("Panther : nouvelle exposition"), tr("{hostname} : {title}", hostname=d['hostname'] or d['ip'], title=f['title']) + ("…" if len(bad) > 1 else ""))
        if fr["fixed"]:
            msg += "  ·  " + plural(len(fr["fixed"]), "exposition corrigée", "expositions corrigées")
        self.send_alerts(online, res, fr, auto=self.last_scan_auto)
        self.dup_suggestions = identity.suggest_duplicates(self.devices)
        if self.dup_suggestions:
            msg += "  ·  " + plural(len(self.dup_suggestions), "doublon possible", "doublons possibles") + tr(" (menu Scan)")
        w = len(self.scan_extra.get("warnings") or [])
        self.status.setText(msg + (tr("  ·  {w} avertissement(s)", w=w) if w else "") + note)
        self.fit()

    def load_offline(self, online, nets):
        """Appareils connus mais absents de ce scan (masqués si l'option est désactivée)."""
        if not self.show_offline:
            return []
        off = history.known_offline({dkey(d) for d in online}, [n["cidr"] for n in nets])
        ov = store.load()
        for d in off:
            store.apply(d, ov)
        return off

    def toggle_offline(self, on):
        self.show_offline = on
        self.settings.setValue("show_offline", on)
        online = [d for d in self.devices if d.get("online", True)]
        if online and self.scanner.snapshot()["status"] != "scanning":
            try:
                self.devices = online + self.load_offline(online, self.networks_info)
            except (sqlite3.Error, OSError):
                return
            self.rebuild(); self.update_count(); self.refresh_panel()

    def populate_ifaces(self):
        cur = self.iface_combo.currentData() if self.iface_combo.count() else self.settings.value("iface", "")
        cb = self.iface_combo
        cb.blockSignals(True); cb.clear()
        cb.addItem(tr("Automatique"), "")
        for it in networks.interfaces():
            cb.addItem(tr("{iface}  ·  {link_labels_label}", iface=it['iface'], link_labels_label=networks.LINK_LABELS.get(it['kind'], '')), it["iface"])
            cb.setItemData(cb.count() - 1, f"{it['ip']}  ({it['cidr']})", Qt.ItemDataRole.ToolTipRole)
        cb.setCurrentIndex(max(cb.findData(cur), 0))
        cb.blockSignals(False)

    def send_alerts(self, online, res, fr, auto):
        """Après un scan : alerte (webhook / e-mail) sur les événements choisis, en arrière-plan. Jamais pour la première analyse."""
        try:
            cfg = alerts.load()
            if not cfg["enabled"] or (cfg["events"]["auto_only"] and not auto) or not (cfg["webhook"]["enabled"] or cfg["email"]["enabled"]):
                return
            events = alerts.build_events(online, res, fr, cfg, res.get("event_list", []))
        except Exception:
            log.exception("Préparation des alertes")
            return
        if not events:
            return
        worker = AlertWorker(cfg, events, self)
        worker.finished_with.connect(self.on_alerts_sent)
        self._alert_workers = [w for w in getattr(self, "_alert_workers", []) if w.isRunning()] + [worker]
        worker.start()

    def on_alerts_sent(self, results):
        bad = [f"{c} : {err}" for c, ok, err in results if not ok]
        self.status.setText((tr("Alerte envoyée (") + ", ".join(c for c, ok, _ in results if ok) + ")") if not bad
                            else tr("Alerte non envoyée : ") + " ; ".join(bad))

    def toggle_passive(self, on):
        self.passive_on = on
        self.settings.setValue("passive", on)
        self.depth.setEnabled(not on)
        if getattr(self, "depth_menu", None) is not None:
            self.depth_menu.setEnabled(not on)
        self.status.setText(tr("Écoute seule : Panther n'enverra plus rien sur le réseau (il lit la table des voisins du noyau et "
                               "les baux DHCP)") if on
                            else tr("Écoute seule désactivée"))

    def update_count(self):
        on = sum(1 for d in self.devices if d.get("online", True))
        off = len(self.devices) - on
        self.count.setText(tr("{on} en ligne", on=on) + (tr("  ·  {off} hors ligne", off=off) if off else "") + "   ")

    def set_auto(self, minutes):
        self.settings.setValue("auto_minutes", minutes)
        self.auto_timer.stop()
        if minutes:
            self.auto_timer.start(minutes * 60000)
        self.auto_label.setText(tr("Scan auto : toutes les {minutes} min   ", minutes=minutes) if minutes else "")

    def auto_tick(self):
        if self.scanner.snapshot()["status"] != "scanning":
            self.start_scan(auto=True)

    def notify(self, title, message):
        """Notification de bureau : zone de notification Qt si disponible, sinon notify-send."""
        if QSystemTrayIcon.isSystemTrayAvailable():
            if self.tray is None:
                self.tray = QSystemTrayIcon(QIcon(type_pixmap("router", 32)), self); self.tray.show()
            self.tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 8000)
        elif shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "-a", "Panther", title, html.escape(message)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
