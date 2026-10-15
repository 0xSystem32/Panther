"""Fenêtre principale – panel."""
import sqlite3

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QLabel, QMessageBox

from .. import fingerprint, history, models, security
from ..i18n import plural, tr
from .dialogs import MetaDialog
from .icons import type_pixmap
from .theme import sev_color
from .util import EVENT_LABELS, LABELS, tip, when, when_short
from .widgets import LatencyChart, PresenceBar, WrapLabel, WrappedValue


class PanelMixin:
    """Méthodes de la fenêtre principale : panel."""

    # ---------- panneau latéral ----------
    def add_row(self, key, value, mono=False):
        if not value:
            return
        k = QLabel(key); k.setObjectName("key")
        if WrappedValue.needed(value):  # adresse IPv6, MAC, bannière sans espace : un QLabel déborderait du panneau
            self.form.addRow(k, WrappedValue(str(value), mono))
            return
        v = WrapLabel(str(value))
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if mono:
            v.setFont(QFont("monospace", 9))
        self.form.addRow(k, v)

    def add_finding_row(self, f):
        k = QLabel(security.LABELS[f["severity"]]); k.setStyleSheet(f"color: {sev_color(f['severity'])}; font-weight: 600;")
        text = f["title"] + (tr("  (port {port})", port=f['port']) if f.get("port") else "") + (tr("\nÀ faire : {remedy}", remedy=f['remedy']) if f["remedy"] else "")
        v = WrapLabel(text)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if f["detail"]:
            v.setToolTip(tip(f["detail"]))
        self.form.addRow(k, v)

    def on_trust_button(self):
        if len(self.selected_keys) > 1:
            self.trust_selection()
        else:
            self.toggle_trust(self.current_device())

    def on_meta_button(self):
        if len(self.selected_keys) > 1:
            self.edit_meta_selection()
        else:
            self.edit_meta(self.current_device())

    def trust_selection(self):
        """Sélection multiple : si tous sont de confiance on retire la confiance, sinon on l'accorde à tous."""
        devs = self.selected_devices()
        if not devs:
            return
        flag = not all(d.get("trusted") for d in devs)
        try:
            history.set_trusted(devs, flag)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer la confiance :\n{e}", e=e)); return
        self.refresh_views(); self.refresh_journal()
        self.status.setText(tr("{count} marqués de confiance", count=plural(len(devs), "appareil", "appareils")) if flag
                            else tr("Confiance retirée à {count}", count=plural(len(devs), "appareil", "appareils")))

    def edit_meta_selection(self):
        devs = self.selected_devices()
        if not devs:
            return
        try:
            groups = history.meta_groups()
        except (sqlite3.Error, OSError):
            groups = []
        dlg = MetaDialog(devs[0], groups, self, count=len(devs))
        if not dlg.exec():
            return
        group, tags, _note = dlg.values()
        added = [t for t in tags.replace(";", ",").split(",") if t.strip()]
        try:
            for d in devs:
                history.set_meta(d, tags=list(d.get("tags", [])) + added if added else None, group=group if group.strip() else None)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer :\n{e}", e=e)); return
        self.refresh_views()
        self.status.setText(tr("Étiquettes et groupe enregistrés pour {count}", count=plural(len(devs), "appareil", "appareils")))

    def refresh_multi_panel(self, devs):
        """Panneau d'une sélection multiple : résumé par type, liste des appareils, actions groupées."""
        kinds = {}
        for d in devs:
            kinds[d["type"]] = kinds.get(d["type"], 0) + 1
        self.edit_btn.setVisible(False); self.trust_btn.setVisible(True); self.meta_btn.setVisible(True)
        self.trust_btn.setText(tr("Retirer la confiance à la sélection") if all(d.get("trusted") for d in devs)
                               else tr("Marquer la sélection comme de confiance"))
        self.meta_btn.setText(tr("Étiquettes et groupe de la sélection…"))
        self.side_icon.setPixmap(type_pixmap("net", 40))
        self.side_title.setText(tr("{count} sélectionnés", count=plural(len(devs), "appareil", "appareils")))
        self.side_sub.setText("  ·  ".join(f"{LABELS.get(k, k)} {n}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])))
        self.add_row(tr("Appareils"), "\n".join(f"• {d['hostname'] or d['ip']}  ({d['ip']})" for d in devs[:15]) + ("\n…" if len(devs) > 15 else ""))
        self.add_row(tr("Confiance"), tr("{trusted} sur {total} de confiance", trusted=sum(1 for d in devs if d.get("trusted")), total=len(devs)))
        groups = sorted({d.get("group", "") for d in devs if d.get("group")})
        self.add_row(tr("Groupe"), ", ".join(groups))
        worst = max((security.worst(d.get("security")) for d in devs if d.get("security")), key=lambda w: security.RANK.get(w, -1), default="")
        if worst:
            self.add_row(tr("Exposition"), tr("Gravité maximale : {severity}", severity=security.LABELS[worst]))

    def refresh_panel(self):
        while self.form.rowCount():
            self.form.removeRow(0)
        self.meta_btn.setText(tr("Étiquettes, notes et groupe…"))
        if len(self.selected_keys) > 1:
            self.refresh_multi_panel(self.selected_devices())
            return
        d = self.current_device()
        self.edit_btn.setVisible(bool(d)); self.trust_btn.setVisible(bool(d)); self.meta_btn.setVisible(bool(d))
        if d:
            self.trust_btn.setText(tr("Retirer la confiance") if d.get("trusted") else tr("Marquer comme appareil de confiance"))
        if d:
            self.side_icon.setPixmap(type_pixmap(d["type"], 40))
            self.side_title.setText(d["hostname"] or d["ip"])
            self.side_sub.setText(LABELS.get(d["type"], ""))
            if not d.get("online", True):
                self.add_row(tr("Statut"), tr("Hors ligne · dernière apparition le {date}", date=when(d['last_seen'])))
            elif d.get("new"):
                self.add_row(tr("Statut"), tr("Nouvel appareil (première apparition)"))
            self.add_row(tr("Adresse IP"), d["ip"], True)
            self.add_row(tr("Adresse MAC"), d["mac"], True)
            self.add_row(tr("Adresses IPv6"), "\n".join(d.get("ipv6") or []), True)
            self.add_row(tr("Réseau"), d.get("network", "") + (tr("  ·  VLAN {vlan}", vlan=d['vlan']) if d.get("vlan") else ""), True)
            self.add_row(tr("Fabricant"), d["vendor"])
            c = d.get("cert") or {}
            if c:
                who = c.get("cn") or c.get("o") or tr("certificat sans nom")
                self.add_row(tr("Certificat HTTPS"), who + (tr("  ·  émis par {issuer}", issuer=c['issuer']) if c.get("issuer") and not c.get("self_signed") else tr("  ·  auto-signé"))
                             + (tr("  ·  expiré le {not_after}", not_after=c['not_after']) if c.get("expired") else tr("  ·  expire le {not_after}", not_after=c['not_after']) if c.get("not_after") else ""))
            if d.get("switch_port"):
                self.add_row(tr("Switch"), tr("{switch}  ·  {switch_port}", switch=d.get('switch', ''), switch_port=d['switch_port']))
            if d.get("path"):
                self.add_row(tr("Chemin"), "  →  ".join(h or "*" for h in d["path"]), True)
            self.add_row(tr("Modèle"), models.describe(d.get("model", "")))
            self.add_row(tr("Système"), d["os"])
            self.add_row(tr("TTL"), str(d["ttl"]) if d["ttl"] else "")
            self.add_row(tr("Services"), "  ·  ".join(d["services"]))
            self.add_row(tr("Ports"), ", ".join(map(str, d["ports"])), True)
            for p, b in d["banners"].items():
                self.add_row(tr("Port {p}", p=p), b)
            if d.get("mdns_services"):
                self.add_row(tr("Annonces"), "\n".join(d["mdns_services"]), True)
            if d["type"] != "unknown" or d.get("reasons"):
                conf = d.get("confidence", 0)
                self.add_row(tr("Détection"), tr("{labels_label} · confiance {confidence_label} ({conf} %)", labels_label=LABELS.get(d['type'], ''), confidence_label=fingerprint.confidence_label(conf), conf=conf))
                self.add_row(tr("Indices"), "\n".join("• " + r for r in d.get("reasons", [])))
            if d.get("light"):
                self.add_row(tr("Analyse"), tr("Présence confirmée ; détails repris du dernier scan complet"))
            self.add_row(tr("Confiance"), tr("De confiance") if d.get("trusted") else tr("Non vérifié"))
            self.add_row(tr("Groupe"), d.get("group", ""))
            self.add_row(tr("Étiquettes"), "  ·  ".join(d.get("tags", [])))
            self.add_row(tr("Notes"), d.get("note", ""))
            if d.get("security") is not None:
                if d["security"]:
                    for f in d["security"]:
                        self.add_finding_row(f)
                else:
                    self.add_row(tr("Exposition"), tr("Aucun constat"))
            try:
                h = history.device_summary(d)
            except (sqlite3.Error, OSError):
                h = None
            if h:
                self.add_row(tr("Première apparition"), when(h["first_seen"]))
                self.add_row(tr("Dernière apparition"), tr("à l'instant") if d.get("online", True) else when(h["last_seen"]))
                if h["presence"]:
                    k = QLabel(tr("Présence")); k.setObjectName("key")
                    self.form.addRow(k, PresenceBar(h["presence"]))
                try:
                    series = history.latency_series(d)
                except (sqlite3.Error, OSError):
                    series = []
                stats = history.latency_summary(series)
                if stats and stats["n"] >= 2:
                    k = QLabel(tr("Latence")); k.setObjectName("key")
                    self.form.addRow(k, LatencyChart(series))
                    self.add_row(tr("Latence (ms)"), tr("moy. {avg} · min {low} · max {high} · {missed} sans réponse", avg=f"{stats['avg']:.1f}",
                                                       low=f"{stats['min']:.1f}", high=f"{stats['max']:.1f}", missed=stats["missed"]))
                if h["uptime7"] is not None:
                    self.add_row(tr("Disponibilité"), tr("{uptime} % sur 7 jours", uptime=h['uptime7']))
                if h["events"]:
                    self.add_row(tr("Historique"), "\n".join(f"{when_short(e['ts'])}  {EVENT_LABELS.get(e['kind'], e['kind'])}"
                                                         + (f"  ({e['detail']})" if e["detail"] and e["kind"] != "first_seen" else "")
                                                         for e in h["events"]))
            if d["is_gateway"]:
                self.add_row(tr("Rôle"), tr("Passerelle par défaut"))
            if d["is_self"]:
                self.add_row(tr("Rôle"), tr("Machine locale"))
        else:
            self.side_icon.setPixmap(type_pixmap("router", 40))
            self.side_title.setText(tr("Réseau local"))
            self.side_sub.setText(tr("Aucune sélection"))
            if self.network:
                self.add_row(tr("Sous-réseau"), self.network["cidr"], True)
                self.add_row(tr("Passerelle"), self.network["gateway"], True)
                self.add_row(tr("Interface"), self.network["iface"], True)
                on = sum(1 for x in self.devices if x.get("online", True))
                self.add_row(tr("Appareils"), tr("{on} en ligne", on=on) + (tr("  ·  {devices_count} hors ligne", devices_count=len(self.devices) - on) if len(self.devices) > on else ""))
                kinds = {}
                for x in self.devices:
                    kinds[x["type"]] = kinds.get(x["type"], 0) + 1
                for k, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
                    self.add_row(LABELS[k], str(n))
                if self.last_new:
                    self.add_row(tr("Nouveaux"), "\n".join(self.last_new))
                if self.dup_suggestions:
                    self.add_row(tr("Doublons possibles"), "\n".join(f"{n['hostname'] or n['ip']} ≈ {o['hostname'] or o['ip']} (hors ligne)"
                                                                 for n, o, _ in self.dup_suggestions))
                if self.security_on and any(x.get("security") is not None for x in self.devices):
                    c = security.count_by_severity(self.devices)
                    self.add_row(tr("Sécurité"), " · ".join(f"{n} {security.LABELS[sv].lower()}" for sv, n in c.items() if n) or tr("Aucun constat"))
                ex = self.scan_extra
                for w_ in ex.get("warnings") or []:
                    self.add_row(tr("Attention"), w_)
                for i in ex.get("snmp") or []:
                    self.add_row(tr("SNMP"), tr("{name} : {arp} entrées ARP, {fdb} adresses MAC", name=i['name'] or i['host'], arp=i['arp'], fdb=i['fdb']))
                nb, st = ex.get("neighbors") or [], ex.get("neighbors_status")
                if nb:
                    self.add_row(tr("Voisins"), "\n".join(
                        f"{n.get('name') or n.get('chassis') or n.get('src', '')}  ·  {n.get('port', '')}"
                        + (f"  ·  VLAN {n['vlan']}" if n.get("vlan") else "") + f"  ({n['proto']})" for n in nb))
                elif st == "refusé":
                    self.add_row(tr("Voisins"), tr("LLDP/CDP : droits insuffisants (voir le README)."))
                elif st == "ok":
                    self.add_row(tr("Voisins"), tr("Aucun voisin LLDP/CDP annoncé."))
            else:
                self.add_row("", tr("Lancez un scan pour cartographier le réseau auquel vous êtes connecté."))
