"""Fenêtre principale – devices."""
import os
import sqlite3

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import QMenu, QMessageBox

from .. import fingerprint, history, rules, store, wol
from ..i18n import tr
from ..scanner import reclassify
from .dialogs import CompareDialog, DataDialog, DuplicatesDialog, EditDialog, MergeDialog, MetaDialog, RuleFromDeviceDialog, RulesDialog
from .util import dkey


class DevicesMixin:
    """Méthodes de la fenêtre principale : devices."""

    def edit_meta(self, dev):
        if not dev or dev.get("virtual"):
            return
        try:
            groups = history.meta_groups()
        except (sqlite3.Error, OSError):
            groups = []
        dlg = MetaDialog(dev, groups, self)
        if dlg.exec():
            group, tags, note = dlg.values()
            try:
                history.set_meta(dev, note=note, tags=tags, group=group)
            except (sqlite3.Error, OSError) as e:
                QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer :\n{e}", e=e)); return
            self.refresh_views()
            self.status.setText(tr("Étiquettes et notes enregistrées"))

    def reclassify_all(self):
        """Après un changement de règles : recalcule le type des appareils analysés (les appareils de présence gardent le leur)."""
        ov = store.load()
        try:
            al = history.alias_map()
        except (sqlite3.Error, OSError):
            al = {}
        for d in self.devices:
            if d.get("online", True) and not d.get("light") and not d.get("virtual") and not d.get("is_self"):
                reclassify(d, ov, al)
        if self.devices:
            self.rebuild(); self.update_count(); self.refresh_panel()

    def open_rules(self):
        RulesDialog(self.devices, self.reclassify_all, self).exec()
        self.reclassify_all()

    def create_rule(self, dev):
        if not dev or dev.get("virtual"):
            QMessageBox.information(self, tr("Règle de détection"), tr("Sélectionnez d'abord un appareil."))
            return
        dlg = RuleFromDeviceDialog(dev, self)
        if dlg.exec():
            try:
                rules.add_rule(dlg.build())
            except (OSError, rules.RuleError) as e:
                QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer la règle :\n{e}", e=e)); return
            self.reclassify_all()
            self.status.setText(tr("Règle enregistrée et appliquée aux appareils affichés"))

    def apply_retention(self, scans_days, events_days):
        history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS = int(scans_days), int(events_days)
        self.settings.setValue("keep_scans_days", int(scans_days)); self.settings.setValue("keep_events_days", int(events_days))

    def open_data(self):
        dlg = DataDialog(history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS, self)
        accepted = dlg.exec()
        if dlg.erased:
            self.after_erase()
        if accepted:
            self.apply_retention(*dlg.values())
            if not dlg.erased:
                self.status.setText(tr("Durée de conservation enregistrée"))

    def after_erase(self):
        """L'historique vient d'être effacé : la fenêtre repart de zéro (la prochaine analyse sera une nouvelle référence)."""
        self.devices, self.selected, self.dup_suggestions, self.last_new = [], None, [], []
        self.last_full_scan = 0.0
        self.settings.setValue("last_full_scan", 0.0)
        self.rebuild(); self.update_count(); self.refresh_journal(); self.refresh_security(); self.refresh_panel()
        self.status.setText(tr("Historique effacé"))

    def compare_scans(self):
        try:
            scans = history.list_scans()
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Historique indisponible :\n{e}", e=e)); return
        if len(scans) < 2:
            QMessageBox.information(self, tr("Comparer deux scans"), tr("Il faut au moins deux scans enregistrés. Lancez un scan (ou deux) : chaque scan terminé est "
                                                                    "conservé pour la comparaison."))
            return
        CompareDialog(scans, self).exec()

    def merge_into(self, keep, drop):
        """Regroupe l'historique de `drop` (hors ligne) dans `keep`. Retourne True si la fusion a eu lieu."""
        if not keep or not drop or drop.get("online", True) or keep is drop:
            QMessageBox.information(self, tr("Fusion"), tr("Seul un appareil hors ligne peut être fusionné dans un autre appareil."))
            return False
        try:
            history.merge_devices(dkey(keep), dkey(drop))
            history.annotate([keep])
        except (ValueError, sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Fusion impossible :\n{e}", e=e))
            return False
        store.apply(keep, store.load(), history.alias_map())
        self.devices = [d for d in self.devices if d is not drop]
        self.dup_suggestions = [t for t in self.dup_suggestions if t[0] is not drop and t[1] is not drop]
        self.selected = dkey(keep)
        self.rebuild(); self.update_count(); self.refresh_panel(); self.refresh_journal()
        self.status.setText(tr("{name} fusionné dans {other}", name=drop['hostname'] or drop['ip'], other=keep['hostname'] or keep['ip']))
        return True

    def open_merge(self, dev):
        if dev.get("online", True):
            cands = [d for d in self.devices if not d.get("online", True) and not d.get("virtual")]
            text = tr("Choisissez l'appareil hors ligne qui est en réalité « {name} » (par exemple avec une ancienne adresse MAC). "
                      "Son historique, sa confiance et ses noms seront regroupés ici.", name=dev['hostname'] or dev['ip'])
        else:
            cands = [d for d in self.devices if d.get("online", True) and not d.get("virtual") and not d.get("is_self")]
            text = tr("« {name} » (hors ligne) est-il un appareil actuellement en ligne ? Choisissez-le : "
                      "l'historique de l'appareil hors ligne sera regroupé avec le sien.", name=dev['hostname'] or dev['ip'])
        if not cands:
            QMessageBox.information(self, tr("Fusion"), tr("Aucun appareil à fusionner.")); return
        dlg = MergeDialog(tr("Fusionner des appareils"), text, cands, self)
        if dlg.exec():
            other = dlg.chosen()
            self.merge_into(dev, other) if dev.get("online", True) else self.merge_into(other, dev)

    def show_duplicates(self):
        if not self.dup_suggestions:
            QMessageBox.information(self, tr("Doublons"), tr("Aucun doublon probable : aucun appareil récent ne ressemble à un appareil hors ligne."))
            return
        DuplicatesDialog(self.dup_suggestions, self.merge_into, self).exec()
        self.refresh_panel()

    def wake_device(self, dev):
        """Envoie un paquet Wake-on-LAN à un appareil hors ligne (si son adresse MAC est la vraie, pas une adresse privée)."""
        name = dev["hostname"] or dev["ip"]
        if self.demo:
            QMessageBox.information(self, tr("Démonstration"), tr("Mode démonstration : aucun paquet n'est envoyé sur le réseau.")); return
        if fingerprint.is_random_mac(dev.get("mac", "")):
            QMessageBox.information(self, tr("Wake-on-LAN"), tr("« {name} » utilise une adresse MAC aléatoire (adresse privée Wi-Fi) : elle ne peut pas servir à le "
                                                            "réveiller. Seule l'adresse matérielle d'origine de la carte réseau le peut.", name=name))
            return
        targets = ["255.255.255.255"]
        if dev.get("network"):
            try:
                targets.insert(0, wol.broadcast_for(dev["network"]))
            except ValueError:
                pass
        try:
            n = wol.send(dev["mac"], targets)
        except ValueError as e:
            QMessageBox.warning(self, tr("Wake-on-LAN"), str(e)); return
        self.status.setText(tr("Paquet de réveil envoyé à {name} ({mac}) : {n} envoi(s). Il faut que Wake-on-LAN soit activé sur "
                               "l'appareil (en général en Ethernet, rarement en Wi-Fi).", name=name, mac=dev['mac'], n=n))

    def open_log(self):
        from .. import log as plog
        if os.path.exists(plog.PATH):
            QDesktopServices.openUrl(QUrl.fromLocalFile(plog.PATH))
        else:
            QMessageBox.information(self, tr("Journal d'erreurs"), tr("Aucune erreur enregistrée pour le moment.\n\nEmplacement : {path}", path=plog.PATH))

    def toggle_trust(self, dev):
        if not dev:
            return
        flag = not dev.get("trusted")
        try:
            history.set_trusted([dev], flag)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer la confiance :\n{e}", e=e)); return
        self.refresh_views(); self.refresh_journal()
        self.status.setText(tr("{hostname} : ", hostname=dev['hostname'] or dev['ip']) + (tr("marqué de confiance") if flag else tr("confiance retirée")))

    def trust_all(self):
        todo = [d for d in self.devices if d.get("online", True) and not d.get("trusted")]
        if not todo:
            QMessageBox.information(self, tr("Panther"), tr("Aucun appareil en ligne à valider.")); return
        names = "\n".join(f"• {d['hostname'] or d['ip']}  ({d['ip']})" for d in todo[:12]) + ("\n…" if len(todo) > 12 else "")
        if QMessageBox.question(self, tr("Faire confiance"), tr("Marquer ces {todo_count} appareil(s) comme de confiance ?\n\n{names}\n\nVérifiez qu'ils sont tous "
                                                            "reconnus : un intrus présent maintenant serait validé.", todo_count=len(todo), names=names)) \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            history.set_trusted(todo, True)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer la confiance :\n{e}", e=e)); return
        self.refresh_views(); self.refresh_journal()
        self.status.setText(tr("{todo_count} appareil(s) marqués de confiance", todo_count=len(todo)))

    def forget_device(self, dev):
        if not dev or QMessageBox.question(self, tr("Oublier"), tr("Oublier {hostname} et son historique ?", hostname=dev['hostname'] or dev['ip'])) \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            history.forget(dev)
        except (sqlite3.Error, OSError) as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'oublier l'appareil :\n{e}", e=e)); return
        self.devices = [d for d in self.devices if d is not dev]
        self.selected = None if self.selected == dkey(dev) else self.selected
        self.rebuild(); self.update_count(); self.refresh_panel(); self.refresh_journal()

    def refresh_views(self):
        """Met à jour l'affichage sans recalculer la disposition (les nœuds déplacés restent en place)."""
        for n in self.nodes.values():
            n.update()
        self.fill_table(); self.apply_filter(); self.sync_table(self.selected); self.refresh_panel()

    def device_menu(self, dev, pos):
        if not dev or dev.get("virtual"):
            return
        menu = QMenu(self)
        menu.addAction(tr("Modifier le nom / le type…"), lambda: self.edit_device(dev))
        menu.addAction(tr("Retirer la confiance") if dev.get("trusted") else tr("Marquer comme appareil de confiance"),
                       lambda: self.toggle_trust(dev))
        menu.addAction(tr("Étiquettes, notes et groupe…"), lambda: self.edit_meta(dev))
        menu.addAction(tr("Créer une règle de détection…"), lambda: self.create_rule(dev))
        if any(d is not dev and not d.get("virtual") and d.get("online", True) != dev.get("online", True) for d in self.devices):
            menu.addAction(tr("Fusionner avec un appareil hors ligne…") if dev.get("online", True) else tr("Fusionner dans un appareil en ligne…"),
                           lambda: self.open_merge(dev))
        if not dev.get("online", True) and dev.get("mac"):
            menu.addAction(tr("Réveiller (Wake-on-LAN)"), lambda: self.wake_device(dev))
        if not dev.get("online", True):
            menu.addAction(tr("Oublier cet appareil"), lambda: self.forget_device(dev))
        if dev.get("custom"):
            menu.addAction(tr("Rétablir la détection automatique"), lambda: self.reset_device(dev))
        menu.exec(pos.toPoint() if hasattr(pos, "toPoint") else pos)

    def edit_device(self, dev):
        if not dev or dev.get("virtual"):
            return
        dlg = EditDialog(dev, self)
        if dlg.exec():
            name, kind = dlg.values()
            self.commit_override(dev, name, kind)

    def reset_device(self, dev):
        self.commit_override(dev, None, None)

    def commit_override(self, dev, name, kind):
        try:
            data = store.set_override(dev, name, kind)
        except OSError as e:
            QMessageBox.warning(self, tr("Panther"), tr("Impossible d'enregistrer le réglage :\n{e}", e=e))
            return
        store.apply(dev, data)
        self.selected = dkey(dev)
        self.rebuild(); self.refresh_panel()
        self.status.setText(tr("Réglage enregistré") if (name or kind) else tr("Détection automatique rétablie"))
