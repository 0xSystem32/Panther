"""Tests d'interface, hors écran (ignorés si PyQt6 n'est pas installé)."""
import importlib.util
import os
import tempfile
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HAS_QT = importlib.util.find_spec("PyQt6") is not None

if HAS_QT:
    from PyQt6.QtCore import QPointF, QSettings, Qt
    from PyQt6.QtWidgets import QApplication, QMenu, QTableWidget, QWidget

    from panther.ui import dialogs, theme
    from panther import alerts, compare, gui, history, ouiupdate, reportpdf, rules, schedule, secrets, security, store, wol

NET = "192.168.1.0/24"


def dev(ip, name, typ="unknown", ports=(), net=NET, **kw):
    d = {"ip": ip, "mac": "aa:00:00:00:00:%02x" % int(ip.split(".")[-1]), "hostname": name, "type": typ, "vendor": "V", "os": "Linux",
         "ports": list(ports), "services": [], "banners": {}, "ttl": 64, "is_gateway": False, "is_self": False, "random_mac": False,
         "online": True, "confidence": 80, "reasons": ["test"], "model": "", "network": net, "vlan": None, "mdns_services": [],
         "mdns_names": [], "mdns_txt": {}, "ssdp": {}, "path": [], "security": None}
    d.update(kw)
    return d


def network():
    return [dev("192.168.1.13", "debian", "desktop", is_self=True), dev("192.168.1.1", "box", "router", [80, 443], is_gateway=True),
            dev("192.168.1.10", "salon-tv", "tv", [8009]), dev("192.168.1.40", "imprimante", "printer", [9100])]


@unittest.skipUnless(HAS_QT, "PyQt6 absent : tests d'interface ignorés (utiliser le Python du .venv)")
class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setStyle("Fusion")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "panther.db")
        store.PATH = os.path.join(self.tmp.name, "devices.json")
        QSettings.setPath(QSettings.Format.NativeFormat, QSettings.Scope.UserScope, self.tmp.name)
        rules.PATH = os.path.join(self.tmp.name, "rules.json")                   # jamais les vraies règles de l'utilisateur
        alerts.PATH = os.path.join(self.tmp.name, "alerts.json")                 # ni les vrais réglages d'alertes ni les vrais secrets
        secrets.PATH = os.path.join(self.tmp.name, "secrets.json")
        self._secret_tool, secrets._tool = secrets._tool, (lambda: None)
        rules._cache.update(path=None, mtime=None, rs=rules.RuleSet())
        gui.T.update(gui.THEMES["dark"]); self.app.setStyleSheet(gui.make_style())
        self.boxes = []                                                          # boîtes de dialogue neutralisées (elles bloqueraient hors écran)
        for name in ("information", "warning", "critical"):
            setattr(gui.QMessageBox, name, staticmethod(lambda *a, _n=name, **k: self.boxes.append((_n, a[1:3])) or 0))
        gui.QMessageBox.question = staticmethod(lambda *a, **k: self.boxes.append(("question", a[1:3])) or gui.QMessageBox.StandardButton.Yes)
        self.w = gui.Main()
        self.w.notify = lambda *a: None
        self.w.network = {"iface": "eth0", "cidr": NET, "gateway": "192.168.1.1", "vlan": None, "kind": "ethernet"}
        self.w.networks_info = [{"cidr": NET, "kind": "local", "vlan": None}]
        self.w.show()

    def tearDown(self):
        secrets._tool = self._secret_tool
        gui.set_text_scale(1.0)
        gui.T.update(gui.THEMES["dark"])
        self.w.close()
        self.tmp.cleanup()

    def scan(self, devices, depth="normal"):
        for d in devices:
            store.apply(d)  # comme le scanner : il applique les réglages manuels enregistrés à chaque appareil
        self.w.finish_scan({"devices": devices, "networks": self.w.networks_info, "depth": depth}, 5)
        self.app.processEvents()
        time.sleep(0.01)

    # --- fenêtre
    def test_window_builds_with_expected_menus_tabs_and_safe_defaults(self):
        w = self.w
        self.assertEqual([a.text() for a in w.menuBar().actions()], ["Fichier", "Scan", "Affichage", "Sécurité", "Détection", "Aide"])
        self.assertEqual([w.tabs.tabText(i) for i in range(w.tabs.count())], ["Carte réseau", "Appareils", "Journal", "Sécurité"])
        self.assertFalse(w.security_on)                                          # l'analyse de sécurité est désactivée par défaut
        self.assertEqual(w.depth.currentData(), "normal")
        self.assertEqual(w.iface_combo.itemData(0), "")                          # « Automatique »

    def test_finish_scan_fills_map_table_journal_and_legend(self):
        self.scan(network())
        w = self.w
        self.assertEqual(len(w.nodes), 4)
        self.assertEqual(w.table.rowCount(), 4)
        self.assertGreaterEqual(w.journal.rowCount(), 4)                          # « Nouvel appareil » (référence) par appareil
        self.assertEqual({k for k, _ in w.view.legend}, {"desktop", "router", "tv", "printer"})
        self.assertIn("première analyse", w.status.text())

    def test_selection_is_synchronised_between_map_and_table(self):
        self.scan(network())
        w = self.w
        key = gui.dkey(w.devices[2])
        w.nodes[key].setSelected(True); self.app.processEvents()
        self.assertEqual(w.current_device()["hostname"], w.devices[2]["hostname"])
        self.assertEqual([w.table.item(r.row(), 0).data(gui.KEY_ROLE) for r in w.table.selectionModel().selectedRows()], [key])
        w.scene.clearSelection(); w.table.selectRow(0); self.app.processEvents()
        self.assertEqual(w.table.item(0, 0).data(gui.KEY_ROLE), gui.dkey(w.current_device()))

    def test_two_devices_with_the_same_ip_stay_distinct(self):
        old = dev("192.168.1.20", "ancien-pc", "desktop", mac="aa:00:00:00:00:20")
        new = dev("192.168.1.20", "nouveau-tel", "phone", mac="cc:00:00:00:00:21")
        self.scan([*network()[:2], old])
        for _ in range(3):
            self.scan([*network()[:2], new])                                    # l'ancien est absent, hors ligne
        w = self.w
        same_ip = [d for d in w.devices if d["ip"] == "192.168.1.20"]
        self.assertEqual(sorted(d["hostname"] for d in same_ip), ["ancien-pc", "nouveau-tel"])
        self.assertEqual(len({gui.dkey(d) for d in w.devices}), len(w.devices))
        self.assertEqual(len(w.nodes), len(w.devices))

    def test_filter_dims_non_matching_nodes(self):
        self.scan(network())
        w = self.w
        w.search.setText("imprimante"); self.app.processEvents()
        op = {d["hostname"]: w.nodes[gui.dkey(d)].opacity() for d in w.devices}
        self.assertEqual(op["imprimante"], 1.0)
        self.assertLess(op["salon-tv"], 0.5)
        self.assertEqual(sum(not w.table.isRowHidden(r) for r in range(w.table.rowCount())), 1)

    # --- édition, confiance
    def test_manual_name_type_and_trust_survive_a_new_scan(self):
        self.scan(network())
        w = self.w
        tv = next(d for d in w.devices if d["hostname"] == "salon-tv")
        w.commit_override(tv, "Télé du salon", "console")
        self.assertEqual((tv["hostname"], tv["type"], tv["custom"]), ("Télé du salon", "console", True))
        w.toggle_trust(tv)
        self.assertTrue(tv["trusted"])
        self.scan(network())                                                     # nouveau scan : réglages repris depuis le disque
        tv2 = next(d for d in w.devices if d["ip"] == "192.168.1.10")
        self.assertEqual((tv2["hostname"], tv2["type"], tv2["trusted"]), ("Télé du salon", "console", True))
        w.reset_device(tv2)
        self.assertEqual(tv2["type"], "tv")

    # --- dispositions
    def test_hierarchical_layout_has_virtual_nodes_and_positions_persist(self):
        self.scan(network())
        w = self.w
        w.set_layout("hierarchique")
        self.assertIn("virt:internet", w.nodes)
        self.assertFalse(w.nodes["virt:internet"].flags() & gui.QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        key = gui.dkey(next(d for d in w.devices if d["hostname"] == "salon-tv"))
        n = w.nodes[key]; moved = (n.pos().x() + 123, n.pos().y() + 45)
        n._press = n.pos(); n.setPos(*moved); n.pos_cb(n)
        w.rebuild()
        self.assertAlmostEqual(w.nodes[key].pos().x(), moved[0]); self.assertAlmostEqual(w.nodes[key].pos().y(), moved[1])
        w.set_layout("etoile")
        self.assertNotAlmostEqual(w.nodes[key].pos().x(), moved[0])               # chaque disposition a ses positions
        w.set_layout("hierarchique"); w.reset_positions()
        self.assertNotAlmostEqual(w.nodes[key].pos().x(), moved[0])

    def test_theme_switch_does_not_break_rendering(self):
        self.scan(network())
        for name in ("light", "dark", "light"):
            self.w.apply_theme(name); self.app.processEvents()
            self.w.grab()
        gui.T.update(gui.THEMES["dark"])

    # --- sécurité
    def test_security_toggle_tab_and_exposure_column(self):
        w = self.w
        w.security_consent = True
        w.toggle_security(True)
        self.assertTrue(w.security_on)
        cam = dev("192.168.1.50", "cam", "camera", [23, 554])
        cam["security"] = security.analyze(cam, {554: "open"})
        self.scan([*network(), cam])
        self.assertIn("constat", w.sec_label.text())
        self.assertGreaterEqual(w.sec_table.rowCount(), 2)
        self.assertEqual(w.sec_table.item(0, 0).text(), "Élevé")
        row = next(r for r in range(w.table.rowCount()) if w.table.item(r, 0).text() == "cam")
        self.assertIn("Élevé", w.table.item(row, 10).text())
        w.toggle_security(False)
        self.assertIn("désactivée", w.sec_label.text())

    # --- comparaison, PDF
    def test_compare_dialog_reports_new_gone_and_changed(self):
        self.scan(network())
        changed = network(); changed[2]["ports"] = [8009, 8060]
        self.scan([*changed[:3], dev("192.168.1.70", "pc-compta", "desktop")])      # imprimante partie, TV modifiée, un nouveau
        scans = history.list_scans()
        self.assertEqual(len(scans), 2)
        dlg = gui.CompareDialog(scans, self.w)
        self.assertEqual(dlg.summary.text().split("  ·  ")[:3], ["1 nouveau", "1 disparu", "1 modifié"])
        kinds = [dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())]
        self.assertEqual(kinds, ["Nouveau", "Modifié", "Disparu"])
        dlg.a.setCurrentIndex(dlg.b.currentIndex())
        self.assertIn("deux scans différents", dlg.summary.text())

    def test_map_image_and_pdf_export(self):
        self.scan(network())
        w = self.w
        img = w.render_map_image(800)
        self.assertFalse(img.isNull())
        self.assertEqual(w.view.legend and gui.T["bg"], gui.THEMES["dark"]["bg"])  # le thème d'affichage n'a pas été modifié
        page = reportpdf.build_html(w.devices, [NET], time.time(), "map")
        path = os.path.join(self.tmp.name, "r.pdf")
        reportpdf.write_pdf(path, page, img)
        with open(path, "rb") as f:
            self.assertTrue(f.read(5) == b"%PDF-")

    def test_depth_policy_presence_needs_a_known_scan_and_auto_scans_alternate_with_full_scans(self):
        w = self.w
        w.depth.setCurrentIndex(w.depth.findData("normal"))
        self.assertEqual(w.choose_depth(auto=False)[0], "normal")                    # scan manuel : la profondeur choisie
        w.last_full_scan = time.time()
        self.assertEqual(w.choose_depth(auto=True)[0], "normal")                      # auto, mais aucun scan connu : pas de présence possible
        self.scan(network())                                                          # un scan complet existe maintenant
        w.last_full_scan = time.time()
        depth, known = w.choose_depth(auto=True)
        self.assertEqual(depth, "presence")
        self.assertEqual(len(known), 4)                                               # les 4 appareils du scan précédent
        w.last_full_scan = time.time() - 3 * 3600
        self.assertEqual(w.choose_depth(auto=True)[0], "normal")                      # plus d'une heure : scan complet
        w.depth.setCurrentIndex(w.depth.findData("presence"))
        self.assertEqual(w.choose_depth(auto=False)[0], "presence")                   # présence demandée à la main
        self.assertEqual(w.choose_depth(auto=True, now=time.time() + 10 * 3600)[0], "presence")

    def test_presence_scan_does_not_reset_the_full_scan_clock(self):
        w = self.w
        w.last_full_scan = 123.0
        self.scan(network(), depth="presence")
        self.assertEqual(w.last_full_scan, 123.0)
        self.assertIn("Scan de présence", w.status.text())
        self.scan(network(), depth="normal")
        self.assertGreater(w.last_full_scan, 123.0)

    # --- carte incrémentale
    def feed(self, devices, status="scanning"):
        """Simule l'état du scanner à un instant d'un scan en cours, puis laisse l'interface le lire."""
        sc = self.w.scanner
        sc.state.update(status=status, progress=40, network=self.w.network, networks=self.w.networks_info,
                        devices={d["ip"]: d for d in devices}, depth="normal")
        self.w.poll()
        self.app.processEvents()

    def test_devices_appear_during_a_scan_without_rebuilding_the_map(self):
        w = self.w
        net = network()
        rebuilds = []
        orig = w.rebuild
        w.rebuild = lambda: (rebuilds.append(1), orig())[1]
        self.feed(net[:2])                                                           # self + box : première apparition = reconstruction
        base = len(rebuilds)
        first = {k: n for k, n in w.nodes.items()}
        moved = next(iter(first.values()))
        moved.setPos(moved.pos().x() + 55, moved.pos().y() + 33); pos = (moved.pos().x(), moved.pos().y())
        self.feed(net[:3]); self.feed(net)
        self.assertEqual(len(rebuilds), base)                                         # aucune reconstruction pendant l'ajout
        self.assertEqual(len(w.nodes), 4)
        self.assertEqual(w.table.rowCount(), 4)
        for k, n in first.items():
            self.assertIs(w.nodes[k], n)                                              # mêmes objets : rien n'a été recréé
        self.assertEqual((moved.pos().x(), moved.pos().y()), pos)                     # le nœud déplacé n'a pas bougé
        self.assertEqual({k for k, _ in w.view.legend}, {"desktop", "router", "tv", "printer"})
        # chaque nouvel appareil est relié à cette machine
        me = next(n for n in w.nodes.values() if n.dev["is_self"])
        self.assertEqual(len(me.links), 3)

    def test_live_nodes_get_distinct_positions_and_wrap_into_rings(self):
        w = self.w
        base = network()[:2]
        many = [dev("192.168.1.%d" % (20 + i), "d%d" % i, "iot") for i in range(30)]
        self.feed(base)
        for i in range(0, 30, 6):
            self.feed(base + many[:i + 6])
        pts = {(round(n.pos().x()), round(n.pos().y())) for n in w.nodes.values()}
        self.assertEqual(len(pts), len(w.nodes))                                      # aucune superposition
        self.assertEqual(w.table.rowCount(), 32)

    def test_hierarchical_layout_and_other_networks_fall_back_to_throttled_rebuilds(self):
        w = self.w
        net = network()
        self.feed(net[:2])
        w.set_layout("hierarchique")
        calls = []
        orig = w.rebuild
        w.rebuild = lambda: (calls.append(1), orig())[1]
        w._last_rebuild = time.time()
        self.feed(net[:3])
        self.assertEqual(calls, [])                                                   # moins d'une seconde après la dernière : on attend
        w._last_rebuild = time.time() - 2
        self.feed(net)
        self.assertEqual(calls, [1])
        self.assertEqual(len(w.nodes) - len([k for k in w.nodes if k.startswith("virt:")]), 4)

    def test_the_previous_map_stays_visible_until_the_new_scan_finds_something(self):
        w = self.w
        self.feed(network())
        before = dict(w.nodes)
        self.feed([])                                                                 # le scan démarre : rien trouvé pour l'instant
        self.assertEqual(w.nodes, before)                                             # pas de carte vide qui clignote
        self.assertEqual(w.table.rowCount(), 4)

    def test_a_new_scan_replaces_the_previous_display(self):
        w = self.w
        self.feed(network())
        self.assertEqual(len(w.nodes), 4)
        self.feed(network()[:1])                                                      # le scan repart de zéro
        self.assertEqual(len(w.nodes), 1)

    # --- fusion de doublons
    def duplicate_scenario(self):
        old = dev("192.168.1.27", "iphone", "phone", mac="02:11:22:33:44:01", random_mac=True)
        self.scan([*network()[:2], old])
        trusted = self.w.devices[-1]
        history.set_trusted([trusted], True)
        new = dev("192.168.1.14", "iphone", "phone", mac="06:11:22:33:44:02", random_mac=True)
        for _ in range(2):
            self.scan([*network()[:2], new])                                       # l'ancienne MAC disparaît, une nouvelle apparaît
        return new

    def test_a_duplicate_is_suggested_after_the_scan_and_merging_keeps_history_and_trust(self):
        self.duplicate_scenario()
        w = self.w
        self.assertEqual(len(w.dup_suggestions), 1)
        self.assertIn("doublon", w.status.text())
        new, old, reasons = w.dup_suggestions[0]
        self.assertFalse(old["online"])
        self.assertTrue(w.merge_into(new, old))
        phones = [d for d in w.devices if d["hostname"] == "iphone"]
        self.assertEqual(len(phones), 1)
        self.assertTrue(phones[0]["trusted"])                                       # la confiance de l'ancienne identité est conservée
        self.assertEqual(w.dup_suggestions, [])
        self.assertEqual(history.alias_map(), {"02:11:22:33:44:01": "06:11:22:33:44:02"})
        self.assertIn("fusionné", w.status.text())
        kinds = [w.journal.item(r, 2).text() for r in range(w.journal.rowCount())]
        self.assertIn("Appareils fusionnés", kinds)

    def test_two_online_devices_cannot_be_merged(self):
        self.scan(network())
        w = self.w
        self.assertFalse(w.merge_into(w.devices[2], w.devices[3]))
        self.assertEqual(self.boxes[-1][0], "information")                           # l'utilisateur est prévenu

    def test_duplicates_dialog_merges_the_selected_row_and_empties_the_list(self):
        self.duplicate_scenario()
        w = self.w
        dlg = gui.DuplicatesDialog(w.dup_suggestions, w.merge_into, w)
        self.assertEqual(dlg.table.rowCount(), 1)
        dlg.merge_selected()
        self.assertEqual((dlg.table.rowCount(), dlg.merge_btn.isEnabled()), (0, False))

    def test_context_menu_offers_merge_only_when_there_is_something_to_merge(self):
        self.scan(network())
        w = self.w
        labels = []
        import panther.gui as g
        orig = QMenu.exec
        QMenu.exec = lambda self_, pos=None: labels.extend(a.text() for a in self_.actions())
        try:
            w.device_menu(w.devices[2], QPointF(0, 0).toPoint())
            self.assertFalse(any("Fusionner" in x for x in labels))                   # tous en ligne : rien à fusionner
            labels.clear()
            self.duplicate_scenario()
            new = next(d for d in w.devices if d["hostname"] == "iphone" and d["online"])
            w.device_menu(new, QPointF(0, 0).toPoint())
            self.assertTrue(any("Fusionner avec un appareil hors ligne" in x for x in labels))
        finally:
            QMenu.exec = orig

    # --- données et purge
    def test_data_dialog_shows_size_and_purges_old_history(self):
        w = self.w
        for i in range(6):                                                           # six scans, un par jour, il y a longtemps
            d = dev("192.168.1.2", "tv", "tv", ports=[i + 1])
            history.record_scan([d], now=time.time() - (40 - i) * 86400, networks=[NET])
        dlg = gui.DataDialog(history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS, w)
        self.assertIn("Scans conservés : 6", dlg.info.text())
        self.assertIn("Appareils connus : 1", dlg.info.text())
        self.assertRegex(dlg.info.text(), r"Taille : [\d.,]+ (Ko|Mo)")
        dlg.sp_scans.setValue(37)                                                    # ne garde que ce qui a moins de 37 jours
        dlg.purge()
        self.assertIn("scans supprimés", dlg.result.text())
        self.assertIn("Scans conservés : 2", dlg.info.text())                         # restent les scans de 36 et 35 jours
        self.assertIn("4 scans supprimés", dlg.result.text())

    def test_retention_is_applied_and_remembered(self):
        w = self.w
        w.apply_retention(30, 400)
        self.assertEqual((history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS), (30, 400))
        self.assertEqual(int(w.settings.value("keep_scans_days")), 30)
        history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS = 90, 365                  # remet les valeurs par défaut pour les autres tests

    def test_human_size(self):
        self.assertEqual(gui.human_size(512), "512 o")
        self.assertEqual(gui.human_size(2048), "2.0 Ko")
        self.assertEqual(gui.human_size(5 * 1024 * 1024), "5.0 Mo")

    # --- alertes
    def wait_workers(self, w, timeout=5):
        end = time.time() + timeout
        while any(x.isRunning() for x in getattr(w, "_alert_workers", [])) and time.time() < end:
            self.app.processEvents(); time.sleep(0.02)
        self.app.processEvents()

    def capture_dispatch(self, results=None):
        calls = []
        orig = alerts.dispatch
        alerts.dispatch = lambda cfg, events, when=None, **kw: calls.append((events, kw)) or (results if results is not None else [("webhook", True, "")])
        self.addCleanup(setattr, alerts, "dispatch", orig)
        return calls

    def enable_alerts(self, **events):
        alerts.save({"enabled": True, "events": events, "webhook": {"enabled": True, "format": "generic"}})

    def test_alerts_dialog_saves_settings_and_secrets_in_different_places(self):
        dlg = gui.AlertsDialog(self.w)
        dlg.enabled.setChecked(True); dlg.wh_on.setChecked(True); dlg.wh_fmt.setCurrentIndex(dlg.wh_fmt.findData("discord"))
        dlg.wh_url.setText("https://discord.example/api/webhooks/SECRET-TOKEN")
        dlg.em_on.setChecked(True); dlg.em_host.setText("smtp.test"); dlg.em_user.setText("moi"); dlg.em_pw.setText("MOT-DE-PASSE")
        dlg.em_from.setText("a@b.fr"); dlg.em_to.setText("c@d.fr, e@f.fr"); dlg.sev.setCurrentIndex(dlg.sev.findData("critique")); dlg.auto_only.setChecked(False)
        dlg.accept()
        cfg = alerts.load()
        self.assertEqual((cfg["enabled"], cfg["webhook"]["format"], cfg["email"]["to"], cfg["events"]["exposure_min"], cfg["events"]["auto_only"]),
                         (True, "discord", ["c@d.fr", "e@f.fr"], "critique", False))
        with open(alerts.PATH, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("SECRET-TOKEN", raw); self.assertNotIn("MOT-DE-PASSE", raw)           # jamais dans le fichier de réglages
        self.assertEqual((secrets.get(alerts.SECRET_WEBHOOK), secrets.get(alerts.SECRET_SMTP)), ("https://discord.example/api/webhooks/SECRET-TOKEN", "MOT-DE-PASSE"))
        again = gui.AlertsDialog(self.w)                                                      # rouvert : secrets non réaffichés, mais conservés
        self.assertEqual((again.wh_url.text(), again.em_pw.text()), ("", ""))
        self.assertIn("déjà enregistrée", again.wh_url.placeholderText())
        again.accept()
        self.assertEqual(secrets.get(alerts.SECRET_SMTP), "MOT-DE-PASSE")                      # laisser vide = garder

    # --- vie privée
    def test_legacy_plaintext_snmp_community_is_migrated_to_the_secret_store(self):
        self.w.settings.setValue("snmp", '[{"host": "192.168.1.1", "community": "COMMU-SECRETE"}]')
        sources = self.w.load_snmp()
        self.assertEqual(sources, [{"host": "192.168.1.1", "community": "COMMU-SECRETE"}])
        self.assertEqual(secrets.get(gui.snmp_secret("192.168.1.1")), "COMMU-SECRETE")
        self.assertNotIn("COMMU-SECRETE", self.w.settings.value("snmp"))                # plus en clair dans les réglages
        self.assertEqual(self.w.load_snmp(), sources)                                   # relu : toujours là, sans nouvelle migration

    def test_saving_snmp_sources_keeps_communities_out_of_settings_and_forgets_removed_hosts(self):
        a, b = {"host": "10.0.0.1", "community": "AAA"}, {"host": "10.0.0.2", "community": "BBB"}
        self.w.save_snmp([a, b], [])
        raw = self.w.settings.value("snmp")
        self.assertNotIn("AAA", raw); self.assertNotIn("BBB", raw)
        self.assertEqual(self.w.load_snmp(), [a, b])
        self.w.save_snmp([b], [a, b])
        self.assertIsNone(secrets.get(gui.snmp_secret("10.0.0.1")))
        self.assertEqual(secrets.get(gui.snmp_secret("10.0.0.2")), "BBB")

    def test_broken_snmp_settings_do_not_crash(self):
        for bad in ("pas du json", "[1, 2]", '[{"pas_de_host": 1}]', '{"a": 1}'):
            self.w.settings.setValue("snmp", bad)
            self.assertEqual(self.w.load_snmp(), [])

    def test_erase_everything_empties_history_names_and_log_after_confirmation(self):
        self.scan([dev("192.168.1.1", "box", "router"), dev("192.168.1.20", "tv", "tv")])
        store.set_override(self.w.devices[0], name="Mon nom")
        logfile = os.path.join(self.tmp.name, "panther.log")
        with open(logfile, "w") as f:
            f.write("192.168.1.20 tv\n")
        old, dialogs.log_path = dialogs.log_path, (lambda: logfile)
        try:
            dlg = gui.DataDialog(90, 365, self.w)
            dlg.erase_everything()
        finally:
            dialogs.log_path = old
        self.assertTrue(dlg.erased)
        self.assertEqual(history.db_stats()["devices"], 0)
        self.assertEqual((store.load(), os.path.getsize(logfile)), ({}, 0))
        self.assertTrue(any(b[0] == "question" for b in self.boxes))
        self.w.after_erase()
        self.assertEqual(self.w.devices, [])

    def test_erase_everything_does_nothing_when_declined(self):
        self.scan([dev("192.168.1.1", "box", "router")])
        gui.QMessageBox.question = staticmethod(lambda *a, **k: gui.QMessageBox.StandardButton.No)
        dlg = gui.DataDialog(90, 365, self.w)
        dlg.erase_everything()
        self.assertFalse(dlg.erased)
        self.assertGreater(history.db_stats()["devices"], 0)

    def test_erase_can_keep_names_and_log(self):
        self.scan([dev("192.168.1.1", "box", "router")])
        store.set_override(self.w.devices[0], name="Garde-moi")
        dlg = gui.DataDialog(90, 365, self.w)
        dlg.erase_names.setChecked(False); dlg.erase_log.setChecked(False)
        dlg.erase_everything()
        self.assertEqual(history.db_stats()["devices"], 0)
        self.assertEqual(len(store.load()), 1)

    def test_passive_mode_forces_the_listening_profile_and_no_security(self):
        self.w.act_passive.trigger()
        self.assertTrue(self.w.passive_on)
        self.assertFalse(self.w.depth.isEnabled())
        depth, known = self.w.choose_depth(auto=True)
        self.assertEqual((depth, known), ("ecoute", {}))
        calls = []
        self.w.scanner.start = lambda *a, **k: calls.append(a) or True
        self.w.security_on = True
        self.w.start_scan()
        self.assertEqual((calls[0][2], calls[0][3]), ("ecoute", False))                  # aucune analyse de sécurité en écoute seule
        self.w.act_passive.trigger()
        self.assertTrue(self.w.depth.isEnabled())
        self.assertNotEqual(self.w.choose_depth()[0], "ecoute")

    def test_hostile_network_text_is_never_rendered_as_html(self):
        """Noms, bannières et certificats viennent du réseau : ils s'affichent comme du texte, jamais comme du HTML."""
        from PyQt6.QtWidgets import QLabel
        evil = "<img src=x onerror=alert(1)><b>GRAS</b><a href='http://evil.example'>clic</a>"
        d = dev("192.168.1.30", evil, "camera", ports=(80, 554))
        d.update(vendor=evil, model=evil, model_name=evil, os=evil, mdns_names=[evil], mdns_services=[evil], reasons=[evil],
                 banners={"80": evil}, http_info=evil, cert={"cn": evil, "o": evil, "issuer": evil}, ssdp={"friendly": evil, "model": evil},
                 netbios={"workgroup": evil}, security=[{"id": "x", "severity": "élevé", "title": evil, "detail": evil, "remedy": evil, "port": 80}])
        self.scan([d])
        self.w.selected = gui.dkey(self.w.devices[0]); self.w.refresh_panel(); self.app.processEvents()
        bad = []
        for lab in self.w.findChildren(QLabel):
            t = lab.text()
            if "onerror" in t and lab.textFormat() != Qt.TextFormat.PlainText and Qt.mightBeRichText(t):
                bad.append(("label", t[:50]))
            if "<img" in lab.toolTip().replace("&lt;img", ""):
                bad.append(("tooltip", lab.toolTip()[:50]))
        for w in self.w.findChildren(QWidget):                                           # toutes les infobulles, pas seulement celles des étiquettes
            if "<img" in w.toolTip().replace("&lt;img", ""):
                bad.append(("tooltip", type(w).__name__))
        for table in self.w.findChildren(QTableWidget):
            for r in range(table.rowCount()):
                for c in range(table.columnCount()):
                    it = table.item(r, c)
                    if it and "<img" in it.toolTip().replace("&lt;img", ""):
                        bad.append(("item", r, c))
        for n in self.w.nodes.values():
            if "<img" in n.toolTip().replace("&lt;img", ""):
                bad.append(("node", n.toolTip()[:40]))
        self.assertEqual(bad, [])

    # --- carte : disposition par type, mini-carte, sélection multiple
    def map_devices(self, n=14):
        ds = [dev("192.168.1.13", "debian", "desktop", is_self=True), dev("192.168.1.1", "box", "router", [80], is_gateway=True)]
        kinds = ["phone", "tv", "camera", "printer", "nas", "iot"]
        for i in range(n):
            ds.append(dev(f"192.168.1.{20 + i}", f"app{i}", kinds[i % len(kinds)]))
        return ds

    def test_type_layout_builds_one_zone_per_type_and_remembers_positions_separately(self):
        from panther.gui import Zone
        self.scan(self.map_devices())
        star_pos = {k: (n.pos().x(), n.pos().y()) for k, n in self.w.nodes.items()}
        self.w.set_layout("types")
        zones = [i for i in self.w.scene.items() if isinstance(i, Zone)]
        self.assertEqual(len(zones), len({d["type"] for d in self.w.devices}))
        self.assertEqual(len(self.w.nodes), len(self.w.devices))
        self.assertFalse(any(type(i).__name__ == "Link" for i in self.w.scene.items()))      # pas de liens : seulement des amas
        self.assertNotEqual({k: (n.pos().x(), n.pos().y()) for k, n in self.w.nodes.items()}, star_pos)
        k = next(iter(self.w.nodes)); node = self.w.nodes[k]
        node.setPos(node.pos().x() + 40, node.pos().y()); self.w.remember_position(node)
        moved_x = node.pos().x()
        self.w.set_layout("etoile")
        self.assertEqual((self.w.nodes[k].pos().x(), self.w.nodes[k].pos().y()), star_pos[k])  # la disposition étoile n'a pas bougé
        self.w.set_layout("types")
        self.assertAlmostEqual(self.w.nodes[k].pos().x(), moved_x, places=3)             # celle-ci a gardé le déplacement
        self.assertEqual(self.w.settings.value("layout"), "types")

    def test_layout_menu_offers_the_three_layouts(self):
        self.assertEqual(set(self.w.layout_actions), {"etoile", "hierarchique", "types"})

    def test_minimap_only_shows_when_the_whole_map_is_not_visible(self):
        self.scan(self.map_devices(30))
        self.w.view.resetTransform(); self.w.view.fitInView(self.w.scene.itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)
        self.app.processEvents()
        self.assertFalse(self.w.view.minimap_visible())
        self.w.view.scale(3, 3); self.app.processEvents()
        self.assertTrue(self.w.view.minimap_visible())
        self.w.view.show_minimap = False
        self.assertFalse(self.w.view.minimap_visible())

    def test_minimap_click_moves_the_view_and_paints_without_error(self):
        from PyQt6.QtCore import QPointF
        from PyQt6.QtGui import QImage, QPainter
        self.scan(self.map_devices(30))
        v = self.w.view
        v.resetTransform(); v.scale(2.5, 2.5); self.app.processEvents()
        scene_rect, k, ox, oy = v.minimap_scale()
        target = QPointF(scene_rect.left() + 0.2 * scene_rect.width(), scene_rect.top() + 0.2 * scene_rect.height())
        v._mm_move(QPointF(ox + (target.x() - scene_rect.left()) * k, oy + (target.y() - scene_rect.top()) * k))
        centre = v.mapToScene(v.viewport().rect().center())
        self.assertLess(abs(centre.x() - target.x()), 60); self.assertLess(abs(centre.y() - target.y()), 60)
        img = QImage(v.viewport().size(), QImage.Format.Format_ARGB32); img.fill(0)
        p = QPainter(img); v.paint_minimap(p); p.end()
        box = v.minimap_rect()
        self.assertNotEqual(img.pixel(int(box.center().x()), int(box.center().y())), 0)             # quelque chose a été dessiné
        self.assertEqual(img.pixel(3, 3), 0)                                                         # et seulement dans le cadre

    def test_minimap_geometry_with_an_empty_scene(self):
        self.w.scene.clear(); self.w.nodes = {}
        self.assertIsNone(self.w.view.minimap_scale())
        self.assertFalse(self.w.view.minimap_visible())

    def test_rubber_band_selects_several_devices_and_the_panel_summarises_them(self):
        from PyQt6.QtGui import QPainterPath
        self.scan(self.map_devices())
        path = QPainterPath(); path.addRect(self.w.scene.itemsBoundingRect())
        self.w.scene.setSelectionArea(path)
        self.app.processEvents()
        n_real = len([d for d in self.w.devices if not d.get("virtual")])
        self.assertEqual(len(self.w.selected_keys), n_real)
        self.assertIsNone(self.w.current_device())
        self.assertIn(str(n_real), self.w.side_title.text())
        self.assertTrue(self.w.edit_btn.isHidden())                                                  # pas de renommage en masse
        self.assertFalse(self.w.trust_btn.isHidden())
        self.assertIn("Marquer la sélection", self.w.trust_btn.text())
        self.assertIn("Étiquettes et groupe", self.w.meta_btn.text())

    def test_selecting_one_device_restores_the_single_panel(self):
        self.scan(self.map_devices())
        self.w.select_all_nodes(); self.app.processEvents()
        self.assertGreater(len(self.w.selected_keys), 1)
        self.w.scene.clearSelection()
        key = gui.dkey(self.w.devices[3]); self.w.nodes[key].setSelected(True); self.app.processEvents()
        self.assertEqual(self.w.selected_keys, [key])
        self.assertIs(self.w.current_device(), self.w.devices[3])
        self.assertFalse(self.w.edit_btn.isHidden())
        self.assertEqual(self.w.meta_btn.text(), "Étiquettes, notes et groupe…")

    def test_trust_selection_toggles_for_all_selected_devices(self):
        self.scan(self.map_devices())
        keys = [gui.dkey(d) for d in self.w.devices if d["type"] in ("phone", "tv")]
        for k in keys:
            self.w.nodes[k].setSelected(True)
        self.app.processEvents()
        self.w.trust_btn.click()
        by_key = {gui.dkey(d): d for d in self.w.devices}
        self.assertTrue(all(by_key[k].get("trusted") for k in keys))
        self.assertTrue(all(not d.get("trusted") for d in self.w.devices if gui.dkey(d) not in keys))   # les autres n'ont pas bougé
        self.assertEqual(len(self.w.selected_keys), len(keys))                                      # la sélection survit au rafraîchissement
        self.w.trust_btn.click()                                                                    # tous de confiance : le second clic retire
        self.assertTrue(all(not d.get("trusted") for d in self.w.devices))

    def test_group_and_tags_for_the_selection_add_without_erasing(self):
        self.scan(self.map_devices())
        a, b = [d for d in self.w.devices if d["type"] == "phone"][:2]
        history_meta = __import__("panther.history", fromlist=["x"])
        history_meta.set_meta(a, tags="déjà", note="ma note")
        for d in (a, b):
            self.w.nodes[gui.dkey(d)].setSelected(True)
        self.app.processEvents()
        old_exec, old_values = gui.MetaDialog.exec, gui.MetaDialog.values
        gui.MetaDialog.exec, gui.MetaDialog.values = (lambda self: True), (lambda self: ("salon", "enfants, tv", None))
        try:
            self.w.meta_btn.click()
        finally:
            gui.MetaDialog.exec, gui.MetaDialog.values = old_exec, old_values
        by_key = {gui.dkey(d): d for d in self.w.devices}
        ka, kb = by_key[gui.dkey(a)], by_key[gui.dkey(b)]
        self.assertEqual((ka["group"], kb["group"]), ("salon", "salon"))
        self.assertEqual(sorted(ka["tags"]), ["déjà", "enfants", "tv"])                              # ajoutées aux étiquettes existantes
        self.assertEqual(sorted(kb["tags"]), ["enfants", "tv"])
        self.assertEqual(ka["note"], "ma note")                                                      # la note n'est pas touchée

    def test_multi_meta_dialog_hides_the_note_and_keeps_the_group_empty(self):
        dlg = gui.MetaDialog(dev("192.168.1.2", "a", "tv", group="x", tags=["t"]), ["x"], self.w, count=3)
        self.assertEqual((dlg.group.currentText(), dlg.tags.text()), ("", ""))
        self.assertIn("3", dlg.windowTitle())
        self.assertIsNone(dlg.values()[2])
        single = gui.MetaDialog(dev("192.168.1.2", "a", "tv", group="x", tags=["t"]), ["x"], self.w)
        self.assertEqual((single.group.currentText(), single.tags.text()), ("x", "t"))

    def test_center_on_selection_for_one_and_for_many(self):
        self.scan(self.map_devices(30))
        v = self.w.view
        v.resetTransform(); v.scale(2, 2)
        key = gui.dkey(self.w.devices[10]); n = self.w.nodes[key]
        n.setSelected(True); self.app.processEvents()
        self.w.center_on_selection()
        c = v.mapToScene(v.viewport().rect().center())
        self.assertLess(abs(c.x() - n.pos().x()), 20); self.assertLess(abs(c.y() - n.pos().y()), 20)
        self.w.select_all_nodes(); self.app.processEvents()
        self.w.center_on_selection()
        whole = self.w.scene.itemsBoundingRect()
        visible = v.mapToScene(v.viewport().rect()).boundingRect()
        self.assertTrue(visible.contains(whole.center()))
        self.w.scene.clearSelection(); self.w.selected = None; self.w.selected_keys = []
        self.w.center_on_selection()
        self.assertIn("Sélectionnez", self.w.status.text())

    def test_shift_drag_in_empty_space_switches_to_rubber_band_then_back(self):
        from PyQt6.QtCore import QPointF
        from PyQt6.QtGui import QMouseEvent
        from PyQt6.QtWidgets import QGraphicsView
        self.scan(self.map_devices(2))
        v = self.w.view
        v.resetTransform(); v.centerOn(5000, 5000)                                                    # loin de tout nœud : le vide
        pos = QPointF(40, 40)
        v.mousePressEvent(QMouseEvent(QMouseEvent.Type.MouseButtonPress, pos, v.mapToGlobal(pos), Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.ShiftModifier))
        self.assertEqual(v.dragMode(), QGraphicsView.DragMode.RubberBandDrag)
        v.mouseReleaseEvent(QMouseEvent(QMouseEvent.Type.MouseButtonRelease, pos, v.mapToGlobal(pos), Qt.MouseButton.LeftButton, Qt.MouseButton.NoButton, Qt.KeyboardModifier.ShiftModifier))
        self.assertEqual(v.dragMode(), QGraphicsView.DragMode.ScrollHandDrag)

    # --- accessibilité : thèmes, taille du texte, clavier, assistant
    @staticmethod
    def contrast(a, b):
        def lum(h):
            h = h.lstrip("#")
            c = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
            return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
        hi, lo = sorted((lum(a), lum(b)), reverse=True)
        return (hi + 0.05) / (lo + 0.05)

    def test_every_theme_meets_wcag_contrast_for_text_and_icons(self):
        for name, t in gui.THEMES.items():
            surfaces = [t["bg"], t["surface"], t["panel"], t["hover"]]
            for fg in ("fg", "mut", "acc", "warn", "ok", "bad"):                                 # tout ce qui sert à écrire du texte
                for bg in surfaces:
                    self.assertGreaterEqual(self.contrast(t[fg], bg), 4.5, f"{name}: {fg} sur {bg}")
            self.assertGreaterEqual(self.contrast(t["on_acc"], t["acc"]), 4.5, f"{name}: texte du bouton principal")
            self.assertGreaterEqual(self.contrast(t["fg"], t["acc_bg"]), 4.5, f"{name}: texte sélectionné")
            for kind, colour in gui.TYPE_COLORS.items():                                         # icônes de la carte : 3:1 suffit (éléments graphiques)
                gui.T.update(t)
                self.assertGreaterEqual(self.contrast(gui.type_color(kind), t["bg"]), 3.0, f"{name}: icône {kind}")
        gui.T.update(gui.THEMES["dark"])
        t = gui.THEMES["contrast"]
        self.assertGreaterEqual(self.contrast(t["fg"], t["bg"]), 7.0)                           # AAA pour le thème contraste élevé
        self.assertGreaterEqual(self.contrast(t["mut"], t["bg"]), 7.0)

    def test_theme_modes_resolve_and_persist(self):
        old = theme.system_theme
        try:
            theme.system_theme = lambda: "light"
            self.assertEqual((gui.resolve_theme("auto"), gui.resolve_theme("dark"), gui.resolve_theme("contrast"), gui.resolve_theme("zzz")),
                             ("light", "dark", "contrast", "dark"))
            self.w.set_theme_mode("auto")
            self.assertEqual((self.w.settings.value("theme"), gui.T["bg"]), ("auto", gui.THEMES["light"]["bg"]))
            theme.system_theme = lambda: "dark"
            self.w.on_system_theme()                                                              # le système passe en sombre : « auto » suit
            self.assertEqual(gui.T["bg"], gui.THEMES["dark"]["bg"])
            self.w.set_theme_mode("light")
            self.w.on_system_theme()                                                              # un thème choisi à la main ne bouge plus
            self.assertEqual(gui.T["bg"], gui.THEMES["light"]["bg"])
            self.w.set_theme_mode("contrast")
            self.assertEqual(gui.T["bg"], "#000000")
            self.assertTrue(self.w.theme_actions["contrast"].isChecked())
            self.w.set_theme_mode("nimportequoi")
            self.assertEqual(self.w.theme_mode, "auto")
        finally:
            theme.system_theme = old

    def test_text_size_scales_the_interface_and_the_map(self):
        self.scan(self.map_devices(4))
        node = next(iter(self.w.nodes.values()))
        base_pt, base_h = self.app.font().pointSizeF(), node.boundingRect().height()
        self.w.set_text_size("xlarge")
        self.assertEqual((self.w.settings.value("text_size"), theme.FONT_SCALE), ("xlarge", 1.4))
        self.assertAlmostEqual(self.app.font().pointSizeF(), base_pt * 1.4, places=1)
        self.assertGreater(next(iter(self.w.nodes.values())).boundingRect().height(), base_h)    # la zone du nom grandit avec la police
        self.assertIn("22px", gui.make_style())                                                   # 16 px × 1,4
        self.w.set_text_size("normal")
        self.assertAlmostEqual(self.app.font().pointSizeF(), base_pt, places=1)
        self.w.set_text_size("bidon")
        self.assertEqual(self.w.text_size, "normal")

    def key(self, key, mods=None):
        from PyQt6.QtCore import QEvent
        from PyQt6.QtGui import QKeyEvent
        self.w.view.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, key, mods or Qt.KeyboardModifier.NoModifier))
        self.app.processEvents()

    def test_map_is_keyboard_navigable(self):
        self.scan(self.map_devices(6))
        v = self.w.view
        self.assertEqual(v.focusPolicy(), Qt.FocusPolicy.StrongFocus)
        self.assertTrue(v.accessibleName() and v.accessibleDescription())
        for n in v.device_nodes():                                                               # grille connue : colonnes de 100 px
            n.setSelected(False)
        nodes = sorted(v.device_nodes(), key=lambda n: gui.ip_key(n.dev["ip"]))
        for i, n in enumerate(nodes):
            n.setPos(i % 3 * 120, i // 3 * 120)
        self.app.processEvents()
        a = nodes[0]; a.setSelected(True); self.app.processEvents()
        self.key(Qt.Key.Key_Right)
        self.assertEqual(self.w.selected_keys, [gui.dkey(nodes[1].dev)])
        self.key(Qt.Key.Key_Down)
        self.assertEqual(self.w.selected_keys, [gui.dkey(nodes[4].dev)])
        self.key(Qt.Key.Key_Left, Qt.KeyboardModifier.ShiftModifier)                             # Maj : on ajoute
        self.assertEqual(set(self.w.selected_keys), {gui.dkey(nodes[4].dev), gui.dkey(nodes[3].dev)})
        self.key(Qt.Key.Key_Escape)
        self.assertEqual(self.w.selected_keys, [])
        self.key(Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(len(self.w.selected_keys), len(nodes))
        self.key(Qt.Key.Key_Escape)

    def test_arrow_keys_start_from_the_centre_when_nothing_is_selected_and_stop_at_the_edges(self):
        self.scan(self.map_devices(3))
        self.w.scene.clearSelection(); self.app.processEvents()
        self.key(Qt.Key.Key_Left)
        self.assertEqual(len(self.w.selected_keys), 1)                                           # un appareil est choisi, pas d'erreur
        only = self.w.view.device_nodes()
        far = max(only, key=lambda n: n.pos().x())
        self.w.scene.clearSelection(); far.setSelected(True); self.app.processEvents()
        self.key(Qt.Key.Key_Right)                                                               # rien plus à droite : la sélection ne bouge pas
        self.assertEqual(self.w.selected_keys, [gui.dkey(far.dev)])

    def test_enter_edits_and_plus_minus_zoom(self):
        self.scan(self.map_devices(3))
        edited = []
        for n in self.w.nodes.values():
            n.edit_cb = lambda d, e=edited: e.append(d["ip"])
        n = self.w.view.device_nodes()[0]; n.setSelected(True); self.app.processEvents()
        self.key(Qt.Key.Key_Return)
        self.assertEqual(edited, [n.dev["ip"]])
        z0 = self.w.view.transform().m11()
        self.key(Qt.Key.Key_Plus); z1 = self.w.view.transform().m11()
        self.key(Qt.Key.Key_Minus); z2 = self.w.view.transform().m11()
        self.assertGreater(z1, z0); self.assertAlmostEqual(z2, z0, places=6)

    def test_keyboard_focus_is_visible_in_the_style(self):
        css = gui.make_style()
        for sel in ("QPushButton:focus", "QCheckBox:focus", "QTabBar::tab:focus", "QTableWidget:focus"):
            self.assertIn(sel, css)

    def test_welcome_wizard_flow_and_language_switch(self):
        from panther import i18n
        try:
            i18n.set_language("fr")
            wiz = gui.WelcomeWizard()
            self.assertEqual(wiz.stack.count(), 4)
            self.assertEqual(wiz.stack.currentIndex(), 0)
            wiz.lang_buttons["en"].click()                                                       # les pages suivantes passent en anglais
            self.assertEqual(i18n.language(), "en")
            wiz.go(1)
            self.assertEqual(wiz.next_btn.text(), "Next")
            self.assertFalse(wiz.next_btn.isEnabled())                                           # il faut cocher l'usage responsable
            wiz.agree.setChecked(True)
            self.assertTrue(wiz.next_btn.isEnabled())
            wiz.go(3)
            self.assertEqual((wiz.next_btn.text(), wiz.step.text()), ("Finish", "Step 4 of 4"))
            wiz.theme.setCurrentIndex(wiz.theme.findData("contrast")); wiz.size.setCurrentIndex(wiz.size.findData("large"))
            wiz.depth.setCurrentIndex(wiz.depth.findData("rapide")); wiz.auto.setCurrentIndex(wiz.auto.findData(30)); wiz.security.setChecked(True)
            self.assertEqual(wiz.values(), {"language": "en", "theme": "contrast", "text_size": "large", "depth": "rapide", "auto_minutes": 30,
                                            "passive": False, "security": True})
            wiz.lang_buttons["fr"].click()                                                       # retour au français : tout est reconstruit
            wiz.go(1)
            self.assertEqual(wiz.next_btn.text(), "Suivant")
        finally:
            i18n.set_language("fr")

    def test_apply_welcome_settings_is_validated_and_marks_the_first_run_done(self):
        st = self.w.settings
        self.assertTrue(gui.first_run_needed(st))
        gui.apply_welcome_settings(st, {"language": "xx", "theme": "rose", "text_size": "énorme", "depth": "dangereux", "auto_minutes": 7,
                                        "passive": False, "security": True})
        self.assertEqual([st.value(k) for k in ("language", "theme", "text_size", "depth", "auto_minutes")], ["fr", "auto", "normal", "normal", 0])
        self.assertFalse(gui.first_run_needed(st))
        self.assertTrue(str(st.value("security_consent")).lower() in ("true", "1"))
        gui.apply_welcome_settings(st, {"language": "en", "theme": "dark", "text_size": "large", "depth": "rapide", "auto_minutes": 15,
                                        "passive": True, "security": True})
        self.assertEqual(str(st.value("security")).lower(), "false")                                  # écoute seule : jamais d'analyse active
        self.assertEqual((st.value("language"), st.value("auto_minutes")), ("en", 15))

    def test_reopening_the_assistant_applies_choices_live(self):
        values = {"language": "fr", "theme": "light", "text_size": "large", "depth": "approfondi", "auto_minutes": 30, "passive": True, "security": False}
        old = (gui.WelcomeWizard.exec, gui.WelcomeWizard.values)
        gui.WelcomeWizard.exec, gui.WelcomeWizard.values = (lambda self: True), (lambda self: values)
        try:
            self.w.open_welcome()
        finally:
            gui.WelcomeWizard.exec, gui.WelcomeWizard.values = old
        self.assertEqual((self.w.theme_mode, self.w.text_size, self.w.depth.currentData(), self.w.passive_on), ("light", "large", "approfondi", True))
        self.assertEqual(gui.T["bg"], gui.THEMES["light"]["bg"])
        self.assertTrue(self.w.auto_actions[30].isChecked())
        self.assertFalse(self.w.depth.isEnabled())

    def test_skipping_the_assistant_changes_nothing(self):
        before = (self.w.theme_mode, self.w.passive_on, self.w.depth.currentData())
        old = gui.WelcomeWizard.exec
        gui.WelcomeWizard.exec = lambda self: False
        try:
            self.w.open_welcome()
        finally:
            gui.WelcomeWizard.exec = old
        self.assertEqual((self.w.theme_mode, self.w.passive_on, self.w.depth.currentData()), before)

    def test_package_resources_are_found_from_the_ui_subpackage(self):
        from panther.ui import app
        self.assertTrue(os.path.isfile(app.ICON))
        self.assertTrue(os.path.isfile(os.path.join(app.PACKAGE_DIR, "oui.txt")))
        self.assertTrue(os.path.isdir(os.path.join(app.PACKAGE_DIR, "static")))

    # --- anglais
    FRENCH = __import__("re").compile(r"[àâçéèêëîïôùûüœ]|\b(appareils?|réseaux?|lancez|aucun[e]?|erreur|impossible|enregistr\w+|choisissez|dossier|fichier|"
                                      r"sélectionn\w+|nouveau|nouvel|hors ligne|en ligne|avec|dans|pour|une?|des|les|est|pas|sur)\b", __import__("re").I)

    def visible_texts(self, root):
        from PyQt6.QtGui import QAction
        from PyQt6.QtWidgets import QComboBox, QLabel, QListWidget, QMenu, QPushButton, QTableWidget, QTabWidget
        out = set()
        for x in root.findChildren(QWidget) + [root]:
            out.add(x.toolTip()); out.add(x.windowTitle() if x.isWindow() else "")
            if isinstance(x, (QLabel, QPushButton)) or hasattr(x, "placeholderText"):
                out.add(x.text() if hasattr(x, "text") else ""); out.add(getattr(x, "placeholderText", lambda: "")())
            if isinstance(x, QTableWidget):
                out.update(x.horizontalHeaderItem(c).text() for c in range(x.columnCount()) if x.horizontalHeaderItem(c))
                out.update(x.item(r, c).text() for r in range(x.rowCount()) for c in range(x.columnCount()) if x.item(r, c))
            if isinstance(x, QComboBox):
                out.update(x.itemText(i) for i in range(x.count()))
            if isinstance(x, QListWidget):
                out.update(x.item(i).text() for i in range(x.count()))
            if isinstance(x, QTabWidget):
                out.update(x.tabText(i) for i in range(x.count()))
        out.update(a.text() + " " + a.toolTip() for a in root.findChildren(QAction))
        out.update(m.title() for m in root.findChildren(QMenu))
        return {__import__("re").sub(r"<[^>]+>", " ", t) for t in out if t.strip()}

    def test_english_interface_has_no_french_leftovers(self):
        from panther import demo, i18n
        i18n.set_language("en")
        try:
            w = gui.Main(scanner=demo.DemoScanner(duration=0.1), demo=True)
            w.show(); gui.start_demo(w)
            w.security_on = True
            w.start_scan(); end = time.time() + 3
            while w.scanner.snapshot()["status"] == "scanning" and time.time() < end:
                time.sleep(0.02)
            w.poll(); self.app.processEvents()
            texts = set(self.visible_texts(w)); texts.add(w.status.text())
            for i in range(w.tabs.count()):
                w.tabs.setCurrentIndex(i); self.app.processEvents(); texts |= self.visible_texts(w)
            for d in list(w.devices):
                w.selected = gui.dkey(d); w.refresh_panel(); self.app.processEvents(); texts |= self.visible_texts(w)
            for make in (lambda: gui.DataDialog(90, 365, w), lambda: gui.AlertsDialog(w), lambda: gui.ReportScheduleDialog(w.report_settings(), w),
                         lambda: gui.NetworksDialog("192.168.1.0/24", [], [], w), lambda: gui.RulesDialog(w, lambda: None),
                         lambda: gui.MetaDialog(w.devices[3], ["salon"], w), lambda: gui.RuleFromDeviceDialog(w.devices[3], w),
                         lambda: gui.EditDialog(w.devices[3], w), lambda: gui.CompareDialog(history.list_scans(), w),
                         lambda: gui.DuplicatesDialog([(w.devices[3], w.devices[4], ["same name"])], lambda a, b: None, w), lambda: gui.MergeDialog("t", "text", w.devices[:3], w)):
                dlg = make(); texts |= self.visible_texts(dlg); dlg.close()
            wiz = gui.WelcomeWizard(); i18n.set_language("en"); wiz.choose_language("en")
            texts |= {t for t in self.visible_texts(wiz) if "Welcome" not in t and "Choose your language" not in t}   # 1re page : volontairement bilingue
            wiz.close()
            bad = sorted(t for t in texts if self.FRENCH.search(t.replace("Français", "")))
            self.assertEqual(bad, [])
            self.assertGreater(len(texts), 150)                                                  # le parcours a bien vu l'interface
            w.close()
        finally:
            i18n.set_language("fr")

    def test_language_menu_saves_the_choice_and_warns_about_restart(self):
        self.w.choose_language("en")
        self.assertEqual(self.w.settings.value("language"), "en")
        self.assertTrue(any(b[0] == "information" for b in self.boxes))
        self.w.choose_language("fr")
        self.assertEqual(self.w.settings.value("language"), "fr")

    # --- mode démonstration
    def test_demo_window_is_populated_from_the_fictional_network_and_never_touches_the_network(self):
        import socket
        from panther import demo
        real_socket, calls = socket.socket, []
        socket.socket = lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError("accès réseau en mode démo"))
        try:
            w = gui.Main(scanner=demo.DemoScanner(duration=0.2), demo=True)
            w.notify = lambda *a: None
            gui.start_demo(w)
            names = {d["hostname"] for d in w.devices}
            self.assertTrue({"box", "nas", "camera-garage", "ancien-pc"} <= names)
            self.assertFalse(next(d for d in w.devices if d["hostname"] == "ancien-pc")["online"])   # hors ligne grâce à l'historique semé
            self.assertIn("démonstration", w.windowTitle())
            self.assertGreaterEqual(len(history.list_scans()), 3)
            w.start_scan()                                                                       # le scan simulé va jusqu'au bout
            end = time.time() + 5
            while w.scanner.snapshot()["status"] == "scanning" and time.time() < end:
                time.sleep(0.05)
            w.poll(); self.app.processEvents()
            self.assertIn("Scan terminé", w.status.text())
            w.wake_device(next(d for d in w.devices if d["hostname"] == "ancien-pc"))
            w.update_oui()
            self.assertFalse(calls)
            self.assertTrue(w.report_settings()["folder"].startswith(os.path.dirname(history.PATH)))   # jamais le dossier personnel
            w.close()
        finally:
            socket.socket = real_socket

    def test_demo_isolate_redirects_every_config_file_and_cleans_up(self):
        from panther import alerts, demo, ouiupdate, rules
        from panther import log as plog
        saved = (history.PATH, store.PATH, alerts.PATH, rules.PATH, secrets.PATH, plog.PATH, ouiupdate.USER_PATH, os.environ.get("XDG_CONFIG_HOME"), secrets._tool)
        tmp = None
        try:
            tmp = demo.isolate()
            for path in (history.PATH, store.PATH, alerts.PATH, rules.PATH, secrets.PATH, plog.PATH, ouiupdate.USER_PATH):
                self.assertTrue(path.startswith(tmp), path)
            self.assertIsNone(secrets._tool())                                                     # jamais le vrai trousseau
        finally:
            (history.PATH, store.PATH, alerts.PATH, rules.PATH, secrets.PATH, plog.PATH, ouiupdate.USER_PATH, xdg, secrets._tool) = saved
            if xdg is None:
                os.environ.pop("XDG_CONFIG_HOME", None)
            else:
                os.environ["XDG_CONFIG_HOME"] = xdg
            if tmp:
                demo.cleanup(tmp)
                self.assertFalse(os.path.exists(tmp))
            QSettings.setPath(QSettings.Format.NativeFormat, QSettings.Scope.UserScope, self.tmp.name)

    # --- rapports planifiés
    def report_cfg(self, **kw):
        folder = os.path.join(self.tmp.name, "rapports")
        self.w.save_report_settings(kw.get("enabled", True), kw.get("freq", "daily"), kw.get("folder", folder), kw.get("keep", 3))
        return folder

    def test_report_tick_writes_one_pdf_when_due_then_waits(self):
        folder = self.report_cfg()
        self.scan([dev("192.168.1.1", "box", "router"), dev("192.168.1.20", "tv", "tv")])
        t0 = 1_800_000_000
        path = self.w.report_tick(t0)
        self.assertTrue(path and os.path.isfile(path))
        with open(path, "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")
        self.assertIsNone(self.w.report_tick(t0 + 3600))                                    # pas encore dû
        self.assertEqual(len(os.listdir(folder)), 1)
        self.assertTrue(self.w.report_tick(t0 + 24 * 3600 + 60))                            # le lendemain
        self.assertEqual(len(os.listdir(folder)), 2)

    def test_report_tick_does_nothing_when_disabled_empty_or_scanning(self):
        folder = self.report_cfg(enabled=False)
        self.scan([dev("192.168.1.1", "box", "router")])
        self.assertIsNone(self.w.report_tick(1_800_000_000)); self.assertFalse(os.path.exists(folder))
        self.report_cfg(enabled=True)
        self.w.devices = []
        self.assertIsNone(self.w.report_tick(1_800_000_000)); self.assertFalse(os.path.exists(folder))

    def test_report_tick_prunes_old_reports_and_keeps_foreign_files(self):
        folder = self.report_cfg(keep=2)
        os.makedirs(folder)
        open(os.path.join(folder, "notes.pdf"), "w").close()
        self.scan([dev("192.168.1.1", "box", "router")])
        for i in range(4):
            self.assertTrue(self.w.report_tick(1_800_000_000 + i * 24 * 3600))
        names = sorted(os.listdir(folder))
        self.assertEqual(len([n for n in names if n.startswith("rapport-panther-")]), 2)
        self.assertIn("notes.pdf", names)

    def test_report_tick_failure_is_reported_and_not_retried_every_minute(self):
        blocker = os.path.join(self.tmp.name, "fichier"); open(blocker, "w").close()
        self.report_cfg(folder=os.path.join(blocker, "sous"))                               # impossible de créer ce dossier
        self.scan([dev("192.168.1.1", "box", "router")])
        t0 = 1_800_000_000
        self.assertIsNone(self.w.report_tick(t0))
        self.assertIn("impossible", self.w.status.text())
        self.assertFalse(schedule.is_due(self.w.report_settings()["last"], t0 + 60, "daily"))

    def test_report_dialog_saves_settings_and_generates_now(self):
        self.scan([dev("192.168.1.1", "box", "router")])
        folder = os.path.join(self.tmp.name, "dlg")
        dlg = gui.ReportScheduleDialog(self.w.report_settings(), self.w)
        dlg.enabled.setChecked(True); dlg.freq.setCurrentIndex(dlg.freq.findData("daily")); dlg.folder.setText(folder); dlg.keep.setValue(5)
        dlg.generate_now()
        self.assertTrue(dlg.generated)
        self.assertEqual(len(os.listdir(folder)), 1)
        self.assertIn(folder, dlg.result.text())
        self.assertEqual(dlg.values(), (True, "daily", folder, 5))

    def test_report_settings_survive_garbage_values(self):
        self.w.settings.setValue("report_keep", "abc"); self.w.settings.setValue("report_freq", "hourly"); self.w.settings.setValue("report_last", "x")
        cfg = self.w.report_settings()
        self.assertEqual((cfg["keep"], cfg["freq"], cfg["last"]), (10, "weekly", 0.0))

    def test_alerts_dialog_refuses_an_invalid_address_and_saves_nothing(self):
        dlg = gui.AlertsDialog(self.w)
        dlg.em_on.setChecked(True); dlg.em_to.setText("pas-une-adresse")
        dlg.accept()
        self.assertIn("adresse e-mail invalide", dlg.result.text())
        self.assertFalse(os.path.exists(alerts.PATH))

    def test_test_button_sends_with_the_typed_values_in_the_background(self):
        calls = self.capture_dispatch()
        dlg = gui.AlertsDialog(self.w)
        dlg.send_test()
        self.assertIn("Activez", dlg.result.text())                                           # rien d'actif : explication, pas d'envoi
        dlg.wh_on.setChecked(True); dlg.wh_url.setText("https://x.example/h")
        dlg.send_test()
        end = time.time() + 5
        while dlg.test_worker.isRunning() and time.time() < end:
            self.app.processEvents(); time.sleep(0.02)
        self.app.processEvents()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["webhook_url"], "https://x.example/h")                    # valeurs saisies, pas besoin d'enregistrer d'abord
        self.assertEqual(calls[0][0][0]["kind"], "test")
        self.assertIn("webhook : envoyé", dlg.result.text())
        self.assertFalse(os.path.exists(secrets.PATH))                                        # un test n'enregistre rien

    def test_clear_secrets_button(self):
        secrets.set(alerts.SECRET_WEBHOOK, "u"); secrets.set(alerts.SECRET_SMTP, "p")
        dlg = gui.AlertsDialog(self.w); dlg.clear_secrets()
        self.assertEqual((secrets.get(alerts.SECRET_WEBHOOK), secrets.get(alerts.SECRET_SMTP)), (None, None))

    def test_no_alert_for_the_first_analysis_then_alert_on_a_new_device_of_an_automatic_scan(self):
        calls = self.capture_dispatch()
        self.enable_alerts()
        w = self.w
        w.last_scan_auto = True
        self.scan(network()); self.wait_workers(w)
        self.assertEqual(calls, [])                                                            # première analyse = référence : silence
        newcomer = dev("192.168.1.98", "camera-neuve", "camera")
        self.scan([*network(), newcomer]); self.wait_workers(w)                                # (scan automatique : last_scan_auto reste vrai)
        self.assertEqual(len(calls), 1)
        self.assertEqual([e["kind"] for e in calls[0][0]], ["new_device"])
        self.assertIn("camera-neuve", calls[0][0][0]["title"])
        self.assertIn("Alerte envoyée", w.status.text())
        self.scan([*network(), newcomer]); self.wait_workers(w)
        self.assertEqual(len(calls), 1)                                                        # le même appareil n'est plus « nouveau » : pas de répétition

    def test_manual_scans_stay_quiet_unless_the_user_asked_for_them_too(self):
        calls = self.capture_dispatch()
        w = self.w
        self.enable_alerts(auto_only=True)
        self.scan(network())
        w.last_scan_auto = False
        w.finish_scan({"devices": [*network(), dev("192.168.1.97", "nouveau", "iot")], "networks": w.networks_info, "depth": "normal"}, 5); self.wait_workers(w)
        self.assertEqual(calls, [])
        self.enable_alerts(auto_only=False)
        w.finish_scan({"devices": [*network(), dev("192.168.1.96", "autre-nouveau", "iot")], "networks": w.networks_info, "depth": "normal"}, 5); self.wait_workers(w)
        self.assertEqual(len(calls), 1)

    def test_disabled_alerts_or_no_channel_send_nothing(self):
        calls = self.capture_dispatch()
        w = self.w
        self.scan(network())
        alerts.save({"enabled": False, "webhook": {"enabled": True}})
        w.last_scan_auto = True
        w.finish_scan({"devices": [*network(), dev("192.168.1.95", "x", "iot")], "networks": w.networks_info, "depth": "normal"}, 5); self.wait_workers(w)
        alerts.save({"enabled": True, "webhook": {"enabled": False}, "email": {"enabled": False}})
        w.finish_scan({"devices": [*network(), dev("192.168.1.94", "y", "iot")], "networks": w.networks_info, "depth": "normal"}, 5); self.wait_workers(w)
        self.assertEqual(calls, [])

    def test_exposure_threshold_and_failure_reporting(self):
        calls = self.capture_dispatch([("webhook", False, "le service a répondu 500")])
        w = self.w
        self.enable_alerts(new_device=False, new_exposure=True, exposure_min="critique", auto_only=False)
        w.security_on = True
        self.scan(network())
        cam = dev("192.168.1.50", "cam", "camera", ports=[23, 554])
        cam["security"] = security.analyze(cam, {554: "open"})                                  # Élevé seulement : sous le seuil « critique »
        w.finish_scan({"devices": [*network(), cam], "networks": w.networks_info, "depth": "normal"}, 5); self.wait_workers(w)
        self.assertEqual(calls, [])
        redis = dev("192.168.1.51", "nas", "nas", ports=[6379]); redis["security"] = security.analyze(redis, {6379: "open"})
        w.finish_scan({"devices": [*network(), cam, redis], "networks": w.networks_info, "depth": "normal"}, 5); self.wait_workers(w)
        self.assertEqual(len(calls), 1)
        self.assertIn("Redis", calls[0][0][0]["detail"])
        self.assertIn("Alerte non envoyée", w.status.text()); self.assertIn("500", w.status.text())

    # --- réveil à distance et base des fabricants
    def offline_device(self, mac="a4:bb:cc:00:00:60", **kw):
        d = dev("192.168.1.60", "nas-salon", "nas", mac=mac, online=False, last_seen=time.time() - 3600, **kw)
        return d

    def test_wake_on_lan_sends_to_the_network_broadcast_and_reports_it(self):
        sent = []
        orig = wol.send
        wol.send = lambda mac, targets, **k: sent.append((mac, list(targets))) or 2
        try:
            self.w.wake_device(self.offline_device())
        finally:
            wol.send = orig
        self.assertEqual(sent, [("a4:bb:cc:00:00:60", ["192.168.1.255", "255.255.255.255"])])
        self.assertIn("Paquet de réveil envoyé à nas-salon", self.w.status.text())
        self.assertIn("Wake-on-LAN soit activé", self.w.status.text())                       # l'utilisateur est prévenu de la condition

    def test_wake_on_lan_refuses_a_random_mac_with_an_explanation(self):
        orig = wol.send
        wol.send = lambda *a, **k: self.fail("rien ne doit être envoyé")
        try:
            self.w.wake_device(self.offline_device(mac="7a:00:00:00:00:60"))
        finally:
            wol.send = orig
        self.assertEqual(self.boxes[-1][0], "information")
        self.assertIn("aléatoire", self.boxes[-1][1][1])

    def test_wake_entry_is_offered_only_for_offline_devices_with_a_mac(self):
        self.scan(network())
        w = self.w
        labels = []
        import panther.gui as g
        orig = QMenu.exec
        QMenu.exec = lambda self_, pos=None: labels.extend(a.text() for a in self_.actions())
        try:
            w.device_menu(w.devices[2], QPointF(0, 0).toPoint())
            self.assertFalse(any("Wake-on-LAN" in x for x in labels))
            labels.clear()
            off = self.offline_device(); w.devices.append(off)
            w.device_menu(off, QPointF(0, 0).toPoint())
            self.assertTrue(any("Wake-on-LAN" in x for x in labels))
        finally:
            QMenu.exec = orig

    def wait_oui(self, w, timeout=5):
        end = time.time() + timeout
        while w.oui_worker.isRunning() and time.time() < end:
            self.app.processEvents(); time.sleep(0.02)
        self.app.processEvents()

    def test_oui_update_asks_first_then_downloads_in_the_background_and_reports(self):
        w = self.w
        calls = []
        orig = ouiupdate.update
        ouiupdate.update = lambda *a, **k: calls.append(1) or 1234
        try:
            w.update_oui(); self.wait_oui(w)
        finally:
            ouiupdate.update = orig
        self.assertEqual(self.boxes[0][0], "question")                                    # demande de confirmation avant tout téléchargement
        self.assertIn(ouiupdate.URL, self.boxes[0][1][1])
        self.assertEqual(calls, [1])
        self.assertIn("1234", w.status.text())

    def test_oui_update_declined_downloads_nothing(self):
        w = self.w
        gui.QMessageBox.question = staticmethod(lambda *a, **k: gui.QMessageBox.StandardButton.No)
        orig = ouiupdate.update
        ouiupdate.update = lambda *a, **k: self.fail("aucun téléchargement sans accord")
        try:
            w.update_oui()
        finally:
            ouiupdate.update = orig
        self.assertFalse(getattr(w, "oui_worker", None))

    def test_oui_update_failure_is_reported_without_crashing(self):
        w = self.w
        def boom(*a, **k):
            raise ouiupdate.UpdateError("téléchargement impossible : hors ligne")
        orig = ouiupdate.update
        ouiupdate.update = boom
        try:
            w.update_oui(); self.wait_oui(w)
        finally:
            ouiupdate.update = orig
        self.assertEqual(self.boxes[-1][0], "warning")
        self.assertIn("hors ligne", self.boxes[-1][1][1])
        self.assertIn("impossible", w.status.text())

    # --- export de la carte et des appareils
    def test_map_exports_to_png_and_svg_without_touching_theme_or_selection(self):
        self.scan(network())
        w = self.w
        sel = w.nodes[gui.dkey(w.devices[2])]; sel.setSelected(True)
        before = dict(gui.T)
        png, svg = os.path.join(self.tmp.name, "carte.png"), os.path.join(self.tmp.name, "carte.svg")
        w.write_map(png, theme="light", width=800); w.write_map(svg, theme="dark", width=800)
        with open(png, "rb") as f:
            self.assertEqual(f.read(8), b"\x89PNG\r\n\x1a\n")
        img = gui.QImage(png)
        self.assertEqual(img.width(), 800)
        self.assertGreater(img.height(), 100)
        with open(svg, encoding="utf-8") as f:
            text = f.read()
        self.assertTrue(text.lstrip().startswith("<?xml") and "<svg" in text)
        self.assertIn("Panther", text)
        self.assertGreater(len(text), 2000)
        self.assertEqual(dict(gui.T), before)                                          # le thème d'affichage n'a pas bougé
        self.assertTrue(sel.isSelected())                                              # la sélection est restaurée

    def test_exporting_an_empty_map_is_refused_clearly(self):
        with self.assertRaises(OSError):
            self.w.write_map(os.path.join(self.tmp.name, "vide.png"))

    def test_dark_and_light_png_differ_in_background(self):
        self.scan(network())
        light, dark = self.w.render_map_image(400, "light"), self.w.render_map_image(400, "dark")
        self.assertNotEqual(light.pixelColor(2, 2).name(), dark.pixelColor(2, 2).name())

    def test_enriched_exports_carry_metadata_and_resist_formula_injection(self):
        self.scan([*network(), dev("192.168.1.99", "=CMD()", "iot")])
        w = self.w
        tv = next(d for d in w.devices if d["hostname"] == "salon-tv")
        history.set_meta(tv, tags="enfants", group="Salon", note="meuble"); history.set_trusted([tv], True)
        csv_path, json_path = os.path.join(self.tmp.name, "e.csv"), os.path.join(self.tmp.name, "e.json")
        w.write_export(csv_path, "csv"); w.write_export(json_path, "json")
        import csv, json
        with open(csv_path, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        by = {r["Adresse IP"]: r for r in rows}
        self.assertEqual((by["192.168.1.10"]["Groupe"], by["192.168.1.10"]["Étiquettes"], by["192.168.1.10"]["De confiance"]), ("Salon", "enfants", "oui"))
        self.assertEqual(by["192.168.1.99"]["Nom"], "'=CMD()")                           # neutralisé
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data["devices"]), 5)
        self.assertEqual(data["networks"], [NET])

    # --- étiquettes, notes et groupes
    def tag_two_devices(self):
        w = self.w
        tv = next(d for d in w.devices if d["hostname"] == "salon-tv")
        pr = next(d for d in w.devices if d["hostname"] == "imprimante")
        history.set_meta(tv, tags="enfants, domotique", group="Salon", note="Posée sur le meuble TV")
        history.set_meta(pr, tags="bureau", group="Bureau du fond")
        w.refresh_views()
        return tv, pr

    def visible(self):
        w = self.w
        return sorted(w.table.item(r, 0).text() for r in range(w.table.rowCount()) if not w.table.isRowHidden(r))

    def test_meta_dialog_is_prefilled_and_returns_what_was_typed(self):
        self.scan(network())
        tv, _ = self.tag_two_devices()
        dlg = gui.MetaDialog(tv, ["Bureau du fond", "Salon"], self.w)
        self.assertEqual((dlg.group.currentText(), dlg.tags.text(), dlg.note.toPlainText()), ("Salon", "enfants, domotique", "Posée sur le meuble TV"))
        self.assertEqual([dlg.group.itemText(i) for i in range(dlg.group.count())], ["", "Bureau du fond", "Salon"])
        dlg.group.setCurrentText("Chambre"); dlg.tags.setText("a, b"); dlg.note.setPlainText("n")
        self.assertEqual(dlg.values(), ("Chambre", "a, b", "n"))

    def test_tags_group_and_notes_appear_in_the_panel_and_the_table(self):
        self.scan(network())
        tv, _ = self.tag_two_devices()
        w = self.w
        w.selected = gui.dkey(tv); w.refresh_panel()
        labels = {w.form.itemAt(r, gui.QFormLayout.ItemRole.LabelRole).widget().text(): w.form.itemAt(r, gui.QFormLayout.ItemRole.FieldRole).widget().text()
                  for r in range(w.form.rowCount()) if w.form.itemAt(r, gui.QFormLayout.ItemRole.FieldRole) and hasattr(w.form.itemAt(r, gui.QFormLayout.ItemRole.FieldRole).widget(), "text")}
        self.assertEqual((labels["Groupe"], labels["Étiquettes"], labels["Notes"]), ("Salon", "enfants  ·  domotique", "Posée sur le meuble TV"))
        row = next(r for r in range(w.table.rowCount()) if w.table.item(r, 0).text() == "salon-tv")
        self.assertEqual((w.table.item(row, 11).text(), w.table.item(row, 12).text()), ("Salon", "enfants, domotique"))

    def test_filter_tokens_tag_is_exact_group_is_a_substring_and_free_text_reaches_notes(self):
        self.scan(network())
        self.tag_two_devices()
        w = self.w
        w.search.setText("tag:enfants"); self.assertEqual(self.visible(), ["salon-tv"])
        w.search.setText("TAG:Domotique"); self.assertEqual(self.visible(), ["salon-tv"])            # casse ignorée
        w.search.setText("tag:enf"); self.assertEqual(self.visible(), [])                              # étiquette exacte, pas un morceau
        w.search.setText("groupe:fond"); self.assertEqual(self.visible(), ["imprimante"])              # groupe : contient le texte
        w.search.setText("group:salon tag:enfants"); self.assertEqual(self.visible(), ["salon-tv"])    # les jetons se combinent
        w.search.setText("group:salon tag:bureau"); self.assertEqual(self.visible(), [])
        w.search.setText("meuble"); self.assertEqual(self.visible(), ["salon-tv"])                     # texte libre : cherche aussi dans les notes
        w.search.setText(""); self.assertEqual(len(self.visible()), 4)

    def test_metadata_survives_a_new_scan_because_it_is_keyed_by_the_device(self):
        self.scan(network())
        self.tag_two_devices()
        self.scan(network())
        tv = next(d for d in self.w.devices if d["hostname"] == "salon-tv")
        self.assertEqual((tv["group"], tv["tags"]), ("Salon", ["enfants", "domotique"]))

    # --- règles de détection personnalisées
    def test_creating_a_rule_from_a_device_reclassifies_the_displayed_devices(self):
        w = self.w
        mystery = dev("192.168.1.80", "garage-1", "unknown", ports=[7777, 7778], vendor="")
        mystery["confidence"], mystery["reasons"] = 0, ["aucun indice exploitable"]
        self.scan([*network(), mystery, dev("192.168.1.81", "garage-2", "unknown", ports=[7777, 7778], vendor="")])
        target = next(d for d in w.devices if d["hostname"] == "garage-1")
        dlg = gui.RuleFromDeviceDialog(target, w)
        self.assertTrue(dlg.buttons.button(gui.QDialogButtonBox.StandardButton.Ok).isEnabled())
        dlg.kind.setCurrentIndex(dlg.kind.findData("camera"))
        for k in ("hostname", "vendor", "mdns", "mac"):
            dlg.boxes[k].setChecked(False)
        dlg.boxes["ports"].setChecked(True)                                          # critère : ports 7777 et 7778 ouverts
        self.assertIn("ports_all", dlg.view.text())
        rules.add_rule(dlg.build())
        w.reclassify_all()
        types = {d["hostname"]: d["type"] for d in w.devices}
        self.assertEqual((types["garage-1"], types["garage-2"]), ("camera", "camera"))   # la règle s'applique aussi à l'appareil jumeau
        self.assertEqual(types["salon-tv"], "tv")                                        # les autres sont inchangés
        self.assertIn("camera", {k for k, _ in w.view.legend})
        reasons = next(d for d in w.devices if d["hostname"] == "garage-1")["reasons"]
        self.assertTrue(any("règle" in r for r in reasons))

    def test_rule_dialog_without_any_usable_criterion_cannot_be_saved(self):
        w = self.w
        bare = dev("192.168.1.90", "192.168.1.90", "unknown", vendor="MAC aléatoire", mac="7a:00:00:00:00:01")
        bare["ports"], bare["mdns_services"] = [], []
        dlg = gui.RuleFromDeviceDialog(bare, w)
        self.assertFalse(dlg.buttons.button(gui.QDialogButtonBox.StandardButton.Ok).isEnabled())
        self.assertIn("aucun critère", dlg.view.text())

    def test_reclassify_keeps_manual_settings_and_skips_presence_data_and_this_machine(self):
        self.scan(network())
        w = self.w
        tv = next(d for d in w.devices if d["hostname"] == "salon-tv")
        w.commit_override(tv, "Télé", "console")
        light = next(d for d in w.devices if d["hostname"] == "imprimante")
        light["light"] = True
        rules.add_rule({"name": "tout en nas", "type": "nas", "points": 100, "force": True, "match": {"os": "linux"}})
        w.reclassify_all()
        by = {d["hostname"] or d["ip"]: d for d in w.devices}
        self.assertEqual(by["Télé"]["type"], "console")                              # le type choisi à la main résiste à la règle
        self.assertEqual(by["imprimante"]["type"], "printer")                        # donnée de présence : non reclassée
        self.assertEqual(by["debian"]["type"], "desktop")                            # cette machine : jamais
        self.assertEqual(by["box"]["type"], "nas")                                   # appareil analysé : règle appliquée

    def test_rules_dialog_lists_rules_with_device_counts_warnings_and_actions(self):
        self.scan(network())
        w = self.w
        rules.add_rule({"name": "Télé du salon", "type": "tv", "points": 60, "match": {"hostname": "^salon"}})
        with open(rules.PATH, encoding="utf-8") as f:
            import json
            data = json.load(f)
        data["rules"].append({"name": "cassée", "type": "frigo", "match": {"os": "x"}})
        with open(rules.PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
        changed = []
        dlg = gui.RulesDialog(w.devices, lambda: changed.append(1), w)
        self.assertEqual(dlg.table.rowCount(), 1)
        self.assertEqual([dlg.table.item(0, c).text() for c in (0, 1, 3)], ["Télé du salon", "TV / multimédia", "1"])   # 1 appareil concerné
        self.assertFalse(dlg.warn.isHidden())
        self.assertIn("cassée", dlg.warn.text())
        dlg.table.selectRow(0)
        dlg.remove()                                                                  # (la confirmation est neutralisée : « Oui »)
        self.assertEqual(dlg.table.rowCount(), 0)
        self.assertEqual(changed, [1])
        self.assertTrue(dlg.example_btn.isEnabled() is False)                         # le fichier existe encore : pas d'exemple à créer

    def test_example_creation_in_the_rules_dialog(self):
        w = self.w
        dlg = gui.RulesDialog([], lambda: None, w)
        self.assertTrue(dlg.example_btn.isEnabled())                                  # pas de fichier : proposé
        dlg.example()
        self.assertEqual(dlg.table.rowCount(), 2)
        self.assertFalse(dlg.example_btn.isEnabled())

    def test_a_broken_rules_file_is_reported_at_startup_without_breaking_anything(self):
        self.w.close()
        with open(rules.PATH, "w") as f:
            f.write("{pas du json")
        rules._cache.update(path=None, mtime=None)
        self.w = gui.Main(); self.w.notify = lambda *a: None
        self.assertIn("Règles de détection", self.w.status.text())
        self.assertEqual(rules.evaluate({"hostname": "x", "ports": []}), [])

    def test_detection_menu_exists(self):
        self.assertIn("Détection", [a.text() for a in self.w.menuBar().actions()])

    def test_scan_button_toggles_between_start_and_stop(self):
        w = self.w
        w.scanner.state["status"] = "scanning"                                    # scan en cours simulé
        called = []
        w.scanner.stop = lambda: called.append(1) or True
        w.on_scan_button()
        self.assertEqual(called, [1])
        self.assertFalse(w.btn.isEnabled())                                      # « arrêt en cours » : on évite le double clic


if __name__ == "__main__":
    unittest.main()
