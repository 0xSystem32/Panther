"""Fenêtre principale : assemble les mixins et construit le menu et la barre d'outils."""
import json

from PyQt6.QtCore import QSettings, Qt, QTimer
from PyQt6.QtGui import QAction, QActionGroup, QGuiApplication
from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QFrame,
    QGraphicsScene,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from .. import history, i18n, networks, rules
from ..i18n import plural, tr
from ..scanner import Scanner
from .devices import DevicesMixin
from .mapctl import MapMixin
from .mapview import MapView
from .panel import PanelMixin
from .prefs import PrefsMixin
from .reports import ReportsMixin
from .scan import ScanMixin
from .settings_dialogs import AlertsDialog
from .tables import TablesMixin
from .theme import TEXT_SIZES, THEME_MODES
from .util import SECURITY_INFO
from .widgets import ElidedLabel, RefreshCombo


class Main(QMainWindow, ScanMixin, MapMixin, TablesMixin, PanelMixin, DevicesMixin, ReportsMixin, PrefsMixin):
    """Fenêtre principale : carte, appareils, journal, sécurité ; le détail des méthodes est réparti dans les mixins."""

    def __init__(self, scanner=None, demo=False):
        super().__init__()
        self.demo = demo  # réseau fictif : rien n'est envoyé, rien n'est écrit hors du dossier temporaire
        self.setWindowTitle(tr("Panther — démonstration") if demo else tr("Panther"))
        self.resize(1320, 820)
        self.scanner = scanner or Scanner()
        self.settings = QSettings("Panther", "Panther")
        self.devices, self.nodes, self.selected, self.network = [], {}, None, None
        self.selected_keys = []  # sélection multiple : clés de tous les appareils sélectionnés sur la carte
        self.networks_info, self.scan_extra = [], {}
        self.snmp = self.load_snmp()
        try:
            self.targets = [c for c in json.loads(self.settings.value("targets", "[]")) if networks.validate_cidr(c)]
        except (ValueError, TypeError):
            self.targets = []
        self._building, self.t0 = False, 0
        self.last_new, self.last_scan_auto, self.tray = [], False, None
        self.dup_suggestions = []
        try:  # durée de conservation de l'historique, réglée par l'utilisateur
            history.KEEP_SCANS_DAYS = int(self.settings.value("keep_scans_days", history.KEEP_SCANS_DAYS))
            history.KEEP_EVENTS_DAYS = int(self.settings.value("keep_events_days", history.KEEP_EVENTS_DAYS))
        except (TypeError, ValueError):
            pass
        try:
            self.last_full_scan = float(self.settings.value("last_full_scan", 0))
        except (TypeError, ValueError):
            self.last_full_scan = 0.0
        self.saved_pos = {}
        self.security_on = str(self.settings.value("security", True)).lower() in ("true", "1")
        self.passive_on = str(self.settings.value("passive", False)).lower() in ("true", "1")
        self.security_consent = str(self.settings.value("security_consent", True)).lower() in ("true", "1")
        self.layout_mode = self.settings.value("layout", "etoile") if self.settings.value("layout", "etoile") in ("etoile", "hierarchique", "types") else "etoile"
        self.show_offline = str(self.settings.value("show_offline", True)).lower() in ("true", "1")
        self.animations = str(self.settings.value("animations", True)).lower() in ("true", "1")
        mode = str(self.settings.value("theme", "dark"))
        self.theme_mode = mode if mode in THEME_MODES else "auto"
        size = str(self.settings.value("text_size", "normal"))
        self.text_size = size if size in {k for k, _l, _s in TEXT_SIZES} else "normal"

        self._build_menu()
        self._build_toolbar()

        self.scene = QGraphicsScene()
        self.scene.setSceneRect(-3000, -3000, 6000, 6000)
        self.scene.selectionChanged.connect(self.on_scene_selection)
        self.view = MapView(self.scene)
        self.view.fit_cb = self.fit

        self.table = QTableWidget(0, 13)
        self.table.setHorizontalHeaderLabels([tr("Appareil"), tr("Adresse IP"), tr("Adresse MAC"), tr("Fabricant"), tr("Type"), tr("Système"), tr("Services"), tr("Réseau"), tr("Statut"), tr("Confiance"), tr("Exposition"), tr("Groupe"), tr("Étiquettes")])
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.setIconSize(self.table.iconSize().expandedTo(self.table.iconSize()))
        self.table.itemSelectionChanged.connect(self.on_table_selection)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(
            lambda pos: self.device_menu(self.table_device(self.table.rowAt(pos.y())), self.table.viewport().mapToGlobal(pos)))
        self.table.cellDoubleClicked.connect(lambda r, c: self.edit_device(self.table_device(r)))

        self.journal = QTableWidget(0, 4)
        self.journal.setHorizontalHeaderLabels([tr("Date"), tr("Appareil"), tr("Événement"), tr("Détail")])
        self.journal.setAlternatingRowColors(True); self.journal.setShowGrid(False)
        self.journal.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.journal.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.journal.verticalHeader().hide(); self.journal.verticalHeader().setDefaultSectionSize(32)
        self.journal.horizontalHeader().setStretchLastSection(True)
        self.journal.cellDoubleClicked.connect(self.journal_open)
        tabs = self.tabs = QTabWidget()
        tabs.addTab(self.view, tr("Carte réseau"))
        tabs.addTab(self.table, tr("Appareils"))
        tabs.addTab(self.journal, tr("Journal"))
        self.sec_label = QLabel(); self.sec_label.setWordWrap(True); self.sec_label.setObjectName("muted")
        self.sec_label.setContentsMargins(16, 12, 16, 8)
        self.sec_table = QTableWidget(0, 5)
        self.sec_table.setHorizontalHeaderLabels([tr("Gravité"), tr("Appareil"), tr("Adresse IP"), tr("Constat"), tr("Recommandation")])
        self.sec_table.setAlternatingRowColors(True); self.sec_table.setShowGrid(False)
        self.sec_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sec_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sec_table.verticalHeader().hide(); self.sec_table.verticalHeader().setDefaultSectionSize(34)
        self.sec_table.horizontalHeader().setStretchLastSection(True)
        self.sec_table.cellDoubleClicked.connect(self.security_open)
        sec_page = QWidget(); sl_ = QVBoxLayout(sec_page); sl_.setContentsMargins(0, 0, 0, 0); sl_.setSpacing(0)
        sl_.addWidget(self.sec_label); sl_.addWidget(self.sec_table)
        tabs.addTab(sec_page, tr("Sécurité"))
        tabs.setDocumentMode(True)
        tabs.currentChanged.connect(lambda i: self.refresh_journal() if i == 2 else self.refresh_security() if i == 3 else None)

        self.side = QFrame(); self.side.setObjectName("side"); self.side.setMinimumWidth(310); self.side.setMaximumWidth(420)
        sl = QVBoxLayout(self.side); sl.setContentsMargins(20, 20, 20, 20); sl.setSpacing(14)
        head = QHBoxLayout(); head.setSpacing(12)
        self.side_icon = QLabel(); self.side_icon.setFixedSize(44, 44)
        ht = QVBoxLayout(); ht.setSpacing(2)
        self.side_title = QLabel(); self.side_title.setObjectName("title"); self.side_title.setTextFormat(Qt.TextFormat.PlainText)
        self.side_sub = QLabel(); self.side_sub.setObjectName("muted"); self.side_sub.setTextFormat(Qt.TextFormat.PlainText)
        ht.addWidget(self.side_title); ht.addWidget(self.side_sub)
        head.addWidget(self.side_icon); head.addLayout(ht, 1)
        sep = QFrame(); sep.setObjectName("sep")
        self.form = QFormLayout(); self.form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.form.setHorizontalSpacing(16); self.form.setVerticalSpacing(10)
        self.form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.edit_btn = QPushButton(tr("Modifier le nom / le type…"))
        self.edit_btn.clicked.connect(lambda: self.edit_device(self.current_device()))
        self.trust_btn = QPushButton()
        self.trust_btn.clicked.connect(self.on_trust_button)
        self.meta_btn = QPushButton(tr("Étiquettes, notes et groupe…"))
        self.meta_btn.clicked.connect(self.on_meta_button)
        body = QWidget(); bl = QVBoxLayout(body); bl.setContentsMargins(0, 0, 4, 0); bl.setSpacing(14)
        bl.addLayout(head); bl.addWidget(sep); bl.addLayout(self.form); bl.addStretch(1)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff); scroll.setWidget(body)
        sl.addWidget(scroll, 1); sl.addWidget(self.edit_btn); sl.addWidget(self.meta_btn); sl.addWidget(self.trust_btn)

        split = QSplitter(); split.addWidget(tabs); split.addWidget(self.side)
        split.setStretchFactor(0, 1); split.setSizes([980, 340]); split.setChildrenCollapsible(False)
        self.setCentralWidget(split)

        self.status = QLabel(tr("Prêt"))
        self.count = QLabel("")
        self.progress = QProgressBar(); self.progress.setFixedWidth(160); self.progress.setTextVisible(False); self.progress.hide()
        self.statusBar().addWidget(self.status, 1)
        self.auto_label = QLabel(""); self.auto_label.setObjectName("muted")
        self.auto_timer = QTimer(self); self.auto_timer.timeout.connect(self.auto_tick)
        self.statusBar().addPermanentWidget(self.auto_label)
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().addPermanentWidget(self.count)
        self.statusBar().setSizeGripEnabled(False)

        self.timer = QTimer(self); self.timer.timeout.connect(self.poll)
        self.report_timer = QTimer(self); self.report_timer.timeout.connect(self.report_tick); self.report_timer.start(60000)
        try:
            QGuiApplication.styleHints().colorSchemeChanged.connect(self.on_system_theme)  # thème « automatique » : suit le système en direct
        except AttributeError:
            pass
        self.update_netlabel()
        w_rules = rules.current().warnings
        if w_rules:
            self.status.setText(tr("Règles de détection : {count} (menu Détection)", count=plural(len(w_rules), 'avertissement', 'avertissements')))
        try:
            minutes = int(self.settings.value("auto_minutes", 0))
        except (TypeError, ValueError):
            minutes = 0
        minutes = minutes if minutes in self.auto_actions else 0
        self.auto_actions[minutes].setChecked(True); self.set_auto(minutes)
        self.refresh_panel()
        self.refresh_security()

    # ---------- construction ----------
    def _build_menu(self):
        mb = self.menuBar()
        m = mb.addMenu(tr("Fichier"))
        for text, fn in ((tr("Exporter le rapport en PDF…"), self.export_pdf), (tr("Exporter la carte (PNG, SVG)…"), self.export_map),
                         (tr("Exporter en JSON…"), lambda: self.export("json")), (tr("Exporter en CSV…"), lambda: self.export("csv"))):
            m.addAction(QAction(text, self, triggered=fn))
        m.addSeparator()
        m.addAction(QAction(tr("Comparer deux scans…"), self, triggered=self.compare_scans))
        m.addAction(QAction(tr("Rapports planifiés…"), self, triggered=self.open_report_schedule))
        m.addAction(QAction(tr("Historique et données…"), self, triggered=self.open_data))
        m.addSeparator()
        quit_ = QAction(tr("Quitter"), self, triggered=self.close); quit_.setShortcut("Ctrl+Q"); m.addAction(quit_)
        m = mb.addMenu(tr("Scan"))
        self.act_scan = QAction(tr("Lancer le scan"), self, triggered=self.on_scan_button); self.act_scan.setShortcut("Ctrl+R")
        self.act_stop = QAction(tr("Arrêter le scan"), self, triggered=self.stop_scan); self.act_stop.setShortcut("Ctrl+.")
        self.act_stop.setEnabled(False)
        m.addAction(self.act_scan); m.addAction(self.act_stop); m.addSeparator()
        self.scan_menu = m
        m.addAction(QAction(tr("Faire confiance à tous les appareils en ligne…"), self, triggered=self.trust_all))
        m.addAction(QAction(tr("Fusionner des doublons…"), self, triggered=self.show_duplicates))
        m.addAction(QAction(tr("Alertes (webhook, e-mail)…"), self, triggered=lambda: AlertsDialog(self).exec()))
        m.addSeparator()
        self.profile_menu = m.addMenu(tr("Profils de scan"))
        self.rebuild_profile_menu()
        auto = m.addMenu(tr("Scan automatique")); group = QActionGroup(self); self.auto_actions = {}
        for minutes, label in ((0, tr("Désactivé")), (5, tr("Toutes les 5 minutes")), (15, tr("Toutes les 15 minutes")),
                               (30, tr("Toutes les 30 minutes")), (60, tr("Toutes les heures"))):
            a = QAction(label, self, checkable=True); group.addAction(a); auto.addAction(a)
            a.triggered.connect(lambda _checked, mm=minutes: self.set_auto(mm)); self.auto_actions[minutes] = a
        m = mb.addMenu(tr("Affichage"))
        fit = QAction(tr("Recentrer la carte"), self, triggered=self.fit); fit.setShortcut("Ctrl+0"); m.addAction(fit)
        center = QAction(tr("Centrer sur la sélection"), self, triggered=self.center_on_selection); center.setShortcut("Ctrl+Shift+0"); m.addAction(center)
        select_all = QAction(tr("Sélectionner tous les appareils"), self, triggered=self.select_all_nodes); select_all.setShortcut("Ctrl+Shift+A")
        m.addAction(select_all)
        anim = QAction(tr("Animer la carte"), self, checkable=True, checked=self.animations, triggered=self.toggle_animations)
        m.addAction(anim)
        mini = QAction(tr("Mini-carte"), self, checkable=True, checked=True, triggered=lambda on: (setattr(self.view, "show_minimap", on), self.view.viewport().update()))
        m.addAction(mini)
        lay = m.addMenu(tr("Disposition")); lgroup = QActionGroup(self); self.layout_actions = {}
        for mode, label in (("etoile", tr("Étoile (autour de cette machine)")), ("hierarchique", tr("Hiérarchique (Internet → box → switch → appareils)")),
                            ("types", tr("Regroupée par type d'appareil"))):
            a = QAction(label, self, checkable=True); lgroup.addAction(a); lay.addAction(a)
            a.triggered.connect(lambda _c, mm=mode: self.set_layout(mm)); self.layout_actions[mode] = a
        self.layout_actions[self.layout_mode].setChecked(True)
        lay.addSeparator()
        lay.addAction(QAction(tr("Réinitialiser les positions de cette disposition"), self, triggered=self.reset_positions))
        leg = QAction(tr("Légende de la carte"), self, checkable=True, checked=True, triggered=lambda on: (setattr(self.view, "show_legend", on), self.view.viewport().update()))
        m.addAction(leg)
        off = QAction(tr("Afficher les appareils hors ligne"), self, checkable=True, checked=self.show_offline, triggered=self.toggle_offline)
        m.addAction(off)
        theme_menu = m.addMenu(tr("Thème")); tgroup = QActionGroup(self); self.theme_actions = {}
        for mode, label in (("auto", tr("Automatique (suit le système)")), ("dark", tr("Sombre")), ("light", tr("Clair")),
                            ("contrast", tr("Contraste élevé"))):
            a = QAction(label, self, checkable=True); tgroup.addAction(a); theme_menu.addAction(a)
            a.triggered.connect(lambda _c, mm=mode: self.set_theme_mode(mm)); self.theme_actions[mode] = a
        self.theme_actions[self.theme_mode].setChecked(True)
        size_menu = m.addMenu(tr("Taille du texte")); sgroup = QActionGroup(self); self.size_actions = {}
        for key, label, _scale in TEXT_SIZES:
            a = QAction(tr(label), self, checkable=True); sgroup.addAction(a); size_menu.addAction(a)
            a.triggered.connect(lambda _c, kk=key: self.set_text_size(kk)); self.size_actions[key] = a
        self.size_actions[self.text_size].setChecked(True)
        lang_menu = m.addMenu(tr("Langue"))
        lang_group = QActionGroup(self)
        for code, label in i18n.LANGUAGES.items():
            act = QAction(label, self, checkable=True, checked=(code == i18n.language()))
            act.triggered.connect(lambda _on, c=code: self.choose_language(c))
            lang_group.addAction(act); lang_menu.addAction(act)
        m = mb.addMenu(tr("Sécurité"))
        self.act_passive = QAction(tr("Écoute seule (aucune sonde active)"), self, checkable=True, checked=self.passive_on)
        self.act_passive.triggered.connect(self.toggle_passive)
        m.addAction(self.act_passive)
        m.addSeparator()
        self.act_security = QAction(tr("Analyse de sécurité (lecture seule)"), self, checkable=True, checked=self.security_on)
        self.act_security.triggered.connect(self.toggle_security)
        m.addAction(self.act_security)
        # réglages du scan aussi dans le menu Scan : profondeur, écoute seule, analyse de sécurité (mêmes actions que le menu Sécurité)
        sm = self.scan_menu
        depth_menu = QMenu(tr("Profondeur"), self); dgroup = QActionGroup(self); self.depth_actions = {}
        for key, label in (("presence", tr("Présence")), ("rapide", tr("Rapide")), ("normal", tr("Normal")), ("approfondi", tr("Approfondi"))):
            a = QAction(label, self, checkable=True); dgroup.addAction(a); depth_menu.addAction(a)
            a.triggered.connect(lambda _c, k=key: self.depth.setCurrentIndex(max(self.depth.findData(k), 0))); self.depth_actions[key] = a
        sm.insertMenu(self.profile_menu.menuAction(), depth_menu)
        sm.insertAction(self.profile_menu.menuAction(), self.act_passive)
        sm.insertAction(self.profile_menu.menuAction(), self.act_security)
        sm.insertSeparator(self.profile_menu.menuAction())
        self.depth_menu = depth_menu
        m.addAction(QAction(tr("Voir le rapport de sécurité"), self, triggered=lambda: self.tabs.setCurrentIndex(3)))
        m.addAction(QAction(tr("Exporter le rapport (Markdown)…"), self, triggered=self.export_security))
        m.addSeparator()
        m.addAction(QAction(tr("Ce que fait l'analyse…"), self, triggered=lambda: QMessageBox.information(self, tr("Analyse de sécurité"), SECURITY_INFO)))
        m = mb.addMenu(tr("Détection"))
        m.addAction(QAction(tr("Règles personnalisées…"), self, triggered=self.open_rules))
        m.addAction(QAction(tr("Créer une règle pour l'appareil sélectionné…"), self, triggered=lambda: self.create_rule(self.current_device())))
        m = mb.addMenu(tr("Aide"))
        m.addAction(QAction(tr("Mettre à jour la base des fabricants…"), self, triggered=self.update_oui))
        m.addAction(QAction(tr("Ouvrir le journal d'erreurs"), self, triggered=self.open_log))
        m.addAction(QAction(tr("À propos de Panther"), self, triggered=lambda: QMessageBox.about(
            self, tr("Panther"), tr("Panther – scanner et cartographie de réseau local.\n\nMoteur de scan maison (TCP, ARP, NetBIOS, "
                                "mDNS), sans dépendance externe.\nÀ n'utiliser que sur des réseaux dont vous avez l'autorisation."))))

    def _build_toolbar(self):
        tb = QToolBar(); tb.setMovable(False); tb.setFloatable(False); self.addToolBar(tb)
        self.btn = QPushButton(tr("Lancer le scan")); self.btn.setObjectName("primary"); self.btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn.clicked.connect(self.on_scan_button); tb.addWidget(self.btn)
        self.net_btn = QPushButton(); self.net_btn.clicked.connect(self.open_networks); tb.addWidget(self.net_btn)
        lab = QLabel(tr("  Profondeur")); lab.setObjectName("muted"); tb.addWidget(lab)
        self.depth = QComboBox()
        for key, label in (("presence", tr("Présence")), ("rapide", tr("Rapide")), ("normal", tr("Normal")), ("approfondi", tr("Approfondi"))):
            self.depth.addItem(label, key)
        self.depth.setToolTip(tr("Présence : qui est là ? (réutilise les détails du dernier scan complet, très discret).\nRapide : "
                                 "ports courants.\nNormal : bon équilibre.\nApprofondi : plus de ports et des délais plus longs.\nLes "
                                 "scans automatiques utilisent la présence, avec un scan complet au plus toutes les heures."))
        self.depth.setCurrentIndex(max(self.depth.findData(self.settings.value("depth", "approfondi")), 0))
        self.depth.currentIndexChanged.connect(lambda _i: (self.settings.setValue("depth", self.depth.currentData()), self.sync_depth_menu()))
        self.depth.setEnabled(not self.passive_on)
        self.sync_depth_menu(); self.depth_menu.setEnabled(not self.passive_on)
        tb.addWidget(self.depth)
        lab2 = QLabel(tr("  Interface")); lab2.setObjectName("muted"); tb.addWidget(lab2)
        self.iface_combo = RefreshCombo()
        self.iface_combo.setToolTip(tr("Réseau à scanner. « Automatique » suit la route par défaut ; choisissez une interface pour scanner "
                                       "un autre réseau (Ethernet, VPN…)."))
        self.iface_combo.about_to_show.connect(self.populate_ifaces)
        self.populate_ifaces()
        self.iface_combo.currentIndexChanged.connect(lambda _i: self.settings.setValue("iface", self.iface_combo.currentData() or ""))
        tb.addWidget(self.iface_combo)
        self.netlabel = ElidedLabel(tr("  Aucun scan effectué")); self.netlabel.setObjectName("muted"); tb.addWidget(self.netlabel)
        self.search = QLineEdit(); self.search.setPlaceholderText(tr("Filtrer : nom, IP, type…  tag:xxx  groupe:xxx"))
        self.search.setClearButtonEnabled(True); self.search.setFixedWidth(220)
        self.search.textChanged.connect(self.apply_filter); tb.addWidget(self.search)

    def closeEvent(self, e):
        self.scanner.stop()
        super().closeEvent(e)
