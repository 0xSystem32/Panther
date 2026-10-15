"""Assistant de premier lancement."""
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QCheckBox, QComboBox, QDialog, QFormLayout, QHBoxLayout, QLabel, QPushButton, QStackedWidget, QVBoxLayout, QWidget

from .. import i18n
from ..i18n import tr
from .theme import TEXT_SIZES, THEME_MODES
from .util import SECURITY_INFO


class WelcomeWizard(QDialog):
    """Assistant de premier lancement : langue, usage responsable, apparence, façon de scanner. Rien n'est lancé : il ne fait que
    régler les options (modifiables ensuite dans les menus). Aide → « Assistant de premier lancement… » le rouvre."""

    AUTO_CHOICES = (0, 15, 30, 60)

    def __init__(self, settings=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Panther")
        self.setMinimumSize(560, 430)
        self.settings = settings
        self.lang = i18n.language()
        self.stack = QStackedWidget()
        self.back_btn, self.next_btn, self.skip_btn = QPushButton(), QPushButton(), QPushButton()
        self.back_btn.clicked.connect(lambda: self.go(self.stack.currentIndex() - 1))
        self.next_btn.clicked.connect(self.on_next)
        self.skip_btn.clicked.connect(self.reject)
        row = QHBoxLayout(); row.addWidget(self.skip_btn); row.addStretch(1); row.addWidget(self.back_btn); row.addWidget(self.next_btn)
        lay = QVBoxLayout(self); lay.setContentsMargins(24, 22, 24, 18); lay.setSpacing(14)
        self.step = QLabel(); self.step.setObjectName("muted")
        lay.addWidget(self.step); lay.addWidget(self.stack, 1); lay.addLayout(row)
        self.build_language_page()
        self.build_pages()
        self.go(0)

    # ---- pages
    def page(self, title, *widgets):
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(0, 0, 0, 0); l.setSpacing(12)
        t = QLabel(title); t.setObjectName("title"); t.setWordWrap(True); l.addWidget(t)
        for x in widgets:
            l.addWidget(x) if isinstance(x, QWidget) else l.addLayout(x)
        l.addStretch(1)
        return w

    @staticmethod
    def check(text):
        """Case à cocher dont le texte passe à la ligne (QCheckBox ne le fait pas) ; cliquer le texte coche la case. -> (case, ligne)."""
        box = QCheckBox()
        lab = QLabel(text); lab.setWordWrap(True); lab.setTextFormat(Qt.TextFormat.PlainText)
        lab.mousePressEvent = lambda _e: box.toggle()
        row = QWidget(); l = QHBoxLayout(row); l.setContentsMargins(0, 0, 0, 0); l.setSpacing(8)
        l.addWidget(box, 0, Qt.AlignmentFlag.AlignTop); l.addWidget(lab, 1)
        box.setAccessibleName(text)  # lecteur d'écran : le texte est porté par la case
        return box, row

    @staticmethod
    def note(text, muted=True):
        lab = QLabel(text); lab.setWordWrap(True); lab.setTextFormat(Qt.TextFormat.PlainText)
        if muted:
            lab.setObjectName("muted")
        return lab

    def build_language_page(self):
        """Première page : bilingue, car la langue n'est pas encore choisie."""
        self.lang_buttons = {}
        row = QHBoxLayout()
        for code, label in i18n.LANGUAGES.items():
            b = QPushButton(label); b.setCheckable(True); b.setMinimumHeight(44)
            b.clicked.connect(lambda _c, c=code: self.choose_language(c))
            row.addWidget(b); self.lang_buttons[code] = b
        self.lang_buttons[self.lang].setChecked(True)
        self.stack.addWidget(self.page("Bienvenue  ·  Welcome", self.note("Choisissez votre langue  ·  Choose your language", muted=False), row))

    def choose_language(self, code):
        """Change la langue du reste de l'assistant tout de suite (les pages suivantes sont reconstruites)."""
        self.lang = i18n.set_language(code)
        for c, b in self.lang_buttons.items():
            b.setChecked(c == self.lang)
        while self.stack.count() > 1:
            w = self.stack.widget(1); self.stack.removeWidget(w); w.deleteLater()
        self.build_pages()
        self.go(0)

    def build_pages(self):
        self.agree, agree_row = self.check(tr("Je n'utiliserai Panther que sur des réseaux dont j'ai la responsabilité ou l'autorisation."))
        self.agree.stateChanged.connect(lambda _s: self.go(self.stack.currentIndex()))
        self.stack.addWidget(self.page(tr("Un outil à utiliser avec discernement"), self.note(tr(
            "Panther envoie des paquets aux appareils d'un réseau pour les reconnaître. Scanner un réseau qui n'est pas le vôtre peut être "
            "illégal. Il refuse les plages publiques et n'essaie jamais de mot de passe."), muted=False), agree_row))
        self.theme = QComboBox()
        for mode, label in (("auto", tr("Automatique (suit le système)")), ("dark", tr("Sombre")), ("light", tr("Clair")), ("contrast", tr("Contraste élevé"))):
            self.theme.addItem(label, mode)
        self.size = QComboBox()
        for key, label, _scale in TEXT_SIZES:
            self.size.addItem(tr(label), key)
        self.size.setCurrentIndex(1)
        form = QFormLayout(); form.addRow(tr("Thème"), self.theme); form.addRow(tr("Taille du texte"), self.size)
        self.stack.addWidget(self.page(tr("Apparence"), form, self.note(tr("Le thème et la taille du texte se changent à tout moment dans le menu Affichage."))))
        self.depth = QComboBox()
        for key, label in (("presence", tr("Présence")), ("rapide", tr("Rapide")), ("normal", tr("Normal")), ("approfondi", tr("Approfondi"))):
            self.depth.addItem(label, key)
        self.depth.setCurrentIndex(2)
        self.auto = QComboBox()
        for minutes, label in ((0, tr("Désactivé")), (15, tr("Toutes les 15 minutes")), (30, tr("Toutes les 30 minutes")), (60, tr("Toutes les heures"))):
            self.auto.addItem(label, minutes)
        self.passive, passive_row = self.check(tr("Écoute seule : ne rien envoyer sur le réseau"))
        self.security, security_row = self.check(tr("Analyse de sécurité en lecture seule (ports ouverts, services sans mot de passe)"))
        form2 = QFormLayout(); form2.addRow(tr("Profondeur"), self.depth); form2.addRow(tr("Scan automatique"), self.auto)
        self.stack.addWidget(self.page(tr("Façon de scanner"), form2, passive_row, security_row,
                                       self.note(tr(SECURITY_INFO)), self.note(tr("Rien n'est lancé tant que vous n'appuyez pas sur « Lancer le scan »."))))

    # ---- navigation
    def on_next(self):
        if self.stack.currentIndex() == self.stack.count() - 1:
            self.accept()
        else:
            self.go(self.stack.currentIndex() + 1)

    def go(self, i):
        i = max(0, min(i, self.stack.count() - 1))
        self.stack.setCurrentIndex(i)
        last = i == self.stack.count() - 1
        self.step.setText(tr("Étape {i} sur {n}", i=i + 1, n=self.stack.count()))
        self.back_btn.setText(tr("Précédent")); self.back_btn.setEnabled(i > 0)
        self.next_btn.setText(tr("Terminer") if last else tr("Suivant")); self.next_btn.setObjectName("primary")
        self.skip_btn.setText(tr("Passer"))
        self.next_btn.setEnabled(not (i == 1 and not self.agree.isChecked()))   # la page « usage responsable » demande une case cochée
        self.next_btn.style().unpolish(self.next_btn); self.next_btn.style().polish(self.next_btn)

    def values(self):
        return {"language": self.lang, "theme": self.theme.currentData(), "text_size": self.size.currentData(), "depth": self.depth.currentData(),
                "auto_minutes": self.auto.currentData(), "passive": self.passive.isChecked(), "security": self.security.isChecked()}


def first_run_needed(settings):
    return str(settings.value("welcome_done", False)).lower() not in ("true", "1")


def apply_welcome_settings(settings, v):
    """Enregistre les choix de l'assistant (jamais de secret ni de réseau) ; cocher l'analyse de sécurité vaut consentement, puisque
    son fonctionnement est expliqué sur la page."""
    settings.setValue("language", v["language"] if v["language"] in i18n.LANGUAGES else "fr")
    settings.setValue("theme", v["theme"] if v["theme"] in THEME_MODES else "auto")
    settings.setValue("text_size", v["text_size"] if v["text_size"] in {k for k, _l, _s in TEXT_SIZES} else "normal")
    settings.setValue("depth", v["depth"] if v["depth"] in ("presence", "rapide", "normal", "approfondi") else "normal")
    settings.setValue("auto_minutes", v["auto_minutes"] if v["auto_minutes"] in WelcomeWizard.AUTO_CHOICES else 0)
    settings.setValue("passive", bool(v["passive"]))
    settings.setValue("security", bool(v["security"]) and not v["passive"])  # l'écoute seule n'envoie rien : pas d'analyse active
    if v["security"] and not v["passive"]:
        settings.setValue("security_consent", True)
    settings.setValue("welcome_done", True)
