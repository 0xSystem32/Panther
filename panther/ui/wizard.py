"""Assistant de premier lancement : le choix de la langue, et rien d'autre (les réglages de scan sont dans le menu Scan, l'apparence dans Affichage)."""
from PyQt6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from .. import i18n


class WelcomeWizard(QDialog):
    """Une fenêtre : « Bienvenue · Welcome », deux boutons de langue. Choisir une langue ferme la fenêtre."""

    def __init__(self, settings=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Panther")
        self.setMinimumWidth(420)
        self.settings = settings
        self.lang = i18n.language()
        title = QLabel("Bienvenue  ·  Welcome"); title.setObjectName("title")
        hint = QLabel("Choisissez votre langue  ·  Choose your language"); hint.setObjectName("muted")
        row = QHBoxLayout()
        self.lang_buttons = {}
        for code, label in i18n.LANGUAGES.items():
            b = QPushButton(label); b.setMinimumHeight(48)
            b.clicked.connect(lambda _c, c=code: self.choose_language(c))
            row.addWidget(b); self.lang_buttons[code] = b
        lay = QVBoxLayout(self); lay.setContentsMargins(24, 22, 24, 22); lay.setSpacing(14)
        lay.addWidget(title); lay.addWidget(hint); lay.addLayout(row)

    def choose_language(self, code):
        self.lang = i18n.set_language(code)
        self.accept()

    def values(self):
        return {"language": self.lang}


def first_run_needed(settings):
    return str(settings.value("welcome_done", False)).lower() not in ("true", "1")


def apply_welcome_settings(settings, v):
    settings.setValue("language", v["language"] if v["language"] in i18n.LANGUAGES else "fr")
    settings.setValue("welcome_done", True)
