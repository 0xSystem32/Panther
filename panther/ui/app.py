"""Démarrage de l'application graphique."""
import os
import sys

from PyQt6.QtCore import QSettings, QTimer
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

from .. import fingerprint, i18n
from ..i18n import tr
from .theme import T, THEMES, THEME_MODES, make_style, resolve_theme, set_text_scale, text_scale_of
from .window import Main
from .wizard import WelcomeWizard, apply_welcome_settings, first_run_needed

PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # panther/ (et non panther/ui/)
ICON = os.path.join(PACKAGE_DIR, "assets", "panther.svg")


def start_demo(w):
    """Charge le réseau fictif : trois scans passés dans l'historique temporaire, puis le dernier affiché."""
    from .. import demo
    demo.seed_history()
    w.notify = lambda *a: None
    w.network, w.networks_info, w.scan_extra = dict(demo.NETWORK), demo.NETS, demo.extra()
    w.targets = [demo.VLAN]
    w.update_netlabel()
    w.last_scan_auto = False
    w.finish_scan({"devices": demo.online_devices(sec=w.security_on), "networks": demo.NETS, "depth": "normal"}, 0)
    w.status.setText(tr("Démonstration : réseau fictif, rien n'est scanné ni envoyé. Lancez le scan pour voir la "
                        "progression, essayez les cartes, le journal et la comparaison."))


def main(demo=False, lang=None):
    fingerprint.load_all_oui(PACKAGE_DIR)
    app = QApplication(sys.argv)
    settings = QSettings("Panther", "Panther")
    # langue : --lang, sinon le choix enregistré (menu Affichage), sinon celle du système
    saved = settings.value("language", "")
    i18n.set_language(lang or (saved if saved in i18n.LANGUAGES else i18n.detect()))
    app.setStyle("Fusion")
    app.setApplicationName("Panther")
    app.setDesktopFileName("panther")
    app.setWindowIcon(QIcon(ICON))

    def look():
        """Apparence enregistrée, appliquée avant d'afficher quoi que ce soit : thème (auto = système) et taille du texte."""
        mode, size = str(settings.value("theme", "auto")), str(settings.value("text_size", "normal"))
        set_text_scale(text_scale_of(size))
        T.update(THEMES[resolve_theme(mode if mode in THEME_MODES else "auto")])
        app.setStyleSheet(make_style())
    look()
    if not demo and first_run_needed(settings):
        wiz = WelcomeWizard(settings)
        if wiz.exec():
            apply_welcome_settings(settings, wiz.values())
        else:
            settings.setValue("welcome_done", True)  # « Passer » : valeurs par défaut, et on ne redemande pas
            settings.setValue("language", i18n.language())
        look()
    if demo:
        from .. import demo as demo_mod
        w = Main(scanner=demo_mod.DemoScanner(), demo=True)
        start_demo(w)
        import signal
        signal.signal(signal.SIGTERM, lambda *a: app.quit())  # le dossier temporaire est supprimé même si on arrête le processus
        wake = QTimer(); wake.timeout.connect(lambda: None); wake.start(500)  # laisse Python traiter le signal
    else:
        w = Main()
    w.refresh_panel()
    w.show()
    sys.exit(app.exec())
