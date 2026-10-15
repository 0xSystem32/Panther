"""Point d'entrée historique de l'interface graphique : tout vit dans `panther/ui/` (un module par rôle).

Ce module ne fait que réexporter les noms publics pour `python -m panther` et pour les scripts (`gui.Main`, `gui.main`…).
Pour *modifier* un comportement (ou le remplacer dans un test), il faut agir sur le module d'origine : par exemple
`panther.ui.theme.system_theme` ou `panther.ui.dialogs.log_path` ; une valeur recopiée ici ne se met pas à jour.
"""
from PyQt6.QtGui import QImage
from PyQt6.QtWidgets import QDialogButtonBox, QFormLayout, QGraphicsItem, QMessageBox

from .ui.app import main, start_demo
from .ui.dialogs import (CompareDialog, DataDialog, DuplicatesDialog, EditDialog, MergeDialog, MetaDialog, RuleFromDeviceDialog,
                         RulesDialog, log_path)
from .ui.icons import draw_icon, type_pixmap
from .ui.mapview import ElbowLink, Hub, Link, MapView, Node, Zone
from .ui.settings_dialogs import AlertsDialog, NetworksDialog, ReportScheduleDialog
from .ui.theme import (T, THEME_MODES, THEMES, TEXT_SIZES, TYPE_COLORS, make_style, resolve_theme, set_text_scale, system_theme,
                       type_color)
from .ui.util import KEY_ROLE, LABELS, dkey, human_size, ip_key, snmp_secret, when
from .ui.widgets import ElidedLabel, PresenceBar, RefreshCombo, SortItem
from .ui.window import Main
from .ui.wizard import WelcomeWizard, apply_welcome_settings, first_run_needed

__all__ = [n for n in dir() if not n.startswith("_")]

if __name__ == "__main__":
    main()
