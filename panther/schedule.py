"""Planification des rapports : quand en produire un, comment le nommer, quels anciens supprimer. Module pur (aucun accès à Qt).

Sécurité du nettoyage : seuls les fichiers que Panther a lui-même nommés (`rapport-panther-AAAA-MM-JJ_HHMM.pdf`) peuvent être supprimés,
jamais un dossier, jamais un lien symbolique, jamais autre chose qui se trouverait dans le même dossier.
"""
import os
import re
import time
from .i18n import N_, TrDict, tr

PERIODS = {"daily": 24 * 3600, "weekly": 7 * 24 * 3600}
LABELS = TrDict({"daily": N_("Tous les jours"), "weekly": N_("Toutes les semaines")})
_NAME = re.compile(r"^rapport-panther-\d{4}-\d{2}-\d{2}_\d{4}\.pdf$")
MAX_KEEP = 365


def is_due(last, now, freq):
    """Vrai si un rapport doit être produit. `last` : date du dernier (None = jamais). Une date dans un futur lointain (horloge changée)
    ne bloque pas la planification."""
    period = PERIODS.get(freq)
    if period is None:
        return False
    if not last:
        return True
    if last > now + 24 * 3600:
        return True
    return now - last >= period


def filename(now):
    return time.strftime("rapport-panther-%Y-%m-%d_%H%M.pdf", time.localtime(now))


def reports_in(folder):
    """Rapports de Panther présents dans le dossier, du plus ancien au plus récent (le nom porte la date)."""
    try:
        names = os.listdir(folder)
    except OSError:
        return []
    out = []
    for n in names:
        p = os.path.join(folder, n)
        if _NAME.match(n) and os.path.isfile(p) and not os.path.islink(p):
            out.append(p)
    return sorted(out)


def prune(folder, keep):
    """Supprime les rapports les plus anciens pour n'en garder que `keep` (au moins 1). -> chemins supprimés."""
    keep = max(1, min(int(keep), MAX_KEEP))
    old = reports_in(folder)[:-keep]
    removed = []
    for p in old:
        try:
            os.remove(p)
            removed.append(p)
        except OSError:
            continue
    return removed


def ensure_folder(folder):
    """Dossier de destination utilisable (créé si besoin). Lève OSError sinon. Chemin absolu obligatoire."""
    if not folder or not os.path.isabs(folder):
        raise OSError(tr("choisissez un dossier (chemin absolu)"))
    os.makedirs(folder, exist_ok=True)
    if not os.access(folder, os.W_OK):
        raise OSError(tr("dossier non inscriptible : {folder}", folder=folder))
    return folder
