"""Traduction de l'interface (français / anglais) sans dépendance.

* Le **français est la langue source** : `tr("texte français")` renvoie ce texte tel quel en français, et sa traduction
  (`lang_en.EN`) en anglais. Un texte sans traduction reste en français plutôt que de planter.
* Les textes avec valeurs s'écrivent `tr("{n} appareils", n=3)` (jamais d'f-string : la traduction doit pouvoir réordonner les mots).
* Les textes définis une fois pour toutes (tables, constantes) se marquent avec `N_("texte")` puis se traduisent à l'affichage.
* La langue se choisit dans le menu Affichage (prise en compte au redémarrage), sinon d'après `LANG` / `LC_MESSAGES`.
"""
import os

LANGUAGES = {"fr": "Français", "en": "English"}
_lang = "fr"
_table = {}


def detect(env=None):
    """Langue du système : « fr » pour une locale française, « en » pour toute autre (et quand rien n'est défini)."""
    env = os.environ if env is None else env
    for var in ("LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        v = (env.get(var) or "").strip().lower()
        if v and v not in ("c", "posix"):
            return "fr" if v.startswith("fr") else "en"  # toute autre langue : l'anglais, valeur de repli usuelle
    return "en"


def set_language(code):
    """Active « fr » ou « en » (valeur inconnue : français). -> la langue activée."""
    global _lang, _table
    _lang = code if code in LANGUAGES else "fr"
    if _lang == "en":
        from .lang_en import EN
        _table = EN
    else:
        _table = {}
    return _lang


def language():
    return _lang


def tr(text, /, **values):
    """Texte traduit dans la langue active ; `values` remplace les {champs}."""
    out = _table.get(text, text)
    return out.format(**values) if values else out


def N_(text):
    """Marque un texte à traduire plus tard (constantes) : renvoie le texte inchangé."""
    return text


def plural(n, one, other):
    """« 1 appareil » / « 3 appareils » : `one` et `other` sont des textes français (traduits ici). Français : 0 et 1 au singulier."""
    singular = (n == 1) if _lang == "en" else (n < 2)
    return f"{n} {tr(one if singular else other)}"


def when_format():
    """(date et heure, date seule) selon la langue."""
    return ("%Y-%m-%d %H:%M", "%Y-%m-%d") if _lang == "en" else ("%d/%m/%Y %H:%M", "%d/%m/%Y")


class TrDict(dict):
    """Table de libellés (constante) dont les valeurs, marquées avec `N_`, sont traduites à la lecture."""

    def __getitem__(self, key):
        return tr(super().__getitem__(key))

    def get(self, key, default=None):
        return tr(super().get(key, default)) if key in self else default

    def values(self):
        return [tr(v) for v in super().values()]

    def items(self):
        return [(k, tr(v)) for k, v in super().items()]
