# Contribuer à Panther

Merci de votre intérêt. Panther est un projet personnel : les corrections et idées sont bienvenues, dans le cadre décrit dans
[README.md](README.md) (réseaux dont on a la responsabilité, lecture seule, aucun mot de passe essayé).

## Mettre en place

    ./run.sh --demo                      # crée .venv, installe PyQt6, ouvre la fenêtre sur un réseau fictif
    .venv/bin/pip install ruff mypy coverage pre-commit
    pre-commit install                   # ruff + traductions à chaque commit, tests avant un push

## Avant de proposer un changement

    python3 -m unittest discover -s tests -t .                                      # moteur : bibliothèque standard seule
    QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests -t .   # + interface, PDF
    ruff check panther tests tools
    mypy
    python3 tools/i18n_check.py

* **Tests** : toute correction ajoute un test qui échoue sans elle. Le moteur (`panther/*.py` hors `ui/`) vise 85 % de couverture ;
  les analyseurs de données du réseau ont des tests « fuzz » (`tests/test_fuzz.py`).
* **Textes** : le français est la langue source. Tout texte affiché passe par `tr("…")` (ou `N_("…")` pour une constante) et reçoit
  sa traduction dans `panther/lang_en.py` ; jamais d'f-string dans `tr()` : `tr("{n} appareils", n=3)`.
* **Entrées non fiables** : noms, bannières, certificats, réponses SNMP/mDNS viennent du réseau. Bornez-les, n'évaluez rien, et
  affichez-les en texte brut (voir [SECURITY.md](SECURITY.md)).
* **Moteur sans dépendance** : `panther/*.py` hors `ui/` n'importe que la bibliothèque standard.
* **Interface** : un module par rôle dans `panther/ui/` ; la fenêtre principale est un assemblage de mixins (`window.py`).
* **Style** : lignes jusqu'à 160 caractères, commentaires en français, dans le ton du code voisin.

## Captures

`QT_QPA_PLATFORM=offscreen .venv/bin/python tools/make_screenshots.py [fr|en]` régénère les captures à partir du réseau fictif :
n'ajoutez jamais de capture d'un vrai réseau.
