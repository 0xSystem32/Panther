"""Journal d'erreurs : fichier rotatif `~/.config/Panther/panther.log` (256 Ko × 3).

Il garde les erreurs et avertissements utiles au diagnostic (analyse d'un appareil ratée, SNMP injoignable,
multicast bloqué, base illisible…) ainsi que les exceptions non gérées, y compris dans les threads du scanner.
Il contient des adresses IP/MAC et des noms d'appareils de votre réseau, jamais de mot de passe ni de communauté SNMP.
"""
import logging
import logging.handlers
import os
import sys
import threading

from . import privacy

PATH = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "Panther", "panther.log")
_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_OURS = "_panther_handler"


def get(name):
    return logging.getLogger("panther." + name)


def setup(verbose=False, path=None, console=False):
    """Configure le journal (idempotent). `verbose` : niveau DEBUG et affichage sur la console. -> logger « panther »."""
    root = logging.getLogger("panther")
    for h in [h for h in root.handlers if getattr(h, _OURS, False)]:  # pas de doublons si on reconfigure
        root.removeHandler(h)
        h.close()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.propagate = False
    fmt = logging.Formatter(_FORMAT)
    handlers: list[logging.Handler] = []
    try:
        target = path or PATH
        os.makedirs(os.path.dirname(target), exist_ok=True)
        handlers.append(logging.handlers.RotatingFileHandler(target, maxBytes=256_000, backupCount=2, encoding="utf-8"))
        privacy.harden(target)  # adresses et noms d'appareils : lisible par vous seul
    except OSError:  # dossier non inscriptible : le journal ne doit jamais empêcher de lancer l'application
        console = True
    if console or verbose:
        handlers.append(logging.StreamHandler(sys.stderr))
    for h in handlers:
        h.setFormatter(fmt)
        setattr(h, _OURS, True)
        root.addHandler(h)
    _install_hooks(root)
    return root


def _install_hooks(logger):
    def hook(exc_type, exc, tb):
        if not issubclass(exc_type, KeyboardInterrupt):
            logger.critical("Exception non gérée", exc_info=(exc_type, exc, tb))
        sys.__excepthook__(exc_type, exc, tb)

    def thread_hook(args):
        logger.error("Exception non gérée dans le thread %s", getattr(args.thread, "name", "?"),
                     exc_info=(args.exc_type, args.exc_value, args.exc_traceback))
    sys.excepthook = hook
    threading.excepthook = thread_hook
