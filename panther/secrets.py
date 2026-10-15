"""Stockage des secrets (URL de webhook, mot de passe SMTP, communauté SNMP) : trousseau du système si possible, sinon fichier privé.

* `secret-tool` (libsecret : GNOME Keyring, KWallet…) quand il est installé et qu'un trousseau répond ;
* sinon `~/.config/Panther/secrets.json`, créé avec les droits 600 (lisible par vous seul), écrit de façon atomique.

Un secret n'est jamais écrit dans les fichiers de configuration, ni dans le journal d'erreurs.
"""
import json
import logging
import os
import shutil
import subprocess
import tempfile

from .i18n import tr

log = logging.getLogger("panther.secrets")
PATH = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "Panther", "secrets.json")
SERVICE = "panther"
RUN = subprocess.run  # remplaçable dans les tests


def _tool():
    return shutil.which("secret-tool")


def _tool_run(args, value=None):
    """Exécute secret-tool. -> (ok, sortie). Le secret passe par l'entrée standard, jamais par la ligne de commande."""
    try:
        r = RUN([_tool(), *args], input=value, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False, ""
    return r.returncode == 0, r.stdout


# ------------------------------------------------------------------ fichier privé (repli)
def _read_file():
    try:
        with open(PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_file(data):
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(PATH), suffix=".tmp")  # mkstemp : droits 600 dès la création
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, PATH)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# ------------------------------------------------------------------ API
def backend():
    """« trousseau » si secret-tool est disponible, sinon « fichier privé »."""
    return tr("trousseau du système") if _tool() else tr("fichier privé (droits 600)")


def set(name, value):
    """Enregistre un secret (une valeur vide le supprime). -> nom du stockage utilisé."""
    if not value:
        delete(name)
        return backend()
    if _tool():
        ok, _ = _tool_run(["store", f"--label=Panther : {name}", "service", SERVICE, "account", name], value)
        if ok:
            data = _read_file()
            if name in data:  # n'en garder aucune copie en clair
                del data[name]
                _write_file(data)
            return tr("trousseau du système")
        log.warning("Trousseau indisponible pour %s : repli sur le fichier privé", name)
    data = _read_file()
    data[name] = value
    _write_file(data)
    return tr("fichier privé (droits 600)")


def get(name):
    if _tool():
        ok, out = _tool_run(["lookup", "service", SERVICE, "account", name])
        if ok and out:
            return out.rstrip("\n")
    return _read_file().get(name) or None


def delete(name):
    if _tool():
        _tool_run(["clear", "service", SERVICE, "account", name])
    data = _read_file()
    if name in data:
        del data[name]
        _write_file(data)
