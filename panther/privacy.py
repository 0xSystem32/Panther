"""Vie privée des données locales : droits restrictifs et effacement.

Les fichiers de `~/.config/Panther/` décrivent votre réseau (adresses MAC, noms d'appareils, habitudes de présence) :
ils ne doivent être lisibles que par vous. Rien n'est chiffré (la bibliothèque standard n'offre pas de chiffrement
sérieux) : la protection repose sur les droits du système de fichiers ; pour un disque exposé, chiffrez le disque
ou le dossier personnel.
"""
import logging
import os

log = logging.getLogger("panther.privacy")
PRIVATE_FILE, PRIVATE_DIR = 0o600, 0o700


def harden(path):
    """Fichier lisible par vous seul et dossier parent fermé aux autres. Sans effet (et sans erreur) si le système refuse."""
    try:
        if os.path.isdir(os.path.dirname(path)):
            os.chmod(os.path.dirname(path), PRIVATE_DIR)
        for p in (path, path + "-wal", path + "-shm", path + "-journal"):
            if os.path.isfile(p) and not os.path.islink(p):
                os.chmod(p, PRIVATE_FILE)
    except OSError:
        log.debug("Droits de %s inchangés", path, exc_info=True)


def mode_of(path):
    """Droits (octal) d'un fichier, ou None s'il n'existe pas."""
    try:
        return os.stat(path).st_mode & 0o777
    except OSError:
        return None


def erase_file(path, backups=0):
    """Vide un fichier (et supprime ses copies .1, .2… de rotation). -> nombre d'octets effacés. Les liens symboliques sont ignorés."""
    freed = 0
    for p in [path] + [f"{path}.{i}" for i in range(1, backups + 1)]:
        try:
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            freed += os.path.getsize(p)
            if p == path:
                with open(p, "w"):  # tronqué en place : un journal ouvert continue d'écrire au bon endroit
                    pass
            else:
                os.unlink(p)
        except OSError:
            log.warning("Effacement de %s impossible", p, exc_info=True)
    return freed
