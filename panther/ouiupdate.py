"""Mise à jour de la base des fabricants (registre IEEE) vers `~/.config/Panther/oui.txt`.

Le fichier de l'utilisateur est chargé après celui livré avec Panther et le complète ; il est écrit de façon atomique (jamais
de fichier à moitié écrit) et seulement si le téléchargement contient assez d'entrées pour être crédible.
"""
import csv
import io
import os
import tempfile
import urllib.request

from . import fingerprint
from .i18n import tr

URL = "https://standards-oui.ieee.org/oui/oui.csv"
USER_PATH = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "Panther", "oui.txt")
MAX_BYTES = 30 * 1024 * 1024
MIN_ENTRIES = 1000


class UpdateError(Exception):
    pass


def parse_csv(text):
    """CSV du registre IEEE -> {préfixe MAC 6 hex: nom court}. Les lignes invalides sont ignorées."""
    rows = {}
    for rec in csv.DictReader(io.StringIO(text)):
        prefix, org = (rec.get("Assignment") or "").strip().upper(), (rec.get("Organization Name") or "").strip()
        if len(prefix) == 6 and all(c in "0123456789ABCDEF" for c in prefix) and org:
            rows[prefix] = fingerprint.canonical_vendor(org.replace(";", ","))
    return rows


def write(rows, dest=None):
    dest = dest or USER_PATH
    if len(rows) < MIN_ENTRIES:
        raise UpdateError(tr("seulement {rows_count} entrées (au moins {min_entries} attendues) : fichier invalide, base inchangée", rows_count=len(rows), min_entries=MIN_ENTRIES))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dest), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for k in sorted(rows):
                f.write(f"{k};{rows[k]}\n")
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def update(url=URL, dest=None, timeout=60):
    """Télécharge, convertit et enregistre. -> nombre de fabricants. Lève UpdateError avec un message clair."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Panther-oui-updater"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(MAX_BYTES + 1)
    except (OSError, ValueError) as e:
        raise UpdateError(tr("téléchargement impossible : {e}", e=e)) from None
    if len(data) > MAX_BYTES:
        raise UpdateError(tr("fichier anormalement gros, abandon"))
    rows = parse_csv(data.decode("utf-8-sig", "ignore"))
    write(rows, dest)
    fingerprint.load_extra_oui(dest or USER_PATH)  # pris en compte immédiatement, sans redémarrer
    return len(rows)
