"""Réglages persistants : nom et type choisis à la main, par appareil (clé = adresse MAC)."""
import json
import os
import tempfile
import threading

from . import fingerprint

PATH = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                    "Panther", "devices.json")
_lock = threading.Lock()


def key_for(dev):
    return dev["mac"].lower() if dev.get("mac") else "ip:" + dev["ip"]


def identity(dev):
    """Identité à utiliser pour un appareil déjà rattaché à l'historique : sa clé résolue (MAC canonique), sinon la brute."""
    return dev.get("key") or key_for(dev)


def load():
    try:
        with open(PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data):
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(PATH), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, PATH)  # écriture atomique : jamais de fichier à moitié écrit


def move_override(src, dst, keep_src=False):
    """Reporte le réglage manuel de `src` sur `dst` (sans écraser un réglage existant). `keep_src` : copie au lieu de déplacer."""
    with _lock:
        data = load()
        if src in data:
            if dst not in data:
                data[dst] = dict(data[src])
            if not keep_src:
                del data[src]
            _save(data)


def set_override(dev, name=None, kind=None):
    """Mémorise nom/type pour cet appareil. Valeurs vides = retour à la détection automatique."""
    name = (name or "").strip()[:60]
    kind = kind if kind in fingerprint.KINDS else None
    with _lock:
        data = load()
        if name or kind:
            entry = {}
            if name:
                entry["name"] = name
            if kind:
                entry["type"] = kind
            data[identity(dev)] = entry
        else:
            data.pop(identity(dev), None)
        _save(data)
        return data


def apply(dev, overrides=None, aliases=None):
    """Applique les réglages à un appareil (idempotent) en gardant les valeurs automatiques."""
    overrides = load() if overrides is None else overrides
    if "auto_type" in dev:
        dev["type"], dev["confidence"], dev["reasons"] = dev.pop("auto_type"), dev.pop("auto_conf"), dev.pop("auto_reasons")
    if "auto_hostname" in dev:
        dev["hostname"] = dev.pop("auto_hostname")
    dev["custom"] = False
    raw = key_for(dev)
    entry = overrides.get(identity(dev)) or overrides.get((aliases or {}).get(raw, raw)) or overrides.get(raw)
    if not isinstance(entry, dict):
        return dev
    if entry.get("name"):
        dev["auto_hostname"], dev["hostname"], dev["custom"] = dev["hostname"], str(entry["name"])[:60], True
    if entry.get("type") in fingerprint.KINDS:
        dev["auto_type"], dev["auto_conf"], dev["auto_reasons"] = dev["type"], dev.get("confidence", 0), dev.get("reasons", [])
        dev["type"], dev["confidence"], dev["reasons"], dev["custom"] = entry["type"], 100, ["défini manuellement"], True
    return dev
