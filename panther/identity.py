"""Doublons probables : un appareil « nouveau » qui ressemble à un appareil hors ligne (MAC « privée » qui a changé).

Module pur. Il ne fait que *suggérer* ; la fusion est toujours confirmée par l'utilisateur.
"""
import re

from . import fingerprint
from .i18n import tr
from .labels import TYPE_LABELS


def _name(d):
    n = (d.get("auto_hostname") or d.get("hostname") or "").strip().lower()
    return "" if n == d.get("ip", "").lower() else n


def suggest_duplicates(devices):
    """[(appareil en ligne, appareil hors ligne, raisons)] : même réseau, même nom, types compatibles, clés différentes."""
    online = [d for d in devices if d.get("online", True) and not d.get("virtual") and not d.get("is_self")]
    offline = [d for d in devices if not d.get("online", True) and not d.get("virtual")]
    out, used = [], set()
    for new in sorted(online, key=lambda d: not d.get("new")):            # les nouveaux appareils d'abord
        for old in offline:
            if id(old) in used or (new.get("key") and new.get("key") == old.get("key")):
                continue
            if new.get("network") != old.get("network") or not _name(new) or _name(new) != _name(old):
                continue
            t1, t2 = new.get("auto_type", new.get("type")), old.get("auto_type", old.get("type"))
            if t1 != t2 and "unknown" not in (t1, t2):
                continue
            reasons = [tr("même nom « {hostname} »", hostname=new.get('hostname')), tr("même type") if t1 == t2 else tr("type compatible")]
            if fingerprint.is_random_mac(new.get("mac", "")) or fingerprint.is_random_mac(old.get("mac", "")):
                reasons.append(tr("adresse MAC aléatoire (change d'un réseau à l'autre)"))
            elif not new.get("new"):
                continue  # ni MAC aléatoire, ni nouvel appareil : rien ne justifie de les rapprocher
            used.add(id(old))
            out.append((new, old, reasons))
            break
    return out


_GENERIC_NAME = re.compile(r"^(device|android|unknown|localhost|espressif|esp\d*|wlan|dhcp|host|client)?[-_ ]?[0-9a-f]{0,12}$", re.I)


def is_anonymous(d):
    """Appareil dont le nom n'aide pas : choisi par personne, vide, égal à l'adresse IP ou générique (« device-32 », « android-3fa… »)."""
    if d.get("custom") or d.get("virtual") or d.get("is_self"):
        return False
    name = (d.get("hostname") or "").strip()
    return not name or name == d.get("ip") or bool(_GENERIC_NAME.match(name))


def suggest_name(d, taken=()):
    """Nom lisible proposé pour un appareil anonyme : modèle connu, sinon « Type Marque » (« Téléphone Samsung »). Chaîne vide s'il n'y a
    rien d'utile à dire. `taken` : noms déjà pris (on ajoute 2, 3… pour rester unique). Ne fait que *suggérer*."""
    kind = d.get("type") or "unknown"
    label = TYPE_LABELS.get(kind, "") if kind != "unknown" else ""
    vendor = fingerprint.shorten_vendor(d.get("vendor") or "") if d.get("vendor") and not fingerprint.is_random_mac(d.get("mac", "")) else ""
    base = (d.get("model") or "").strip() or " ".join(x for x in (label, vendor) if x)
    if not base:
        return ""
    used = {t.lower() for t in taken}
    name, n = base, 1
    while name.lower() in used:
        n += 1
        name = f"{base} {n}"
    return name[:60]
