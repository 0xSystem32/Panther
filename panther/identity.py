"""Doublons probables : un appareil « nouveau » qui ressemble à un appareil hors ligne (MAC « privée » qui a changé).

Module pur. Il ne fait que *suggérer* ; la fusion est toujours confirmée par l'utilisateur.
"""
from . import fingerprint


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
            reasons = [f"même nom « {new.get('hostname')} »", "même type" if t1 == t2 else "type compatible"]
            if fingerprint.is_random_mac(new.get("mac", "")) or fingerprint.is_random_mac(old.get("mac", "")):
                reasons.append("adresse MAC aléatoire (change d'un réseau à l'autre)")
            elif not new.get("new"):
                continue  # ni MAC aléatoire, ni nouvel appareil : rien ne justifie de les rapprocher
            used.add(id(old))
            out.append((new, old, reasons))
            break
    return out
