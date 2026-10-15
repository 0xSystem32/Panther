"""Comparaison de deux scans : nouveaux appareils, appareils disparus, appareils modifiés.

Module pur. Un « instantané » est la liste des appareils en ligne lors d'un scan, réduite à ce qui a un
sens à comparer (pas de TTL ni d'heures qui changent à chaque scan). On compare les valeurs automatiques
(pas le nom choisi à la main), pour qu'un renommage ne passe pas pour un changement de l'appareil.
"""
from . import security
from . import store
from .i18n import N_, tr

# Les libellés français servent aussi d'identifiants de changement : ils ne sont traduits qu'à l'affichage (`format_change`).
FIELD_LABELS = {"ip": N_("Adresse IP"), "name": N_("Nom"), "type": N_("Type"), "os": N_("Système"), "vendor": N_("Fabricant")}


def format_change(label, old, new):
    """Texte lisible d'un changement : « Adresse IP : a → b », « Ports ouverts : +443 », « Constats : −Telnet activé »."""
    if label == "Constats de sécurité":
        names = lambda v: ", ".join(security.title_of(x) for x in v[1:].split(", ")) if v != "—" else "—"
        old = ("−" + names(old)) if old != "—" else "—"
        new = ("+" + names(new)) if new != "—" else "—"
    if label in ("Ports ouverts", "Constats de sécurité"):
        return f"{tr(label)} : " + "  /  ".join(x for x in (old, new) if x != "—")
    return f"{tr(label)} : {old} → {new}"


def snapshot_record(d):
    sec = d.get("security")
    return {"key": d.get("key") or store.key_for(d), "ip": d["ip"], "mac": d.get("mac", ""),
            "name": d.get("auto_hostname", d.get("hostname", "")), "type": d.get("auto_type", d.get("type", "")),
            "vendor": d.get("vendor", ""), "os": d.get("os", ""), "network": d.get("network", ""),
            "ports": sorted(d.get("ports") or []),
            "sec": None if sec is None else sorted(f["id"] for f in sec)}


def snapshot_of(devices):
    return [snapshot_record(d) for d in devices if d.get("online", True) and not d.get("virtual")]


def compare(a, b):
    """a = scan le plus ancien, b = le plus récent (listes d'enregistrements).
    -> {new, gone, changed: [{rec, changes: [(libellé, avant, après)]}], same}"""
    ka, kb = {r["key"]: r for r in a}, {r["key"]: r for r in b}
    changed, same = [], 0
    for k in kb.keys() & ka.keys():
        old, new, ch = ka[k], kb[k], []
        for f, label in FIELD_LABELS.items():
            if old.get(f) != new.get(f):
                ch.append((label, old.get(f) or "—", new.get(f) or "—"))
        po, pn = set(old.get("ports", [])), set(new.get("ports", []))
        if po != pn:
            ch.append((N_("Ports ouverts"), "−" + ", ".join(map(str, sorted(po - pn))) if po - pn else "—",
                       "+" + ", ".join(map(str, sorted(pn - po))) if pn - po else "—"))
        so, sn = old.get("sec"), new.get("sec")
        if so is not None and sn is not None and set(so) != set(sn):  # comparé seulement si les deux scans ont analysé la sécurité
            ch.append((N_("Constats de sécurité"), "−" + ", ".join(sorted(set(so) - set(sn))) if set(so) - set(sn) else "—",
                       "+" + ", ".join(sorted(set(sn) - set(so))) if set(sn) - set(so) else "—"))
        if ch:
            changed.append({"rec": new, "changes": ch})
        else:
            same += 1
    by_ip = lambda r: tuple(int(x) for x in r["ip"].split(".")) if r["ip"].count(".") == 3 else (0,)
    return {"new": sorted((kb[k] for k in kb.keys() - ka.keys()), key=by_ip),
            "gone": sorted((ka[k] for k in ka.keys() - kb.keys()), key=by_ip),
            "changed": sorted(changed, key=lambda c: by_ip(c["rec"])), "same": same}
