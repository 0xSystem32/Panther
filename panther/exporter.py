"""Export des appareils en lignes plates (CSV / JSON), avec tout ce que Panther sait : confiance, groupe, étiquettes, notes,
historique, exposition, certificat. Module pur (testable sans interface).

Les valeurs viennent du réseau (noms d'appareils, bannières…) : en CSV, une cellule qui commence par `=`, `+`, `-`, `@`
ou une tabulation est préfixée d'une apostrophe, pour qu'un tableur ne l'exécute jamais comme une formule.
"""
import csv
import io
import json
import time

from . import security
from .i18n import N_, tr
from .labels import TYPE_LABELS

# (clé, libellé de colonne)
COLUMNS = [("ip", N_("Adresse IP")), ("name", N_("Nom")), ("type", N_("Type")), ("mac", N_("Adresse MAC")), ("vendor", N_("Fabricant")), ("model", N_("Modèle")),
           ("os", N_("Système")), ("network", N_("Réseau")), ("vlan", N_("VLAN")), ("status", N_("Statut")), ("trusted", N_("De confiance")), ("group", N_("Groupe")),
           ("tags", N_("Étiquettes")), ("note", N_("Notes")), ("first_seen", N_("Première apparition")), ("last_seen", N_("Dernière apparition")),
           ("exposure", N_("Exposition max.")), ("findings", N_("Constats de sécurité")), ("ports", N_("Ports ouverts")), ("services", N_("Services")),
           ("cert", N_("Certificat HTTPS")), ("switch", N_("Switch")), ("switch_port", N_("Port du switch")), ("confidence", N_("Confiance de la détection (%)")),
           ("reasons", N_("Indices de détection"))]
_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _when(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""


def row(d):
    """Un appareil -> dict de valeurs simples (texte, nombres, booléens)."""
    findings = d.get("security")
    cert = d.get("cert") or {}
    model = d.get("model_name") or d.get("model") or ""
    status = tr("Hors ligne") if not d.get("online", True) else tr("Nouveau") if d.get("new") else tr("En ligne")
    return {"ip": d.get("ip", ""), "name": d.get("hostname", ""), "type": TYPE_LABELS.get(d.get("type"), d.get("type", "")), "mac": d.get("mac", ""),
            "vendor": d.get("vendor", ""), "model": model, "os": d.get("os", ""), "network": d.get("network", ""), "vlan": d.get("vlan") or "",
            "status": status, "trusted": bool(d.get("trusted")), "group": d.get("group", ""), "tags": ", ".join(d.get("tags", [])), "note": d.get("note", ""),
            "first_seen": _when(d.get("first_seen")), "last_seen": tr("en ligne") if d.get("online", True) else _when(d.get("last_seen")),
            "exposure": security.LABELS.get(security.worst(findings), "") if findings else ("" if findings is None else tr("aucun")),
            "findings": " ; ".join(f["title"] for f in findings or []), "ports": " ".join(map(str, d.get("ports", []))),
            "services": ", ".join(d.get("services", [])),
            "cert": " · ".join(x for x in (cert.get("cn") or cert.get("o"), (tr("auto-signé") if cert.get("self_signed") else cert.get("issuer")),
                                           (tr("expiré") if cert.get("expired") else tr("expire le {date}", date=cert['not_after']) if cert.get("not_after") else "")) if x),
            "switch": d.get("switch", ""), "switch_port": d.get("switch_port", ""), "confidence": d.get("confidence", ""),
            "reasons": " ; ".join(d.get("reasons", []))}


def rows(devices):
    return [row(d) for d in sorted((x for x in devices if not x.get("virtual")), key=_ip_key)]


def _ip_key(d):
    try:
        return tuple(int(x) for x in d.get("ip", "").split("."))
    except ValueError:
        return (0,)


def csv_safe(v):
    if isinstance(v, bool):
        return "oui" if v else "non"
    s = "" if v is None else str(v)
    return "'" + s if s.startswith(_FORMULA) else s


def to_csv(devices):
    out = io.StringIO(newline="")
    w = csv.writer(out)
    w.writerow([tr(label) for _k, label in COLUMNS])
    for r in rows(devices):
        w.writerow([csv_safe(r[k]) for k, _l in COLUMNS])
    return out.getvalue()


def to_json(devices, networks=()):
    data = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "networks": list(networks), "devices": rows(devices)}
    return json.dumps(data, indent=2, ensure_ascii=False)
