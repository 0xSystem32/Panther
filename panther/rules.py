"""Règles de détection personnalisées (fichier JSON, sans toucher au code).

`~/.config/Panther/rules.json` :

    {"version": 1,
     "rules": [
        {"name": "Imprimante du bureau", "type": "printer", "points": 60,
         "match": {"hostname": "^hp-", "ports_any": [9100, 631]}}],
     "models": [
        {"pattern": "^MaCam-", "name": "Ma caméra", "type": "camera"}]}

Une règle s'applique si **toutes** ses conditions sont vraies ; elle ajoute `points` (1 à 100, 50 par défaut) au type
indiqué, comme n'importe quel autre indice (la détection intégrée garde son rôle). `"force": true` impose le type.
Conditions : hostname, vendor, model, os, banner, ssdp, cert (expressions régulières, ou liste = l'une d'elles), ports_any,
ports_all, mdns_service, mac_prefix, in_network (CIDR), gateway (true/false).

Les expressions régulières viennent d'un fichier que l'on peut échanger : elles sont limitées en taille, les motifs à
quantificateurs imbriqués (risque de blocage) sont refusés et le texte testé est tronqué.
"""
import ipaddress
import json
import logging
import os
import re
import tempfile
from typing import Any

from . import fingerprint
from .i18n import tr

log = logging.getLogger("panther.rules")
PATH = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "Panther", "rules.json")
MAX_BYTES, MAX_RULES, MAX_PATTERN, MAX_TEXT = 256 * 1024, 500, 200, 400
TEXT_FIELDS = ("hostname", "vendor", "model", "os", "banner", "ssdp", "cert")
LIST_FIELDS = ("ports_any", "ports_all", "mdns_service", "mac_prefix")
CONDITIONS = TEXT_FIELDS + LIST_FIELDS + ("in_network", "gateway")
_NESTED = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*{]")  # (a+)+ , (.*)* … : backtracking explosif


class RuleError(ValueError):
    pass


def _regexes(value, field):
    items = value if isinstance(value, list) else [value]
    out = []
    for p in items:
        if not isinstance(p, str) or not p:
            raise RuleError(f"{field} : motif vide ou invalide")
        if len(p) > MAX_PATTERN:
            raise RuleError(f"{field} : motif trop long ({len(p)} > {MAX_PATTERN})")
        if _NESTED.search(p):
            raise RuleError(tr("{field} : motif refusé (quantificateurs imbriqués, risque de blocage)", field=field))
        try:
            out.append(re.compile(p, re.I))
        except re.error as e:
            raise RuleError(tr("{field} : expression régulière invalide ({e})", field=field, e=e)) from None
    return out


def _ports(value, field):
    if not isinstance(value, list) or not value or not all(isinstance(p, int) and 0 < p < 65536 for p in value):
        raise RuleError(tr("{field} : liste de ports (1-65535) attendue", field=field))
    return set(value)


def _mac_prefixes(value):
    items = value if isinstance(value, list) else [value]
    out = []
    for p in items:
        h = re.sub(r"[^0-9a-f]", "", str(p).lower())
        if not 2 <= len(h) <= 12:
            raise RuleError(tr("mac_prefix : préfixe de 1 à 6 octets attendu"))
        out.append(h)
    return out


class Rule:
    def __init__(self, name, kind, points, force, reason, cond):
        self.name, self.kind, self.points, self.force, self.reason, self.cond = name, kind, points, force, reason, cond

    def matches(self, view):
        c = self.cond
        for f in TEXT_FIELDS:
            if f in c and not any(rx.search(view[f]) for rx in c[f]):
                return False
        if "ports_any" in c and not (c["ports_any"] & view["ports"]):
            return False
        if "ports_all" in c and not c["ports_all"] <= view["ports"]:
            return False
        if "mdns_service" in c and not any(rx.search(s) for rx in c["mdns_service"] for s in view["mdns"]):
            return False
        if "mac_prefix" in c and not any(view["mac"].startswith(p) for p in c["mac_prefix"]):
            return False
        if "in_network" in c and not (view["ip"] and ipaddress.ip_address(view["ip"]) in c["in_network"]):
            return False
        if "gateway" in c and bool(c["gateway"]) != view["gateway"]:
            return False
        return True


def parse_rule(raw):
    """Règle brute (dict) -> Rule, ou RuleError avec un message clair."""
    if not isinstance(raw, dict):
        raise RuleError(tr("la règle doit être un objet"))
    name = str(raw.get("name") or "").strip()[:80]
    if not name:
        raise RuleError(tr("nom manquant"))
    kind = raw.get("type")
    if kind not in fingerprint.KINDS:
        raise RuleError(tr("type « {kind} » inconnu (types : {types})", kind=kind, types=', '.join(fingerprint.KINDS)))
    pts = raw.get("points", 50)
    if not isinstance(pts, (int, float)) or isinstance(pts, bool) or not 1 <= pts <= 100:
        raise RuleError("points : nombre entre 1 et 100 attendu")
    match = raw.get("match")
    if not isinstance(match, dict) or not match:
        raise RuleError(tr("match : au moins une condition est nécessaire (sinon la règle s'appliquerait à tout)"))
    unknown = set(match) - set(CONDITIONS)
    if unknown:
        raise RuleError(f"condition(s) inconnue(s) : {', '.join(sorted(unknown))}")
    cond = {}
    for f, v in match.items():
        if f in TEXT_FIELDS or f == "mdns_service":
            cond[f] = _regexes(v, f)
        elif f in ("ports_any", "ports_all"):
            cond[f] = _ports(v, f)
        elif f == "mac_prefix":
            cond[f] = _mac_prefixes(v)
        elif f == "in_network":
            try:
                cond[f] = ipaddress.ip_network(str(v), strict=False)
            except ValueError:
                raise RuleError(f"in_network : plage invalide « {v} »") from None
        elif f == "gateway":
            cond[f] = bool(v)
    reason = str(raw.get("reason") or tr("règle « {name} »", name=name))[:100]
    return Rule(name, kind, float(pts), bool(raw.get("force", False)), reason, cond)


class RuleSet:
    def __init__(self, rules=(), models=(), warnings=()):
        self.rules, self.models, self.warnings = list(rules), list(models), list(warnings)


def parse(data):
    """Contenu JSON déjà lu -> RuleSet (les règles invalides sont écartées, avec un avertissement chacune)."""
    rs = RuleSet()
    if not isinstance(data, dict):
        rs.warnings.append(tr("fichier de règles : un objet JSON est attendu"))
        return rs
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        rs.warnings.append(tr("« rules » doit être une liste"))
        raw_rules = []
    if len(raw_rules) > MAX_RULES:
        rs.warnings.append(tr("{count} règles : seules les {maximum} premières sont lues", count=len(raw_rules), maximum=MAX_RULES))
    for i, raw in enumerate(raw_rules[:MAX_RULES], 1):
        try:
            rs.rules.append(parse_rule(raw))
        except RuleError as e:
            label = raw.get("name") if isinstance(raw, dict) and raw.get("name") else f"n°{i}"
            rs.warnings.append(tr("règle {label} ignorée : {e}", label=label, e=e))
    for i, m in enumerate(data.get("models", []) if isinstance(data.get("models"), list) else [], 1):
        try:
            rx = _regexes(m.get("pattern"), "pattern")[0]
            name = str(m.get("name") or "").strip()[:80]
            if not name:
                raise RuleError(tr("nom manquant"))
            kind = m.get("type")
            if kind is not None and kind not in fingerprint.KINDS:
                raise RuleError(tr("type « {kind} » inconnu", kind=kind))
            rs.models.append((rx, name, kind))
        except (RuleError, AttributeError, IndexError) as e:
            rs.warnings.append(tr("modèle n°{i} ignoré : {e}", i=i, e=e))
    return rs


_cache: dict[str, Any] = {"path": None, "mtime": None, "rs": RuleSet()}


def read_data(path=None):
    """Lit le fichier (dict brut). Fichier absent : dict vide. Lève RuleError s'il est illisible ou trop gros."""
    path = path or PATH
    try:
        if os.path.getsize(path) > MAX_BYTES:
            raise RuleError(f"fichier trop gros (> {MAX_BYTES // 1024} Ko)")
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise RuleError(f"fichier illisible : {e}") from None


def current(path=None):
    """RuleSet à jour : le fichier n'est relu que s'il a changé. Un fichier cassé ne casse jamais le scan."""
    path = path or PATH
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    if _cache["path"] == path and _cache["mtime"] == mtime:
        return _cache["rs"]
    try:
        rs = parse(read_data(path))
    except RuleError as e:
        rs = RuleSet(warnings=[str(e)])
        log.warning("Règles de détection : %s", e)
    for w in rs.warnings:
        log.warning("Règles de détection : %s", w)
    _cache.update(path=path, mtime=mtime, rs=rs)
    return rs


def _view(dev):
    """Les champs d'un appareil sous la forme que les règles comparent (texte tronqué, minuscules pour les listes)."""
    ss = dev.get("ssdp") or {}
    return {"hostname": (dev.get("auto_hostname") or dev.get("hostname") or "")[:MAX_TEXT], "vendor": (dev.get("vendor") or "")[:MAX_TEXT],
            "model": fingerprint._model_text(dev)[:MAX_TEXT], "os": (dev.get("os") or "")[:MAX_TEXT],
            "banner": " ".join((dev.get("banners") or {}).values())[:MAX_TEXT],
            "cert": ((dev.get("cert") or {}).get("indicators") or "")[:MAX_TEXT],
            "ssdp": " ".join(str(ss.get(k, "")) for k in ("server", "friendly", "manufacturer", "model", "dtype"))[:MAX_TEXT],
            "ports": set(dev.get("ports") or []), "mdns": list(dev.get("mdns_services") or []),
            "mac": re.sub(r"[^0-9a-f]", "", (dev.get("mac") or "").lower()), "ip": dev.get("ip") or "", "gateway": bool(dev.get("is_gateway"))}


def evaluate(dev, rs=None):
    """[(type, points, raison, force)] pour les règles qui s'appliquent à cet appareil."""
    rs = rs or current()
    if not rs.rules:
        return []
    view = _view(dev)
    out = []
    for r in rs.rules:
        try:
            if r.matches(view):
                out.append((r.kind, r.points, r.reason, r.force))
        except Exception:
            log.debug("Règle %s ignorée sur %s", r.name, dev.get("ip"), exc_info=True)
    return out


def user_model(identifier, rs=None):
    """(nom, type) d'un modèle défini par l'utilisateur, ou None."""
    for rx, name, kind in (rs or current()).models:
        if identifier and rx.search(identifier):
            return name, kind
    return None


# ------------------------------------------------------------------ édition, import / export
def _save(data, path=None):
    path = path or PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)  # écriture atomique


def example():
    return {"version": 1,
            "rules": [{"name": "Exemple : imprimante réseau du bureau", "type": "printer", "points": 60,
                       "match": {"hostname": "^(hp|brother)-", "ports_any": [9100, 631]}},
                      {"name": "Exemple : caméras du garage", "type": "camera", "points": 70,
                       "match": {"in_network": "192.168.20.0/24", "ports_any": [554]}}],
            "models": [{"pattern": "^MaCam-", "name": "Ma caméra maison", "type": "camera"}]}


def create_example(path=None):
    """Écrit un fichier d'exemple s'il n'en existe pas encore. -> True si créé."""
    path = path or PATH
    if os.path.exists(path):
        return False
    _save(example(), path)
    return True


def make_rule(dev, kind, criteria, name=None):
    """Construit une règle à partir d'un appareil : `criteria` ⊂ {hostname, vendor, ports, mdns, mac}.
    Lève RuleError si aucun critère exploitable n'est retenu."""
    if kind not in fingerprint.KINDS:
        raise RuleError(tr("type « {kind} » inconnu", kind=kind))
    v = _view(dev)
    match = {}
    if "hostname" in criteria and v["hostname"] and v["hostname"] != dev.get("ip"):
        match["hostname"] = "^" + re.escape(v["hostname"]) + "$"
    if "vendor" in criteria and v["vendor"] and v["vendor"] not in ("MAC aléatoire", tr("MAC aléatoire")):
        match["vendor"] = "^" + re.escape(v["vendor"]) + "$"
    if "ports" in criteria and v["ports"]:
        match["ports_all"] = sorted(v["ports"])[:4]
    if "mdns" in criteria and v["mdns"]:
        match["mdns_service"] = [re.escape(s) for s in sorted(v["mdns"])[:3]]
    if "mac" in criteria and len(v["mac"]) >= 6 and not fingerprint.is_random_mac(dev.get("mac", "")):
        match["mac_prefix"] = ":".join(v["mac"][i:i + 2] for i in range(0, 6, 2))
    if not match:
        raise RuleError(tr("aucun critère exploitable pour cet appareil (nom, fabricant, ports, services ou MAC)"))
    label = name or f"{dev.get('hostname') or dev.get('ip')} → {kind}"
    return {"name": label[:80], "type": kind, "points": 70, "match": match}


def add_rule(raw, path=None):
    """Ajoute une règle au fichier (validée avant l'écriture). Remplace une règle de même nom."""
    parse_rule(raw)
    data = read_data(path) or {}
    data.setdefault("version", 1)
    rules = [r for r in data.get("rules", []) if not (isinstance(r, dict) and r.get("name") == raw["name"])]
    rules.append(raw)
    data["rules"] = rules
    _save(data, path)


def remove_rule(name, path=None):
    """Supprime la règle de ce nom. -> True si elle existait."""
    data = read_data(path) or {}
    rules_ = data.get("rules", [])
    kept = [x for x in rules_ if not (isinstance(x, dict) and x.get("name") == name)]
    if len(kept) == len(rules_):
        return False
    data["rules"] = kept
    _save(data, path)
    return True


def describe(rule):
    """Résumé lisible des conditions d'une règle (dict brut ou Rule)."""
    match = rule.get("match", {}) if isinstance(rule, dict) else {}
    parts = []
    for k, v in match.items():
        parts.append(f"{k} = {', '.join(map(str, v)) if isinstance(v, list) else v}")
    return " ; ".join(parts)


def export_to(dest, path=None):
    """Copie le fichier de règles (ou l'exemple s'il n'existe pas) vers `dest`."""
    data = read_data(path)
    _save(data if data else example(), dest)


def import_from(src, path=None):
    """Fusionne un fichier de règles externe : règles valides ajoutées (même nom = remplacée). -> (ajoutées, écartées[str])."""
    incoming = read_data(src)
    rs = parse(incoming)
    ok_names = {r.name for r in rs.rules}
    data = read_data(path) or {}
    data.setdefault("version", 1)
    mine = {r.get("name"): r for r in data.get("rules", []) if isinstance(r, dict)}
    added = 0
    for raw in incoming.get("rules", []) if isinstance(incoming, dict) else []:
        if isinstance(raw, dict) and str(raw.get("name") or "").strip()[:80] in ok_names:
            mine[str(raw["name"]).strip()[:80]] = raw
            added += 1
    data["rules"] = list(mine.values())
    models = {m.get("pattern"): m for m in data.get("models", []) if isinstance(m, dict)}
    for m in (incoming.get("models", []) if isinstance(incoming, dict) and isinstance(incoming.get("models"), list) else []):
        if isinstance(m, dict) and any(rx.pattern == m.get("pattern") for rx, _n, _k in rs.models):
            models[m["pattern"]] = m
    data["models"] = list(models.values())
    _save(data, path)
    return added, rs.warnings
