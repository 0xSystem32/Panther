"""Alertes sur événements du réseau, par webhook (Discord, Slack, ntfy, JSON générique) et/ou e-mail (SMTP).

* Un seul message par scan, qui regroupe les événements (pas de rafale) ; jamais pour la première analyse (référence).
* Les réglages (`~/.config/Panther/alerts.json`) ne contiennent AUCUN secret : l'URL du webhook et le mot de passe SMTP sont dans
  `secrets.py` (trousseau du système ou fichier privé).
* Le message contient des noms et adresses d'appareils de votre réseau : il part là où vous l'envoyez, à vous de choisir un service de
  confiance. Les noms viennent du réseau (non fiables) : ils sont nettoyés avant d'entrer dans un message ou un en-tête d'e-mail.
"""
import json
import logging
import os
import re
import smtplib
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage

from . import secrets, security
from .i18n import plural, tr

log = logging.getLogger("panther.alerts")
PATH = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "Panther", "alerts.json")
FORMATS = ("generic", "discord", "slack", "ntfy")
SECURITIES = ("starttls", "ssl", "none")
SECRET_WEBHOOK, SECRET_SMTP = "alerts-webhook-url", "alerts-smtp-password"
MAX_LINES, MAX_TEXT = 20, 160
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")

DEFAULTS = {"enabled": False,
            "events": {"new_device": True, "new_exposure": True, "exposure_min": "élevé", "trusted_offline": False, "auto_only": True},
            "webhook": {"enabled": False, "format": "generic"},
            "email": {"enabled": False, "host": "", "port": 587, "security": "starttls", "user": "", "from": "", "to": []}}


class AlertError(Exception):
    pass


def clean(text, limit=MAX_TEXT):
    """Texte venu du réseau, rendu inoffensif pour un message ou un en-tête : sans retours à la ligne ni caractères de contrôle."""
    return _CTRL.sub(" ", str(text or "")).strip()[:limit]


# ------------------------------------------------------------------ configuration
def validate(cfg):
    """Réglages bruts -> réglages complets et sûrs (valeurs par défaut, types, bornes). Lève AlertError sur une adresse invalide."""
    cfg = cfg if isinstance(cfg, dict) else {}
    out = json.loads(json.dumps(DEFAULTS))
    out["enabled"] = bool(cfg.get("enabled"))
    ev = cfg.get("events") if isinstance(cfg.get("events"), dict) else {}
    for k in ("new_device", "new_exposure", "trusted_offline", "auto_only"):
        out["events"][k] = bool(ev.get(k, out["events"][k]))
    out["events"]["exposure_min"] = ev.get("exposure_min") if ev.get("exposure_min") in security.RANK else "élevé"
    wh = cfg.get("webhook") if isinstance(cfg.get("webhook"), dict) else {}
    out["webhook"] = {"enabled": bool(wh.get("enabled")), "format": wh.get("format") if wh.get("format") in FORMATS else "generic"}
    em = cfg.get("email") if isinstance(cfg.get("email"), dict) else {}
    try:
        port = int(em.get("port", 587))
    except (TypeError, ValueError):
        port = 587
    to = em.get("to", [])
    to = [t.strip() for t in (to.split(",") if isinstance(to, str) else to) if str(t).strip()]
    sender = str(em.get("from") or "").strip()
    bad = [a for a in to + ([sender] if sender else []) if not _EMAIL.match(a)]
    if bad:
        raise AlertError(tr("adresse e-mail invalide : {address}", address=bad[0]))
    out["email"] = {"enabled": bool(em.get("enabled")), "host": clean(em.get("host"), 253), "port": port if 1 <= port <= 65535 else 587,
                    "security": em.get("security") if em.get("security") in SECURITIES else "starttls", "user": clean(em.get("user"), 200),
                    "from": sender, "to": to[:10]}
    return out


def load(path=None):
    try:
        with open(path or PATH, encoding="utf-8") as f:
            return validate(json.load(f))
    except (OSError, ValueError, AlertError):
        return validate({})


def save(cfg, path=None):
    """Enregistre les réglages (sans secret). Écriture atomique."""
    path = path or PATH
    cfg = validate(cfg)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return cfg


# ------------------------------------------------------------------ événements
def build_events(devices, record, findings, cfg, history_events=()):
    """Événements à signaler après un scan : [{kind, title, detail}]. Rien pour la première analyse (référence)."""
    ev = cfg["events"]
    out = []
    if record.get("baseline") and not findings.get("new"):
        return out
    by_key = {(d.get("key") or d.get("mac") or "ip:" + d.get("ip", "")): d for d in devices}
    if ev["new_device"] and not record.get("baseline"):
        for d in devices:
            if d.get("new") and d.get("online", True):
                what = " · ".join(x for x in (clean(d.get("ip")), clean(d.get("vendor"), 40), clean(d.get("model_name") or d.get("type"), 40)) if x)
                out.append({"kind": "new_device", "title": tr("Nouvel appareil : {name}", name=clean(d.get('hostname') or d.get('ip'), 60)), "detail": what})
    if ev["new_exposure"]:
        floor = security.RANK[ev["exposure_min"]]
        for d, f in findings.get("new", []):
            if security.RANK.get(f["severity"], 0) >= floor:
                out.append({"kind": "new_exposure", "title": tr("Nouvelle exposition ({severity}) : {name}", severity=security.LABELS[f['severity']].lower(), name=clean(d.get('hostname') or d.get('ip'), 60)),
                            "detail": clean(f["title"] + (tr(" (port {port})", port=f['port']) if f.get("port") else ""))})
    if ev["trusted_offline"]:
        for kind, key, name, detail in history_events:
            d = by_key.get(key)
            if kind == "offline" and d is not None and d.get("trusted"):
                out.append({"kind": "offline", "title": tr("Appareil de confiance hors ligne : {name}", name=clean(name, 60)), "detail": clean(detail)})
    return out


def compose(events, when=None):
    """(titre, texte) d'un message regroupant les événements."""
    n = len(events)
    title = tr("Panther : {count} sur le réseau", count=plural(n, "événement", "événements"))
    lines = [f"• {e['title']}" + (f" — {e['detail']}" if e.get("detail") else "") for e in events[:MAX_LINES]]
    if n > MAX_LINES:
        lines.append(tr("… et {n} autre(s)", n=n - MAX_LINES))
    stamp = time.strftime(tr("%d/%m/%Y %H:%M"), time.localtime(when or time.time()))
    return title, f"{stamp}\n" + "\n".join(lines)


# ------------------------------------------------------------------ webhook
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # on n'envoie jamais le message ailleurs que là où l'utilisateur l'a demandé


def webhook_request(url, fmt, title, text, events=()):
    """Construit la requête HTTP (url, en-têtes, corps) selon le service visé."""
    u = urllib.parse.urlparse(url or "")
    if u.scheme not in ("http", "https") or not u.netloc:
        raise AlertError(tr("l'URL du webhook doit commencer par http:// ou https://"))
    if fmt == "discord":
        body, ctype = json.dumps({"content": f"**{title}**\n{text}"[:1900]}).encode(), "application/json"
        headers = {}
    elif fmt == "slack":
        body, ctype = json.dumps({"text": f"*{title}*\n{text}"}).encode(), "application/json"
        headers = {}
    elif fmt == "ntfy":
        body, ctype = text.encode("utf-8"), "text/plain; charset=utf-8"
        headers = {"Title": title.encode("ascii", "ignore").decode().strip() or "Panther"}  # en-tête : ASCII seulement
    else:
        body, ctype = json.dumps({"title": title, "message": text, "events": list(events), "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z")},
                                 ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8"
        headers = {}
    return url, {"Content-Type": ctype, "User-Agent": "Panther", **headers}, body


def send_webhook(url, fmt, title, text, events=(), timeout=10):
    url, headers, body = webhook_request(url, fmt, title, text, events)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(urllib.request.Request(url, data=body, headers=headers, method="POST"), timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        raise AlertError(tr("le service a répondu {code}", code=e.code)) from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise AlertError(tr("envoi impossible : {reason}", reason=getattr(e, 'reason', e))) from None


# ------------------------------------------------------------------ e-mail
def send_email(em, password, title, text, timeout=15):
    if not em.get("host") or not em.get("to") or not em.get("from"):
        raise AlertError(tr("réglages e-mail incomplets (serveur, expéditeur et destinataire requis)"))
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = clean(title, 200), em["from"], ", ".join(em["to"])
    msg.set_content(text)
    try:
        if em["security"] == "ssl":
            smtp = smtplib.SMTP_SSL(em["host"], em["port"], timeout=timeout, context=ssl.create_default_context())  # certificat vérifié
        else:
            smtp = smtplib.SMTP(em["host"], em["port"], timeout=timeout)
        with smtp:
            if em["security"] == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if em.get("user") and password:
                smtp.login(em["user"], password)
            smtp.send_message(msg)
    except ssl.SSLError as e:
        raise AlertError(tr("connexion sécurisée refusée (certificat ou protocole) : {e}", e=e)) from None
    except (smtplib.SMTPException, OSError) as e:
        raise AlertError(tr("envoi impossible : {e}", e=e)) from None


# ------------------------------------------------------------------ envoi
def dispatch(cfg, events, when=None, webhook_url=None, smtp_password=None):
    """Envoie le message sur chaque canal actif. -> [(canal, ok, message d'erreur ou '')]. N'échoue jamais : un canal en panne n'empêche pas l'autre."""
    if not events:
        return []
    title, text = compose(events, when)
    results = []
    if cfg["webhook"]["enabled"]:
        try:
            send_webhook(webhook_url if webhook_url is not None else (secrets.get(SECRET_WEBHOOK) or ""), cfg["webhook"]["format"], title, text, events)
            results.append(("webhook", True, ""))
        except AlertError as e:
            log.warning("Webhook : %s", e)
            results.append(("webhook", False, str(e)))
    if cfg["email"]["enabled"]:
        try:
            send_email(cfg["email"], smtp_password if smtp_password is not None else secrets.get(SECRET_SMTP), title, text)
            results.append(("e-mail", True, ""))
        except AlertError as e:
            log.warning("E-mail : %s", e)
            results.append(("e-mail", False, str(e)))
    return results


def test_message():
    return [{"kind": "test", "title": tr("Message de test"), "detail": tr("Si vous lisez ceci, les alertes Panther fonctionnent.")}]
