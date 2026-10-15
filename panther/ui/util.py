"""Libellés, dates et petites fonctions communes à l'interface."""
import html
import logging
import time

from PyQt6.QtCore import Qt

from .. import i18n, store
from ..i18n import N_, TrDict, tr
from ..labels import TYPE_LABELS

log = logging.getLogger("panther.gui")


LABELS = TYPE_LABELS


EVENT_LABELS = TrDict({"first_seen": N_("Nouvel appareil"), "online": N_("De retour en ligne"), "offline": N_("Hors ligne"),
                       "exposure": N_("Nouvelle exposition"), "exposure_fixed": N_("Exposition corrigée"), "merged": N_("Appareils fusionnés"),
                       "ip_changed": N_("Changement d'adresse IP"), "trusted": N_("Marqué de confiance"), "untrusted": N_("Confiance retirée")})


SECURITY_INFO = N_(
    "L'analyse de sécurité est en lecture seule.\n\n"
    "Elle regarde les ports ouverts et les bannières, et envoie UNE requête de lecture sans identifiant à "
    "certains services pour savoir s'ils répondent sans mot de passe : PING (Redis), version (Memcached), "
    "GET / (Elasticsearch), GET /version (Docker), DESCRIBE (flux vidéo RTSP).\n\n"
    "Elle n'essaie aucun identifiant, ne devine aucun mot de passe et n'exploite aucune faille.\n\n"
    "À n'activer que sur des réseaux dont vous êtes responsable ou que vous avez l'autorisation d'analyser.")


def human_size(n):
    units = ("B", "KB", "MB", "GB") if i18n.language() == "en" else ("o", "Ko", "Mo", "Go")
    for i, unit in enumerate(units):
        if n < 1024 or i == len(units) - 1:
            return f"{n:.0f} {unit}" if i == 0 else f"{n:.1f} {unit}"
        n /= 1024


def tip(text):
    """Infobulle sûre : Qt affiche en HTML tout texte qui y ressemble, or noms, bannières et certificats viennent du réseau."""
    return "<div style='white-space:pre-wrap'>" + html.escape(str(text), quote=False) + "</div>"


def snmp_secret(host):
    return f"snmp-community:{host}"


def when(ts):
    return time.strftime(i18n.when_format()[0], time.localtime(ts)) if ts else ""


def when_short(ts):
    return time.strftime("%m-%d %H:%M" if i18n.language() == "en" else "%d/%m %H:%M", time.localtime(ts)) if ts else ""


def seen_label(ts):
    """Heure si c'était aujourd'hui, sinon jour/mois."""
    if not ts:
        return ""
    t = time.localtime(ts)
    return time.strftime("%H:%M" if time.strftime("%Y%m%d", t) == time.strftime("%Y%m%d") else "%m-%d" if i18n.language() == "en" else "%d/%m", t)


def status_text(d):
    if not d.get("online", True):
        return tr("Hors ligne (vu {seen})", seen=seen_label(d.get('last_seen')))
    return tr("Nouveau") if d.get("new") else tr("En ligne")


KEY_ROLE = Qt.ItemDataRole.UserRole + 1


def dkey(d):
    """Identité d'un appareil dans l'interface : sa clé (MAC d'abord), jamais l'IP seule."""
    return d.get("key") or store.key_for(d)


def ip_key(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (0,)
