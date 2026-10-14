"""Analyse d'exposition en lecture seule (opt-in, réseaux dont on a la responsabilité).

Ce que fait Panther, et seulement cela :
  * regarder quels ports sont ouverts et quelles bannières les services annoncent ;
  * envoyer UNE requête de lecture anodine, sans identifiant, pour savoir si un service répond sans
    mot de passe (PING Redis, `version` Memcached, GET / Elasticsearch, GET /version Docker, DESCRIBE RTSP).
Il n'essaie AUCUN identifiant, ne devine aucun mot de passe, n'exploite aucune faille.
"""
import logging
import re
import socket
import time

log = logging.getLogger("panther.security")
SEVERITIES = ("info", "faible", "moyen", "élevé", "critique")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
LABELS = {"critique": "Critique", "élevé": "Élevé", "moyen": "Moyen", "faible": "Faible", "info": "Info"}
# Ports ajoutés au scan quand l'analyse est activée (sur les ports déjà scannés, rien n'est dupliqué).
EXTRA_PORTS = (111, 1433, 1883, 2049, 2323, 2375, 5900, 5984, 7547, 8554, 9200, 11211, 27017, 34567, 37777)
ADMIN_TYPES = {"router", "switch", "camera", "nas", "printer", "iot"}
PLAIN_HTTP = {80, 8000, 8008, 8080, 8081, 8888, 9000}


def finding(fid, severity, title, detail="", remedy="", port=None):
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "remedy": remedy, "port": port}


# id, gravité, titre, détail, recommandation
PORT_RULES = {
    23: ("telnet", "élevé", "Telnet activé", "Le mot de passe et les commandes circulent en clair sur le réseau.",
         "Désactiver Telnet et utiliser SSH."),
    2323: ("telnet", "élevé", "Telnet activé (port 2323)", "Le mot de passe et les commandes circulent en clair.",
           "Désactiver Telnet et utiliser SSH."),
    21: ("ftp", "moyen", "FTP activé", "Identifiants et fichiers transmis en clair.", "Utiliser SFTP ou FTPS."),
    3389: ("rdp", "élevé", "Bureau à distance (RDP) accessible", "Cible fréquente d'attaques par mots de passe.",
           "Activer l'authentification NLA, limiter l'accès (VPN, pare-feu) ou désactiver."),
    5900: ("vnc", "élevé", "VNC accessible", "Prise de contrôle à distance souvent protégée par un mot de passe faible.",
           "Passer par un tunnel SSH/VPN ou désactiver."),
    5555: ("adb", "élevé", "Débogage Android (ADB) ouvert", "Permet de contrôler l'appareil depuis le réseau.",
           "Désactiver le débogage réseau dans les options développeur."),
    111: ("rpc", "moyen", "RPC/portmap accessible", "Service d'administration réseau rarement nécessaire.", "Filtrer ou désactiver."),
    2049: ("nfs", "moyen", "Partage NFS accessible", "Selon la configuration, accessible sans authentification.",
           "Restreindre les clients autorisés."),
    3306: ("mysql", "moyen", "Base MySQL accessible depuis le réseau", "", "Limiter à localhost ou à des machines précises."),
    5432: ("postgres", "moyen", "Base PostgreSQL accessible depuis le réseau", "", "Limiter à localhost ou à des machines précises."),
    1433: ("mssql", "moyen", "Base SQL Server accessible depuis le réseau", "", "Limiter à des machines précises."),
    27017: ("mongodb", "élevé", "MongoDB accessible depuis le réseau", "Historiquement souvent ouvert sans authentification.",
            "Activer l'authentification et limiter l'accès."),
    6379: ("redis", "moyen", "Redis accessible depuis le réseau", "", "Définir un mot de passe et limiter l'accès."),
    11211: ("memcached", "élevé", "Memcached accessible", "Données lisibles et service utilisable pour des attaques par amplification.",
            "Limiter à localhost."),
    9200: ("elasticsearch", "élevé", "Elasticsearch accessible", "", "Activer l'authentification et limiter l'accès."),
    5984: ("couchdb", "moyen", "CouchDB accessible depuis le réseau", "", "Activer l'authentification."),
    2375: ("docker", "critique", "API Docker non chiffrée (2375)", "Donne un contrôle total de la machine.",
           "Désactiver l'API TCP ou la protéger par TLS."),
    1883: ("mqtt", "faible", "MQTT non chiffré", "Messages domotiques lisibles sur le réseau.", "Utiliser MQTT sur TLS (8883)."),
    37777: ("dvr", "moyen", "Port d'enregistreur vidéo (DVR/NVR)", "Ces interfaces sont fréquemment vulnérables.",
            "Mettre à jour le firmware, isoler dans un VLAN."),
    34567: ("dvr", "moyen", "Port d'enregistreur vidéo (DVR/NVR)", "Ces interfaces sont fréquemment vulnérables.",
            "Mettre à jour le firmware, isoler dans un VLAN."),
    554: ("rtsp", "faible", "Flux vidéo RTSP exposé", "Vérifier qu'il demande un mot de passe.", "Protéger le flux par identifiant."),
    8554: ("rtsp", "faible", "Flux vidéo RTSP exposé", "Vérifier qu'il demande un mot de passe.", "Protéger le flux par identifiant."),
}

# Motifs de bannière : (regex, id, gravité, titre, détail, recommandation)
BANNER_RULES = [
    (r"SSH-1\.(0|3|5)\b", "ssh1", "élevé", "SSH protocole 1", "Protocole obsolète et cassé.", "Passer au protocole 2."),
    (r"vsFTPd 2\.3\.4", "vsftpd-backdoor", "critique", "vsFTPd 2.3.4",
     "Version distribuée en 2011 avec une porte dérobée connue.", "Mettre à jour immédiatement."),
    (r"ProFTPD 1\.3\.3c", "proftpd-backdoor", "critique", "ProFTPD 1.3.3c",
     "Version distribuée en 2010 avec une porte dérobée connue.", "Mettre à jour immédiatement."),
    (r"Apache/(1\.|2\.[0-2]\b)", "apache-old", "moyen", "Serveur Apache ancien (fin de support)", "",
     "Mettre à jour vers une version maintenue."),
    (r"Microsoft-IIS/([1-7])\.", "iis-old", "moyen", "IIS obsolète", "Version sans support de sécurité.", "Mettre à jour Windows/IIS."),
    (r"Boa/0\.9", "boa", "moyen", "Serveur web Boa (abandonné depuis 2005)",
     "Très répandu dans les caméras et routeurs bas de gamme, sans correctifs.", "Mettre à jour le firmware ou remplacer l'appareil."),
    (r"nginx/(0\.|1\.[0-9]\.|1\.1[0-5]\.)", "nginx-old", "faible", "nginx ancien (< 1.16)", "", "Mettre à jour."),
    (r"lighttpd/1\.4\.[0-3]\d\b", "lighttpd-old", "faible", "lighttpd ancien", "", "Mettre à jour."),
]


def _version(text, pattern):
    m = re.search(pattern, text)
    return tuple(int(x) for x in m.groups()) if m else None


def banner_findings(dev):
    out, seen = [], set()
    for port, banner in (dev.get("banners") or {}).items():
        for rx, fid, sev, title, detail, remedy in BANNER_RULES:
            if re.search(rx, banner) and fid not in seen:
                seen.add(fid)
                out.append(finding(fid, sev, title, detail or f"Annonce : {banner[:60]}", remedy, int(port)))
        v = _version(banner, r"OpenSSH_(\d+)\.(\d+)")
        if v and v < (7, 4) and "openssh-old" not in seen:
            seen.add("openssh-old")
            out.append(finding("openssh-old", "faible", f"OpenSSH {v[0]}.{v[1]} annoncé (ancien)",
                               "Sur Linux, les correctifs peuvent être rétroportés : la version affichée ne prouve pas la faille.",
                               "Vérifier que le système est à jour.", int(port)))
    cert = dev.get("cert") or {}
    if cert.get("expired"):
        out.append(finding("tls-expired", "faible", "Certificat HTTPS expiré", f"Expiré le {cert.get('not_after', '?')} : les navigateurs affichent un avertissement.",
                           "Renouveler le certificat de l'appareil (ou le désactiver s'il n'est plus utilisé)."))
    server = (dev.get("ssdp") or {}).get("server", "")
    v = _version(server, r"Portable SDK for UPnP devices/(\d+)\.(\d+)\.(\d+)")
    if v and v < (1, 6, 18):
        out.append(finding("libupnp-old", "moyen", f"Pile UPnP ancienne (libupnp {'.'.join(map(str, v))})",
                           "Les versions antérieures à 1.6.18 ont des failles connues (CVE-2012-5958 et suivantes).",
                           "Mettre à jour le firmware ou désactiver UPnP."))
    return out


# ------------------------------------------------------------------ vérifications sans authentification
def _exchange(ip, port, payload, timeout=2.0, size=2048):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        if payload:
            s.sendall(payload)
        return s.recv(size)
    except OSError:
        return None
    finally:
        s.close()


def _http(ip, port, path, timeout=2.0):
    return _exchange(ip, port, f"GET {path} HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode(), timeout, 4096)


def probe_redis(ip, port=6379):
    r = _exchange(ip, port, b"PING\r\n")
    return None if r is None else "open" if r.startswith(b"+PONG") else "protected" if r[:1] == b"-" else None


def probe_memcached(ip, port=11211):
    r = _exchange(ip, port, b"version\r\n")
    return None if r is None else "open" if r.startswith(b"VERSION") else None


def probe_elasticsearch(ip, port=9200):
    r = _http(ip, port, "/")
    if not r:
        return None
    return "open" if b"cluster_name" in r else "protected" if b" 401 " in r.split(b"\r\n", 1)[0] + b" " else None


def probe_docker(ip, port=2375):
    r = _http(ip, port, "/version")
    return "open" if r and b"ApiVersion" in r else None


def probe_rtsp(ip, port):
    r = _exchange(ip, port, f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n".encode())
    if not r:
        return None
    first = r.split(b"\r\n", 1)[0]
    return "open" if b" 200" in first else "protected" if b" 401" in first else None


PROBES = {6379: probe_redis, 11211: probe_memcached, 9200: probe_elasticsearch, 2375: probe_docker,
          554: lambda ip, p=554: probe_rtsp(ip, 554), 8554: lambda ip, p=8554: probe_rtsp(ip, 8554)}


def active_probes(ip, ports):
    """Une requête de lecture sans identifiant par service concerné. -> {port: "open" | "protected"}."""
    out = {}
    for p in ports:
        fn = PROBES.get(p)
        if fn:
            try:
                r = fn(ip)
            except Exception:  # noqa: BLE001 - une sonde ne doit jamais faire échouer le scan
                log.debug("Sonde du port %s ratée sur %s", p, ip, exc_info=True)
                r = None
            if r:
                out[p] = r
    return out


OPEN_PROBE = {
    6379: finding("redis-open", "critique", "Redis accessible sans mot de passe",
                  "N'importe qui sur le réseau peut lire et modifier les données (et parfois exécuter du code).",
                  "Définir `requirepass` et limiter l'écoute à localhost.", 6379),
    11211: finding("memcached-open", "élevé", "Memcached répond sans authentification",
                   "Données lisibles et service exploitable pour des attaques par amplification.", "Limiter l'écoute à localhost.", 11211),
    9200: finding("elasticsearch-open", "critique", "Elasticsearch répond sans authentification",
                  "Toutes les données indexées sont lisibles.", "Activer l'authentification et limiter l'accès.", 9200),
    2375: finding("docker-open", "critique", "API Docker ouverte sans authentification",
                  "Contrôle total de la machine hôte.", "Désactiver l'API TCP ou la protéger par TLS.", 2375),
}
for _p in (554, 8554):
    OPEN_PROBE[_p] = finding("rtsp-open", "élevé", "Flux caméra accessible sans mot de passe",
                             "Le flux vidéo peut être regardé par n'importe qui sur le réseau.", "Activer l'authentification du flux.", _p)

OPEN_PROBE_BY_ID = {f['id']: f['title'] for f in OPEN_PROBE.values()}


def analyze(dev, probes=None):
    """Constats pour un appareil, du plus grave au moins grave."""
    probes, out, ids = probes or {}, [], set()

    def add(f):
        if f["id"] not in ids:
            ids.add(f["id"])
            out.append(f)
    for port in dev.get("ports", []):
        res = probes.get(port)
        if res == "open" and port in OPEN_PROBE:
            add(OPEN_PROBE[port])
            continue
        rule = PORT_RULES.get(port)
        if rule:
            fid, sev, title, detail, remedy = rule
            if res == "protected":  # le service demande une authentification : exposition réduite
                sev, detail = "faible", "Le service demande une authentification."
            add(finding(fid, sev, title, detail, remedy, port))
    ports, typ = set(dev.get("ports", [])), dev.get("type", "unknown")
    if 445 in ports and typ not in ("desktop", "laptop", "nas", "server", "unknown"):
        add(finding("smb-device", "moyen", f"Partage SMB sur un appareil de type « {typ} »",
                    "Un partage Windows n'est pas attendu ici (surface d'attaque inutile).", "Désactiver SMB si inutile.", 445))
    if typ in ADMIN_TYPES and ports & PLAIN_HTTP and 443 not in ports and 8443 not in ports:
        add(finding("http-admin", "faible", "Interface d'administration en HTTP non chiffré",
                    "Le mot de passe d'administration circule en clair sur le réseau.", "Activer HTTPS si l'appareil le permet."))
    for f in banner_findings(dev):
        add(f)
    out.sort(key=lambda f: (-RANK[f["severity"]], f["title"]))
    return out


_STATIC_TITLES = {"smb-device": "Partage SMB inattendu", "http-admin": "Administration en HTTP", "libupnp-old": "Pile UPnP ancienne",
                  "openssh-old": "OpenSSH ancien", "tls-expired": "Certificat HTTPS expiré"}


def title_of(rule_id):
    """Libellé lisible d'une règle à partir de son identifiant (« rtsp-open » -> « Flux caméra accessible sans mot de passe »)."""
    for fid, _sev, title, *_ in PORT_RULES.values():
        if fid == rule_id:
            return title
    if rule_id in OPEN_PROBE_BY_ID:
        return OPEN_PROBE_BY_ID[rule_id]
    for _rx, fid, _sev, title, *_ in BANNER_RULES:
        if fid == rule_id:
            return title
    return _STATIC_TITLES.get(rule_id, rule_id)


def worst(findings):
    """Gravité maximale d'une liste de constats ('' s'il n'y en a pas)."""
    return max((f["severity"] for f in findings or []), key=lambda s: RANK[s], default="")


def count_by_severity(devices):
    c = {s: 0 for s in reversed(SEVERITIES)}
    for d in devices:
        for f in d.get("security") or []:
            c[f["severity"]] += 1
    return c


def report_markdown(devices, networks=(), when=None):
    """Rapport d'exposition en Markdown, appareils les plus exposés d'abord."""
    when = time.localtime(when or time.time())
    analysed = [d for d in devices if d.get("security") is not None and d.get("online", True)]
    exposed = sorted((d for d in analysed if d["security"]), key=lambda d: (-RANK[worst(d["security"])], d.get("hostname") or d["ip"]))
    c = count_by_severity(analysed)
    lines = ["# Rapport d'exposition – Panther", "",
             f"Généré le {time.strftime('%d/%m/%Y à %H:%M', when)}"
             + (f" · réseaux analysés : {', '.join(networks)}" if networks else ""), "",
             "Analyse en lecture seule : ports ouverts, bannières et réponses sans identifiant. "
             "Aucun mot de passe n'a été essayé, aucune faille exploitée.", "",
             "## Résumé", "",
             f"- {len(analysed)} appareil(s) analysé(s), {len(exposed)} avec au moins un constat",
             "- " + " · ".join(f"{LABELS[s]} : {n}" for s, n in c.items() if n) if any(c.values()) else "- Aucun constat", ""]
    if exposed:
        lines += ["## Constats par appareil", ""]
    for d in exposed:
        lines += [f"### {d.get('hostname') or d['ip']} ({d['ip']})", "",
                  f"Type : {d.get('type', 'inconnu')} · gravité maximale : {LABELS[worst(d['security'])]}", ""]
        for f in d["security"]:
            lines.append(f"- **{LABELS[f['severity']]}** – {f['title']}" + (f" (port {f['port']})" if f.get("port") else ""))
            if f["detail"]:
                lines.append(f"  - {f['detail']}")
            if f["remedy"]:
                lines.append(f"  - À faire : {f['remedy']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
