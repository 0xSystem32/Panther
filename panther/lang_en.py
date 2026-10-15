"""Traductions anglaises (clé = texte français source). Contrôle : `python3 tools/i18n_check.py`."""

EN = {
    "Nom":
        "Name",
    "Type":
        "Type",
    "Système":
        "System",
    "Fabricant":
        "Vendor",
    "Réseau":
        "Network",
    "Scanner et carte de réseau local":
        "Local network scanner and mapper",
    "scanner et afficher un tableau (sans interface)":
        "scan and print a table (no interface)",
    "interface web locale au lieu de la fenêtre":
        "local web interface instead of the window",
    "plage supplémentaire à scanner (VLAN, sous-réseau routé), répétable":
        "extra range to scan (VLAN, routed subnet), repeatable",
    "profondeur du scan (mode --cli) ; ecoute = aucune sonde envoyée":
        "scan depth (--cli mode); ecoute = no probe sent",
    "interface réseau à scanner (mode --cli ; défaut : route par défaut)":
        "network interface to scan (--cli mode; default: default route)",
    "active l'analyse de sécurité en lecture seule (mode --cli) ; à n'utiliser que sur vos réseaux":
        "enable the read-only security analysis (--cli mode); only use it on your own networks",
    "réseau fictif pour essayer l'interface : aucun scan, aucune configuration lue ni écrite":
        "fictional network to try the interface: no scan, no configuration read or written",
    "langue de l'interface (défaut : celle du système)":
        "interface language (default: the system's)",
    "journal détaillé (aussi affiché sur la console)":
        "detailed log (also shown on the console)",
    "port de l'interface web":
        "web interface port",
    "Attention :":
        "Warning:",
    "Exposition":
        "Exposure",
    "aucun constat":
        "no findings",
    "--demo s'utilise avec la fenêtre (sans --cli ni --web).":
        "--demo is used with the window (without --cli or --web).",
    "Le mode démonstration demande PyQt6 ({e}).":
        "Demo mode needs PyQt6 ({e}).",
    "L'interface graphique demande PyQt6 ({e}).\nInstallez-le (pip install PyQt6) ou utilisez --cli / --web.":
        "The graphical interface needs PyQt6 ({e}).\nInstall it (pip install PyQt6) or use --cli / --web.",
    "Panther : {count} sur le réseau":
        "Panther: {count} on the network",
    "%d/%m/%Y %H:%M":
        "%Y-%m-%d %H:%M",
    "adresse e-mail invalide : {address}":
        "invalid e-mail address: {address}",
    "événement":
        "event",
    "événements":
        "events",
    "… et {n} autre(s)":
        "… and {n} more",
    "l'URL du webhook doit commencer par http:// ou https://":
        "the webhook URL must start with http:// or https://",
    "réglages e-mail incomplets (serveur, expéditeur et destinataire requis)":
        "incomplete e-mail settings (server, sender and recipient required)",
    "Message de test":
        "Test message",
    "Si vous lisez ceci, les alertes Panther fonctionnent.":
        "If you can read this, Panther alerts are working.",
    "le service a répondu {code}":
        "the service answered {code}",
    "envoi impossible : {reason}":
        "sending failed: {reason}",
    "connexion sécurisée refusée (certificat ou protocole) : {e}":
        "secure connection refused (certificate or protocol): {e}",
    "envoi impossible : {e}":
        "sending failed: {e}",
    "Nouvel appareil : {name}":
        "New device: {name}",
    "Nouvelle exposition ({severity}) : {name}":
        "New exposure ({severity}): {name}",
    "Appareil de confiance hors ligne : {name}":
        "Trusted device offline: {name}",
    " (port {port})":
        " (port {port})",
    "Adresse IP":
        "IP address",
    "Ports ouverts":
        "Open ports",
    "Constats de sécurité":
        "Security findings",
    "pc-invite":
        "guest-pc",
    "annonce mDNS":
        "mDNS announcement",
    "fabricant":
        "vendor",
    "portable-demo":
        "laptop-demo",
    "sw-salon":
        "sw-livingroom",
    "tv-salon":
        "tv-livingroom",
    "imprimante":
        "printer",
    "telephone-marie":
        "phone-mary",
    "tablette":
        "tablet",
    "enceinte-cuisine":
        "speaker-kitchen",
    "ampoule-salon":
        "bulb-livingroom",
    "ancien-pc":
        "old-pc",
    "cam-entree":
        "cam-entrance",
    "cam-jardin":
        "cam-garden",
    "enregistreur":
        "recorder",
    "Linux (cette machine)":
        "Linux (this machine)",
    "Adresse MAC":
        "MAC address",
    "Modèle":
        "Model",
    "VLAN":
        "VLAN",
    "Statut":
        "Status",
    "De confiance":
        "Trusted",
    "Groupe":
        "Group",
    "Étiquettes":
        "Tags",
    "Notes":
        "Notes",
    "Première apparition":
        "First seen",
    "Dernière apparition":
        "Last seen",
    "Exposition max.":
        "Max. exposure",
    "Services":
        "Services",
    "Adresses IPv6":
        "IPv6 addresses",
    "Certificat HTTPS":
        "HTTPS certificate",
    "Switch":
        "Switch",
    "Port du switch":
        "Switch port",
    "Confiance de la détection (%)":
        "Detection confidence (%)",
    "Indices de détection":
        "Detection clues",
    "Hors ligne":
        "Offline",
    "Nouveau":
        "New",
    "En ligne":
        "Online",
    "en ligne":
        "online",
    "aucun":
        "none",
    "auto-signé":
        "self-signed",
    "expiré":
        "expired",
    "expire le {date}":
        "expires on {date}",
    "Inconnu":
        "Unknown",
    "Firmware imprimante":
        "Printer firmware",
    "port d'impression 9100":
        "printing port 9100",
    "port d'impression IPP 631":
        "IPP printing port 631",
    "port d'impression LPD 515":
        "LPD printing port 515",
    "flux vidéo RTSP (554)":
        "RTSP video stream (554)",
    "port Google Cast (8009)":
        "Google Cast port (8009)",
    "port Google Cast (8008)":
        "Google Cast port (8008)",
    "contrôle Roku (8060)":
        "Roku control (8060)",
    "synchronisation iOS (62078)":
        "iOS sync (62078)",
    "ADB Android (5555)":
        "Android ADB (5555)",
    "Bureau à distance (3389)":
        "Remote Desktop (3389)",
    "RPC Windows (135)":
        "Windows RPC (135)",
    "partage SMB (445)":
        "SMB share (445)",
    "interface NAS (5000)":
        "NAS interface (5000)",
    "interface NAS (5001)":
        "NAS interface (5001)",
    "MySQL (3306)":
        "MySQL (3306)",
    "PostgreSQL (5432)":
        "PostgreSQL (5432)",
    "Redis (6379)":
        "Redis (6379)",
    "MongoDB (27017)":
        "MongoDB (27017)",
    "élevée":
        "high",
    "MAC aléatoire":
        "Random MAC",
    "Équipement réseau (Cisco/embarqué)":
        "Network equipment (Cisco/embedded)",
    "passerelle par défaut du réseau":
        "default gateway of the network",
    "équipement de commutation (table de ports SNMP ou voisin LLDP)":
        "switching equipment (SNMP port table or LLDP neighbour)",
    "WS-Discovery : caméra ONVIF":
        "WS-Discovery: ONVIF camera",
    "WS-Discovery : imprimante":
        "WS-Discovery: printer",
    "WS-Discovery : ordinateur":
        "WS-Discovery: computer",
    "NetBIOS : poste Windows / partage Samba":
        "NetBIOS: Windows workstation / Samba share",
    "UPnP : imprimante":
        "UPnP: printer",
    "UPnP : passerelle Internet":
        "UPnP: Internet gateway",
    "UPnP : lecteur multimédia":
        "UPnP: media player",
    "modèle":
        "model",
    "nom":
        "name",
    "certificat":
        "certificate",
    "fabricant Apple":
        "vendor Apple",
    "adresse MAC aléatoire (appareil mobile)":
        "random MAC address (mobile device)",
    "système iOS":
        "iOS system",
    "modèle « {model} » (défini par vous)":
        "model “{model}” (defined by you)",
    "moyenne":
        "medium",
    "faible":
        "low",
    "Cette machine":
        "This machine",
    "annonce mDNS {svc}":
        "mDNS announcement {svc}",
    "WS-Discovery : scanner":
        "WS-Discovery: scanner",
    "fabricant {vendor}":
        "vendor {vendor}",
    "système Android":
        "Android system",
    "aucun indice exploitable":
        "no usable clue",
    "{label} évocateur ({match})":
        "{label} suggestive ({match})",
    "système Windows":
        "Windows system",
    "système macOS":
        "macOS system",
    "Impossible de fusionner un appareil avec lui-même.":
        "Cannot merge a device with itself.",
    "fusionné avec {name} ({from_key})":
        "merged with {name} ({from_key})",
    "Appareil inconnu dans l'historique.":
        "Device unknown in the history.",
    "première analyse":
        "first analysis",
    "de retour sur le réseau":
        "back on the network",
    "absent de {misses} scans":
        "missing from {misses} scans",
    "même nom « {hostname} »":
        "same name “{hostname}”",
    "même type":
        "same type",
    "type compatible":
        "compatible type",
    "adresse MAC aléatoire (change d'un réseau à l'autre)":
        "random MAC address (changes from one network to another)",
    "Ordinateur":
        "Computer",
    "Portable":
        "Laptop",
    "Téléphone":
        "Phone",
    "Imprimante":
        "Printer",
    "Routeur / box":
        "Router / box",
    "TV / multimédia":
        "TV / media",
    "Tablette":
        "Tablet",
    "Console de jeux":
        "Game console",
    "Enceinte connectée":
        "Smart speaker",
    "Internet":
        "Internet",
    "Routeur du chemin":
        "Router on the path",
    "Saut sans réponse":
        "Unanswered hop",
    "Caméra":
        "Camera",
    "Serveur":
        "Server",
    "NAS":
        "NAS",
    "Objet connecté":
        "Smart device",
    "Non identifié":
        "Unidentified",
    "aucun appareil":
        "no device",
    "saut sans réponse":
        "unanswered hop",
    "virtuelle":
        "virtual",
    "Seul l'IPv4 est géré pour le moment.":
        "Only IPv4 is supported for now.",
    "Plage publique refusée : Panther ne scanne que des réseaux privés (10.x, 172.16-31.x, 192.168.x).":
        "Public range refused: Panther only scans private networks (10.x, 172.16-31.x, 192.168.x).",
    "Plage trop grande ({num_addresses} adresses, maximum {max_hosts} : /20).":
        "Range too large ({num_addresses} addresses, maximum {max_hosts}: /20).",
    "interface de votre routeur":
        "your router's interface",
    "« {text} » n'est pas une plage valide (exemple : 192.168.20.0/24).":
        "“{text}” is not a valid range (example: 192.168.20.0/24).",
    "~{hops} saut(s)":
        "~{hops} hop(s)",
    "seulement {rows_count} entrées (au moins {min_entries} attendues) : fichier invalide, base inchangée":
        "only {rows_count} entries (at least {min_entries} expected): invalid file, database unchanged",
    "fichier anormalement gros, abandon":
        "file abnormally large, aborting",
    "téléchargement impossible : {e}":
        "download failed: {e}",
    "Rapport de scan réseau":
        "Network scan report",
    "<b>{online}</b> appareil(s) en ligne · <b>{offline}</b> hors ligne · <b>{trusted}</b> de confiance · <b>{new}</b> nouveau(x) lors de ce scan":
        "<b>{online}</b> device(s) online · <b>{offline}</b> offline · <b>{trusted}</b> trusted · <b>{new}</b> new in this scan",
    "Résumé":
        "Summary",
    "{new} nouveau(x) · {gone} disparu(s) · {changed} modifié(s) · {same} inchangé(s)":
        "{new} new · {gone} gone · {changed} changed · {same} unchanged",
    "Appareils":
        "Devices",
    "Généré par Panther. À n'utiliser que sur des réseaux dont vous avez la responsabilité.":
        "Generated by Panther. Only use it on networks you are responsible for.",
    " · réseaux : {networks}":
        " · networks: {networks}",
    "Carte du réseau":
        "Network map",
    "Changements depuis le scan précédent":
        "Changes since the previous scan",
    "Disparu":
        "Gone",
    "Exposition (analyse en lecture seule)":
        "Exposure (read-only analysis)",
    "Gravité":
        "Severity",
    "Appareil":
        "Device",
    "Constat":
        "Finding",
    "Recommandation":
        "Recommendation",
    "Avertissements du scan":
        "Scan warnings",
    " sur {count} appareil(s) analysé(s). Aucun mot de passe n'a été essayé.":
        " on {count} analysed device(s). No password was tried.",
    "%d/%m/%Y à %H:%M":
        "%Y-%m-%d at %H:%M",
    "Modifié":
        "Changed",
    "Aucun constat":
        "No finding",
    "{field} : liste de ports (1-65535) attendue":
        "{field}: list of ports (1-65535) expected",
    "la règle doit être un objet":
        "the rule must be an object",
    "nom manquant":
        "missing name",
    "type « {kind} » inconnu (types : {types})":
        "unknown type “{kind}” (types: {types})",
    "match : au moins une condition est nécessaire (sinon la règle s'appliquerait à tout)":
        "match: at least one condition is required (otherwise the rule would apply to everything)",
    "fichier de règles : un objet JSON est attendu":
        "rules file: a JSON object is expected",
    "« rules » doit être une liste":
        "“rules” must be a list",
    "{count} règles : seules les {maximum} premières sont lues":
        "{count} rules: only the first {maximum} are read",
    "type « {kind} » inconnu":
        "unknown type “{kind}”",
    "aucun critère exploitable pour cet appareil (nom, fabricant, ports, services ou MAC)":
        "no usable criterion for this device (name, vendor, ports, services or MAC)",
    "{field} : motif refusé (quantificateurs imbriqués, risque de blocage)":
        "{field}: pattern refused (nested quantifiers, risk of hanging)",
    "mac_prefix : préfixe de 1 à 6 octets attendu":
        "mac_prefix: prefix of 1 to 6 bytes expected",
    "règle « {name} »":
        "rule “{name}”",
    "{field} : expression régulière invalide ({e})":
        "{field}: invalid regular expression ({e})",
    "règle {label} ignorée : {e}":
        "rule {label} ignored: {e}",
    "modèle n°{i} ignoré : {e}":
        "model #{i} ignored: {e}",
    "L'interface {dev} n'a pas d'adresse IPv4 : choisissez-en une autre.":
        "Interface {dev} has no IPv4 address: choose another one.",
    "Aucune route par défaut : êtes-vous connecté à un réseau ?":
        "No default route: are you connected to a network?",
    "connu : détails du dernier scan complet":
        "known: details from the last full scan",
    "Trop d'adresses à scanner ({hosts_count}) : réduisez les plages.":
        "Too many addresses to scan ({hosts_count}): reduce the ranges.",
    " Dernier saut atteint : {hop}.":
        " Last hop reached: {hop}.",
    "Réseau {n} : aucun hôte n'a répondu (routage entre VLAN ou pare-feu ?).{hint}":
        "Network {n}: no host answered (routing between VLANs or firewall?).{hint}",
    "adresse non privée":
        "non-private address",
    "SNMP {host} : {e}":
        "SNMP {host}: {e}",
    "Plage ignorée : {e}":
        "Range ignored: {e}",
    "Analyse de {ip} impossible : {e}":
        "Analysis of {ip} failed: {e}",
    "Tous les jours":
        "Every day",
    "Toutes les semaines":
        "Every week",
    "choisissez un dossier (chemin absolu)":
        "choose a folder (absolute path)",
    "dossier non inscriptible : {folder}":
        "folder not writable: {folder}",
    "fichier privé (droits 600)":
        "private file (mode 600)",
    "trousseau du système":
        "system keyring",
    "Partage SMB inattendu":
        "Unexpected SMB share",
    "Administration en HTTP":
        "Administration over HTTP",
    "Pile UPnP ancienne":
        "Outdated UPnP stack",
    "OpenSSH ancien":
        "Outdated OpenSSH",
    "Certificat HTTPS expiré":
        "Expired HTTPS certificate",
    "Critique":
        "Critical",
    "Élevé":
        "High",
    "Moyen":
        "Medium",
    "Faible":
        "Low",
    "Info":
        "Info",
    "Telnet activé":
        "Telnet enabled",
    "Le mot de passe et les commandes circulent en clair sur le réseau.":
        "The password and commands travel in clear text over the network.",
    "Désactiver Telnet et utiliser SSH.":
        "Disable Telnet and use SSH.",
    "Telnet activé (port 2323)":
        "Telnet enabled (port 2323)",
    "Le mot de passe et les commandes circulent en clair.":
        "The password and commands travel in clear text.",
    "FTP activé":
        "FTP enabled",
    "Identifiants et fichiers transmis en clair.":
        "Credentials and files are sent in clear text.",
    "Utiliser SFTP ou FTPS.":
        "Use SFTP or FTPS.",
    "Bureau à distance (RDP) accessible":
        "Remote Desktop (RDP) reachable",
    "Cible fréquente d'attaques par mots de passe.":
        "A frequent target of password attacks.",
    "Activer l'authentification NLA, limiter l'accès (VPN, pare-feu) ou désactiver.":
        "Enable NLA authentication, restrict access (VPN, firewall) or disable it.",
    "VNC accessible":
        "VNC reachable",
    "Prise de contrôle à distance souvent protégée par un mot de passe faible.":
        "Remote control often protected by a weak password.",
    "Passer par un tunnel SSH/VPN ou désactiver.":
        "Go through an SSH/VPN tunnel or disable it.",
    "Débogage Android (ADB) ouvert":
        "Android debugging (ADB) open",
    "Permet de contrôler l'appareil depuis le réseau.":
        "Allows controlling the device from the network.",
    "Désactiver le débogage réseau dans les options développeur.":
        "Disable network debugging in the developer options.",
    "RPC/portmap accessible":
        "RPC/portmap reachable",
    "Service d'administration réseau rarement nécessaire.":
        "Network administration service rarely needed.",
    "Filtrer ou désactiver.":
        "Filter or disable.",
    "Partage NFS accessible":
        "NFS share reachable",
    "Selon la configuration, accessible sans authentification.":
        "Depending on the configuration, reachable without authentication.",
    "Restreindre les clients autorisés.":
        "Restrict the allowed clients.",
    "Base MySQL accessible depuis le réseau":
        "MySQL database reachable from the network",
    "Limiter à localhost ou à des machines précises.":
        "Limit to localhost or to specific machines.",
    "Base PostgreSQL accessible depuis le réseau":
        "PostgreSQL database reachable from the network",
    "Base SQL Server accessible depuis le réseau":
        "SQL Server database reachable from the network",
    "Limiter à des machines précises.":
        "Limit to specific machines.",
    "MongoDB accessible depuis le réseau":
        "MongoDB reachable from the network",
    "Historiquement souvent ouvert sans authentification.":
        "Historically often left open without authentication.",
    "Activer l'authentification et limiter l'accès.":
        "Enable authentication and restrict access.",
    "Redis accessible depuis le réseau":
        "Redis reachable from the network",
    "Définir un mot de passe et limiter l'accès.":
        "Set a password and restrict access.",
    "Memcached accessible":
        "Memcached reachable",
    "Données lisibles et service utilisable pour des attaques par amplification.":
        "Readable data and a service usable for amplification attacks.",
    "Limiter à localhost.":
        "Limit to localhost.",
    "Elasticsearch accessible":
        "Elasticsearch reachable",
    "CouchDB accessible depuis le réseau":
        "CouchDB reachable from the network",
    "Activer l'authentification.":
        "Enable authentication.",
    "API Docker non chiffrée (2375)":
        "Unencrypted Docker API (2375)",
    "Donne un contrôle total de la machine.":
        "Gives full control of the machine.",
    "Désactiver l'API TCP ou la protéger par TLS.":
        "Disable the TCP API or protect it with TLS.",
    "MQTT non chiffré":
        "Unencrypted MQTT",
    "Messages domotiques lisibles sur le réseau.":
        "Home-automation messages readable on the network.",
    "Utiliser MQTT sur TLS (8883).":
        "Use MQTT over TLS (8883).",
    "Port d'enregistreur vidéo (DVR/NVR)":
        "Video recorder port (DVR/NVR)",
    "Ces interfaces sont fréquemment vulnérables.":
        "These interfaces are frequently vulnerable.",
    "Mettre à jour le firmware, isoler dans un VLAN.":
        "Update the firmware, isolate in a VLAN.",
    "Flux vidéo RTSP exposé":
        "RTSP video stream exposed",
    "Vérifier qu'il demande un mot de passe.":
        "Check that it asks for a password.",
    "Protéger le flux par identifiant.":
        "Protect the stream with credentials.",
    "SSH protocole 1":
        "SSH protocol 1",
    "Protocole obsolète et cassé.":
        "Obsolete and broken protocol.",
    "Passer au protocole 2.":
        "Switch to protocol 2.",
    "vsFTPd 2.3.4":
        "vsFTPd 2.3.4",
    "Version distribuée en 2011 avec une porte dérobée connue.":
        "Version distributed in 2011 with a known backdoor.",
    "Mettre à jour immédiatement.":
        "Update immediately.",
    "ProFTPD 1.3.3c":
        "ProFTPD 1.3.3c",
    "Version distribuée en 2010 avec une porte dérobée connue.":
        "Version distributed in 2010 with a known backdoor.",
    "Serveur Apache ancien (fin de support)":
        "Old Apache server (end of support)",
    "Mettre à jour vers une version maintenue.":
        "Update to a maintained version.",
    "IIS obsolète":
        "Obsolete IIS",
    "Version sans support de sécurité.":
        "Version without security support.",
    "Mettre à jour Windows/IIS.":
        "Update Windows/IIS.",
    "Serveur web Boa (abandonné depuis 2005)":
        "Boa web server (abandoned since 2005)",
    "Très répandu dans les caméras et routeurs bas de gamme, sans correctifs.":
        "Very common in low-end cameras and routers, without fixes.",
    "Mettre à jour le firmware ou remplacer l'appareil.":
        "Update the firmware or replace the device.",
    "nginx ancien (< 1.16)":
        "Old nginx (< 1.16)",
    "Mettre à jour.":
        "Update.",
    "lighttpd ancien":
        "Old lighttpd",
    "Redis accessible sans mot de passe":
        "Redis reachable without a password",
    "N'importe qui sur le réseau peut lire et modifier les données (et parfois exécuter du code).":
        "Anyone on the network can read and modify the data (and sometimes run code).",
    "Définir `requirepass` et limiter l'écoute à localhost.":
        "Set `requirepass` and limit listening to localhost.",
    "Memcached répond sans authentification":
        "Memcached answers without authentication",
    "Données lisibles et service exploitable pour des attaques par amplification.":
        "Readable data and a service exploitable for amplification attacks.",
    "Limiter l'écoute à localhost.":
        "Limit listening to localhost.",
    "Elasticsearch répond sans authentification":
        "Elasticsearch answers without authentication",
    "Toutes les données indexées sont lisibles.":
        "All indexed data is readable.",
    "API Docker ouverte sans authentification":
        "Docker API open without authentication",
    "Contrôle total de la machine hôte.":
        "Full control of the host machine.",
    "Flux caméra accessible sans mot de passe":
        "Camera stream reachable without a password",
    "Le flux vidéo peut être regardé par n'importe qui sur le réseau.":
        "The video stream can be watched by anyone on the network.",
    "Activer l'authentification du flux.":
        "Enable stream authentication.",
    "# Rapport d'exposition – Panther":
        "# Exposure report – Panther",
    "Analyse en lecture seule : ports ouverts, bannières et réponses sans identifiant. Aucun mot de passe n'a été essayé, aucune faille exploitée.":
        "Read-only analysis: open ports, banners and answers without credentials. No password was tried, no vulnerability exploited.",
    "## Résumé":
        "## Summary",
    "- {analysed} appareil(s) analysé(s), {exposed} avec au moins un constat":
        "- {analysed} device(s) analysed, {exposed} with at least one finding",
    "Généré le {stamp}":
        "Generated on {stamp}",
    "- Aucun constat":
        "- No finding",
    "## Constats par appareil":
        "## Findings by device",
    "Type : {type} · gravité maximale : {severity}":
        "Type: {type} · highest severity: {severity}",
    "Expiré le {not_after} : les navigateurs affichent un avertissement.":
        "Expired on {not_after}: browsers show a warning.",
    "Renouveler le certificat de l'appareil (ou le désactiver s'il n'est plus utilisé).":
        "Renew the device's certificate (or disable it if it is no longer used).",
    "Pile UPnP ancienne (libupnp {version})":
        "Outdated UPnP stack (libupnp {version})",
    "Les versions antérieures à 1.6.18 ont des failles connues (CVE-2012-5958 et suivantes).":
        "Versions before 1.6.18 have known vulnerabilities (CVE-2012-5958 and others).",
    "Mettre à jour le firmware ou désactiver UPnP.":
        "Update the firmware or disable UPnP.",
    "Partage SMB sur un appareil de type « {typ} »":
        "SMB share on a device of type “{typ}”",
    "Un partage Windows n'est pas attendu ici (surface d'attaque inutile).":
        "A Windows share is not expected here (needless attack surface).",
    "Désactiver SMB si inutile.":
        "Disable SMB if not needed.",
    "Interface d'administration en HTTP non chiffré":
        "Administration interface over unencrypted HTTP",
    "Le mot de passe d'administration circule en clair sur le réseau.":
        "The administration password travels in clear text over the network.",
    "Activer HTTPS si l'appareil le permet.":
        "Enable HTTPS if the device supports it.",
    " · réseaux analysés : {networks}":
        " · networks analysed: {networks}",
    "OpenSSH {major}.{minor} annoncé (ancien)":
        "OpenSSH {major}.{minor} announced (old)",
    "Sur Linux, les correctifs peuvent être rétroportés : la version affichée ne prouve pas la faille.":
        "On Linux, fixes can be backported: the displayed version does not prove the flaw.",
    "Vérifier que le système est à jour.":
        "Check that the system is up to date.",
    "Le service demande une authentification.":
        "The service requires authentication.",
    "  - À faire : {remedy}":
        "  - To do: {remedy}",
    "inconnu":
        "unknown",
    "Annonce : {banner}":
        "Announces: {banner}",
    "Lancer le scan":
        "Start scan",
    "Cliquez sur un appareil pour voir ses détails.":
        "Click a device to see its details.",
    "cette machine":
        "this machine",
    "Bannières":
        "Banners",
    "{cidr} · passerelle {gateway}":
        "{cidr} · gateway {gateway}",
    "{n} appareil(s)":
        "{n} device(s)",
    "Scan en cours… {progress}%":
        "Scanning… {progress}%",
    "Erreur : {error}":
        "Error: {error}",
    "Scan en cours, les appareils apparaissent au fur et à mesure.":
        "Scan in progress, devices appear as they are found.",
    "Panther → http://127.0.0.1:{port}  (Ctrl+C pour quitter)":
        "Panther → http://127.0.0.1:{port}  (Ctrl+C to quit)",
    "accès refusé":
        "access denied",
    "message SNMP invalide":
        "invalid SNMP message",
    "pas de réponse (communauté incorrecte, SNMP désactivé ou filtré)":
        "no answer (wrong community, SNMP disabled or filtered)",
    "port {bp}":
        "port {bp}",
    "paquet tronqué":
        "truncated packet",
    "longueur BER invalide":
        "invalid BER length",
    "erreur SNMP {err}":
        "SNMP error {err}",
    "niveau de sécurité non pris en charge":
        "security level not supported",
    "hors de la fenêtre de temps":
        "outside the time window",
    "utilisateur inconnu":
        "unknown user",
    "moteur inconnu":
        "unknown engine",
    "authentification refusée (mot de passe ou algorithme incorrect)":
        "authentication refused (wrong password or algorithm)",
    "déchiffrement refusé":
        "decryption refused",
    "pas de réponse (utilisateur ou mot de passe incorrect, SNMP v3 désactivé ou filtré)":
        "no answer (wrong user or password, SNMP v3 disabled or filtered)",
    "SNMP v3 : {why}":
        "SNMP v3: {why}",
    "Démonstration : réseau fictif, rien n'est scanné ni envoyé. Lancez le scan pour voir la progression, essayez les cartes, le journal et la comparaison.":
        "Demo: fictional network, nothing is scanned or sent. Start the scan to see the progress, and try the maps, the log and the comparison.",
    "Historique effacé":
        "History erased",
    "{name} fusionné dans {other}":
        "{name} merged into {other}",
    "Choisissez l'appareil hors ligne qui est en réalité « {name} » (par exemple avec une ancienne adresse MAC). Son historique, sa confiance et ses noms seront regroupés ici.":
        "Choose the offline device that is actually “{name}” (for example with an old MAC address). Its history, trust and names will be combined here.",
    "« {name} » (hors ligne) est-il un appareil actuellement en ligne ? Choisissez-le : l'historique de l'appareil hors ligne sera regroupé avec le sien.":
        "Is “{name}” (offline) a device that is currently online? Choose it: the offline device's history will be combined with its own.",
    "Fusionner des appareils":
        "Merge devices",
    "Paquet de réveil envoyé à {name} ({mac}) : {n} envoi(s). Il faut que Wake-on-LAN soit activé sur l'appareil (en général en Ethernet, rarement en Wi-Fi).":
        "Wake packet sent to {name} ({mac}): {n} send(s). Wake-on-LAN must be enabled on the device (usually over Ethernet, rarely over Wi-Fi).",
    "{todo_count} appareil(s) marqués de confiance":
        "{todo_count} device(s) marked as trusted",
    "Modifier le nom / le type…":
        "Edit name / type…",
    "Étiquettes, notes et groupe…":
        "Tags, notes and group…",
    "Créer une règle de détection…":
        "Create a detection rule…",
    "Étiquettes et notes enregistrées":
        "Tags and notes saved",
    "Règle de détection":
        "Detection rule",
    "Sélectionnez d'abord un appareil.":
        "Select a device first.",
    "Règle enregistrée et appliquée aux appareils affichés":
        "Rule saved and applied to the displayed devices",
    "Comparer deux scans":
        "Compare two scans",
    "Il faut au moins deux scans enregistrés. Lancez un scan (ou deux) : chaque scan terminé est conservé pour la comparaison.":
        "At least two saved scans are needed. Run a scan (or two): every finished scan is kept for comparison.",
    "Fusion":
        "Merge",
    "Seul un appareil hors ligne peut être fusionné dans un autre appareil.":
        "Only an offline device can be merged into another device.",
    "Aucun appareil à fusionner.":
        "No device to merge.",
    "Doublons":
        "Duplicates",
    "Aucun doublon probable : aucun appareil récent ne ressemble à un appareil hors ligne.":
        "No likely duplicate: no recent device looks like an offline device.",
    "Démonstration":
        "Demo",
    "Mode démonstration : aucun paquet n'est envoyé sur le réseau.":
        "Demo mode: no packet is sent on the network.",
    "Wake-on-LAN":
        "Wake-on-LAN",
    "« {name} » utilise une adresse MAC aléatoire (adresse privée Wi-Fi) : elle ne peut pas servir à le réveiller. Seule l'adresse matérielle d'origine de la carte réseau le peut.":
        "“{name}” uses a random MAC address (private Wi-Fi address): it cannot be used to wake it. Only the network card's original hardware address can.",
    "Journal d'erreurs":
        "Error log",
    "Aucune erreur enregistrée pour le moment.\n\nEmplacement : {path}":
        "No error recorded so far.\n\nLocation: {path}",
    "{hostname} : ":
        "{hostname}: ",
    "Panther":
        "Panther",
    "Aucun appareil en ligne à valider.":
        "No online device to validate.",
    "Faire confiance":
        "Trust",
    "Marquer ces {todo_count} appareil(s) comme de confiance ?\n\n{names}\n\nVérifiez qu'ils sont tous reconnus : un intrus présent maintenant serait validé.":
        "Mark these {todo_count} device(s) as trusted?\n\n{names}\n\nCheck that you recognise all of them: an intruder present right now would be validated.",
    "Retirer la confiance":
        "Remove trust",
    "Marquer comme appareil de confiance":
        "Mark as trusted device",
    "Réveiller (Wake-on-LAN)":
        "Wake up (Wake-on-LAN)",
    "Oublier cet appareil":
        "Forget this device",
    "Rétablir la détection automatique":
        "Restore automatic detection",
    "Réglage enregistré":
        "Setting saved",
    "Détection automatique rétablie":
        "Automatic detection restored",
    "Durée de conservation enregistrée":
        "Retention saved",
    "Historique indisponible :\n{e}":
        "History unavailable:\n{e}",
    "Fusion impossible :\n{e}":
        "Merge failed:\n{e}",
    "Impossible d'enregistrer la confiance :\n{e}":
        "Could not save trust:\n{e}",
    "marqué de confiance":
        "marked as trusted",
    "confiance retirée":
        "trust removed",
    "Oublier":
        "Forget",
    "Oublier {hostname} et son historique ?":
        "Forget {hostname} and its history?",
    "Impossible d'oublier l'appareil :\n{e}":
        "Could not forget the device:\n{e}",
    "Fusionner avec un appareil hors ligne…":
        "Merge with an offline device…",
    "Fusionner dans un appareil en ligne…":
        "Merge into an online device…",
    "Impossible d'enregistrer le réglage :\n{e}":
        "Could not save the setting:\n{e}",
    "Impossible d'enregistrer :\n{e}":
        "Could not save:\n{e}",
    "Impossible d'enregistrer la règle :\n{e}":
        "Could not save the rule:\n{e}",
    "Modifier l'appareil":
        "Edit device",
    "Détection automatique ({labels_label})":
        "Automatic detection ({labels_label})",
    "Mémorisé pour l'adresse MAC {mac}.":
        "Saved for MAC address {mac}.",
    "Enregistrer":
        "Save",
    "Annuler":
        "Cancel",
    "{when}  ·  {depth}  ·  {count} appareil(s)":
        "{when}  ·  {depth}  ·  {count} device(s)",
    "Scan de départ":
        "From scan",
    "Scan d'arrivée":
        "To scan",
    "Fermer":
        "Close",
    "{new}  ·  {gone}  ·  {changed}  ·  {same} inchangé(s)":
        "{new}  ·  {gone}  ·  {changed}  ·  {same} unchanged",
    "Fusionner":
        "Merge",
    "Doublons probables":
        "Likely duplicates",
    "Un appareil récent ressemble à un appareil hors ligne (même nom, même type, adresse MAC aléatoire). Si c'est le même, fusionnez-les : l'historique, la confiance et les noms seront regroupés.":
        "A recent device looks like an offline device (same name, same type, random MAC address). If it is the same one, merge them: history, trust and names will be combined.",
    "Fusionner la sélection":
        "Merge selection",
    "ex. Salon, Bureau, Invités…":
        "e.g. Living room, Office, Guests…",
    "Notes libres : emplacement, propriétaire, numéro de série…":
        "Free notes: location, owner, serial number…",
    "Nom de l'appareil":
        "Device name",
    "Services annoncés (mDNS)":
        "Advertised services (mDNS)",
    "Préfixe de l'adresse MAC (fabricant)":
        "MAC address prefix (vendor)",
    "Créer une règle de détection":
        "Create a detection rule",
    "Quand un appareil ressemble à « {hostname} », Panther le classera dans le type choisi. Cochez ce qui doit être commun (plus de critères = règle plus précise).":
        "When a device looks like “{hostname}”, Panther will classify it as the chosen type. Tick what must match (more criteria = a more precise rule).",
    "Nom de la règle":
        "Rule name",
    "Enregistrer la règle":
        "Save rule",
    "Règles de détection personnalisées":
        "Custom detection rules",
    "Fichier : {path}\n{rules} · {models}. Chaque règle ajoute des points au type indiqué ; la détection intégrée garde son rôle (\"force\": true impose le type).":
        "File: {path}\n{rules} · {models}. Each rule adds points to the given type; built-in detection keeps its role (\"force\": true imposes the type).",
    "Exporter les règles":
        "Export rules",
    "Importer des règles":
        "Import rules",
    "Import":
        "Import",
    "Historique et données":
        "History and data",
    "Conserver la présence détaillée":
        "Keep detailed presence",
    "Conserver le journal":
        "Keep the log",
    "La purge supprime aussi les instantanés qui servent à comparer deux scans. Les appareils connus, leur confiance et leurs noms sont conservés.":
        "Purging also deletes the snapshots used to compare two scans. Known devices, their trust and their names are kept.",
    "Purger maintenant":
        "Purge now",
    "Effacer aussi les noms et types choisis à la main":
        "Also erase names and types set by hand",
    "Effacer aussi le journal d'erreurs (adresses et noms d'appareils)":
        "Also erase the error log (device addresses and names)",
    "Tout effacer…":
        "Erase everything…",
    "Enregistrer et fermer":
        "Save and close",
    "Effacer l'historique supprime les appareils connus, la présence, le journal, les comparaisons, les positions de la carte, les étiquettes et les alias. Les règles de détection, les alertes et les secrets ne sont pas touchés.":
        "Erasing the history deletes known devices, presence, the log, comparisons, map positions, tags and aliases. Detection rules, alerts and secrets are not touched.",
    "  (le plus ancien : {when})":
        "  (oldest: {when})",
    "Fichier : {path}\nTaille : {human_size}\nAppareils connus : {devices}\nScans conservés : {scans}{oldest}\nÉvénements du journal : {events}":
        "File: {path}\nSize: {human_size}\nKnown devices: {devices}\nScans kept: {scans}{oldest}\nLog events: {events}",
    "{scans}, {events}.":
        "{scans}, {events}.",
    "Changement":
        "Change",
    "Détail":
        "Detail",
    "Choisissez deux scans différents.":
        "Choose two different scans.",
    "Instantané indisponible pour l'un des scans.":
        "Snapshot unavailable for one of the scans.",
    "Appareil actuel":
        "Current device",
    "Ressemble à (hors ligne)":
        "Looks like (offline)",
    "Pourquoi":
        "Why",
    "Étiquettes et groupe : {count} appareils":
        "Tags and group: {count} devices",
    "Étiquettes et notes : {hostname}":
        "Tags and notes: {hostname}",
    "étiquettes à ajouter à chacun, séparées par des virgules":
        "tags to add to each one, separated by commas",
    "ex. enfants, domotique, à surveiller":
        "e.g. kids, home automation, to watch",
    "Les étiquettes saisies s'ajoutent à celles de chaque appareil ; un groupe vide laisse le groupe actuel.":
        "The tags you enter are added to those of each device; an empty group keeps the current group.",
    "Filtrez ensuite avec « tag:enfants » ou « groupe:salon » dans la barre de recherche. Jusqu'à {max_tags} étiquettes de {max_tag_len} caractères.":
        "Then filter with “tag:kids” or “group:livingroom” in the search bar. Up to {max_tags} tags of {max_tag_len} characters.",
    "Règle":
        "Rule",
    "Conditions":
        "Conditions",
    "Modifier le fichier":
        "Edit file",
    "Recharger":
        "Reload",
    "Créer un exemple":
        "Create an example",
    "Supprimer la règle":
        "Delete rule",
    "Exporter…":
        "Export…",
    "Importer…":
        "Import…",
    "{count}.":
        "{count}.",
    " jours":
        " days",
    "Tout effacer ?":
        "Erase everything?",
    "Supprimer définitivement tout l'historique de Panther ?\n\nCette action est irréversible.":
        "Permanently delete all of Panther's history?\n\nThis cannot be undone.",
    "nom choisi effacé":
        "name set by hand erased",
    "noms choisis effacés":
        "names set by hand erased",
    "journal vidé ({size})":
        "log emptied ({size})",
    "nouveau":
        "new",
    "nouveaux":
        "new",
    "disparu":
        "gone",
    "disparus":
        "gone",
    "modifié":
        "changed",
    "modifiés":
        "changed",
    "{hostname}  ·  {ip}":
        "{hostname}  ·  {ip}",
    "Règle : ":
        "Rule: ",
    "règle valide":
        "valid rule",
    "règles valides":
        "valid rules",
    "modèle personnalisé":
        "custom model",
    "modèles personnalisés":
        "custom models",
    "Impossible d'écrire le fichier :\n{e}":
        "Could not write the file:\n{e}",
    "Supprimer":
        "Delete",
    "Supprimer la règle « {name} » ?":
        "Delete the rule “{name}”?",
    "Import impossible :\n{e}":
        "Import failed:\n{e}",
    "Effacement impossible : {e}":
        "Erase failed: {e}",
    "Historique indisponible : {e}":
        "History unavailable: {e}",
    "Purge impossible : {e}":
        "Purge failed: {e}",
    "scan supprimé":
        "scan deleted",
    "scans supprimés":
        "scans deleted",
    "événement supprimé":
        "event deleted",
    "événements supprimés":
        "events deleted",
    "  ·  hors ligne, vu {seen_label}":
        "  ·  offline, seen {seen_label}",
    "Impossible de modifier le fichier :\n{e}":
        "Could not modify the file:\n{e}",
    "Export impossible :\n{e}":
        "Export failed:\n{e}",
    "règle importée":
        "rule imported",
    "règles importées":
        "rules imported",
    "\n\nÉcartées :\n":
        "\n\nDiscarded:\n",
    "ligne supprimée":
        "row deleted",
    "lignes supprimées":
        "rows deleted",
    "Exporter la carte":
        "Export map",
    "Image PNG (*.png);;Image vectorielle SVG (*.svg)":
        "PNG image (*.png);;SVG vector image (*.svg)",
    "Carte exportée : {basename}":
        "Map exported: {basename}",
    "Positions de cette disposition réinitialisées":
        "Positions of this layout reset",
    "la carte est vide : lancez d'abord un scan":
        "the map is empty: run a scan first",
    "Panther – carte du réseau":
        "Panther – network map",
    "impossible d'écrire {path}":
        "cannot write {path}",
    "La carte est vide : lancez d'abord un scan.":
        "The map is empty: run a scan first.",
    "Impossible de réinitialiser les positions :\n{e}":
        "Could not reset positions:\n{e}",
    "  ·  aucun appareil":
        "  ·  no device",
    "de confiance":
        "trusted",
    "non vérifié":
        "unverified",
    "Flèches : changer d'appareil. Maj + flèches : ajouter à la sélection. + et − : zoom. Entrée : modifier l'appareil. Échap : tout désélectionner. L'onglet Appareils liste les mêmes appareils.":
        "Arrow keys: change device. Shift + arrows: add to the selection. + and −: zoom. Enter: edit the device. Esc: clear the selection. The Devices tab lists the same devices.",
    "\nSwitch : {switch}  ·  {port}":
        "\nSwitch: {switch}  ·  {port}",
    "hors ligne · vu {seen}":
        "offline · seen {seen}",
    "Étiquettes et groupe enregistrés pour {count}":
        "Tags and group saved for {count}",
    "Étiquettes et groupe de la sélection…":
        "Tags and group of the selection…",
    "{count} sélectionnés":
        "{count} selected",
    "Confiance":
        "Trust",
    "{trusted} sur {total} de confiance":
        "{trusted} of {total} trusted",
    "\nÀ faire : {remedy}":
        "\nTo do: {remedy}",
    "{count} marqués de confiance":
        "{count} marked as trusted",
    "Confiance retirée à {count}":
        "Trust removed from {count}",
    "Retirer la confiance à la sélection":
        "Remove trust from the selection",
    "Marquer la sélection comme de confiance":
        "Mark the selection as trusted",
    "Gravité maximale : {severity}":
        "Highest severity: {severity}",
    "TTL":
        "TTL",
    "Ports":
        "Ports",
    "Réseau local":
        "Local network",
    "Aucune sélection":
        "No selection",
    "  (port {port})":
        "  (port {port})",
    "appareil":
        "device",
    "appareils":
        "devices",
    "Hors ligne · dernière apparition le {date}":
        "Offline · last seen on {date}",
    "certificat sans nom":
        "unnamed certificate",
    "{switch}  ·  {switch_port}":
        "{switch}  ·  {switch_port}",
    "Chemin":
        "Path",
    "Port {p}":
        "Port {p}",
    "Annonces":
        "Announcements",
    "Détection":
        "Detection",
    "{labels_label} · confiance {confidence_label} ({conf} %)":
        "{labels_label} · {confidence_label} confidence ({conf} %)",
    "Indices":
        "Clues",
    "Analyse":
        "Analysis",
    "Présence confirmée ; détails repris du dernier scan complet":
        "Presence confirmed; details taken from the last full scan",
    "Non vérifié":
        "Unverified",
    "Rôle":
        "Role",
    "Passerelle par défaut":
        "Default gateway",
    "Machine locale":
        "Local machine",
    "Sous-réseau":
        "Subnet",
    "Passerelle":
        "Gateway",
    "Interface":
        "Interface",
    "Lancez un scan pour cartographier le réseau auquel vous êtes connecté.":
        "Run a scan to map the network you are connected to.",
    "Nouvel appareil (première apparition)":
        "New device (first seen)",
    "  ·  VLAN {vlan}":
        "  ·  VLAN {vlan}",
    "à l'instant":
        "just now",
    "Présence":
        "Presence",
    "Latence":
        "Latency",
    "Latence (ms)":
        "Latency (ms)",
    "moy. {avg} · min {low} · max {high} · {missed} sans réponse":
        "avg {avg} · min {low} · max {high} · {missed} unanswered",
    "Disponibilité":
        "Availability",
    "{uptime} % sur 7 jours":
        "{uptime} % over 7 days",
    "Historique":
        "History",
    "{on} en ligne":
        "{on} online",
    "Nouveaux":
        "New",
    "Doublons possibles":
        "Possible duplicates",
    "Sécurité":
        "Security",
    "Attention":
        "Warning",
    "SNMP":
        "SNMP",
    "{name} : {arp} entrées ARP, {fdb} adresses MAC":
        "{name}: {arp} ARP entries, {fdb} MAC addresses",
    "Voisins":
        "Neighbours",
    "  ·  expiré le {not_after}":
        "  ·  expired on {not_after}",
    "  ·  {devices_count} hors ligne":
        "  ·  {devices_count} offline",
    "LLDP/CDP : droits insuffisants (voir le README).":
        "LLDP/CDP: insufficient privileges (see the README).",
    "  ·  émis par {issuer}":
        "  ·  issued by {issuer}",
    "  ·  auto-signé":
        "  ·  self-signed",
    "  ·  expire le {not_after}":
        "  ·  expires {not_after}",
    "Aucun voisin LLDP/CDP annoncé.":
        "No LLDP/CDP neighbour announced.",
    "Téléchargement de la base des fabricants…":
        "Downloading the vendor database…",
    "Base des fabricants mise à jour : {n} entrées":
        "Vendor database updated: {n} entries",
    "Base des fabricants":
        "Vendor database",
    "{n} fabricants enregistrés. Les nouveaux noms apparaîtront au prochain scan.":
        "{n} vendors saved. New names will appear at the next scan.",
    "Mise à jour de la base des fabricants impossible":
        "Could not update the vendor database",
    "La base n'a pas été modifiée.\n\n{message}":
        "The database was not modified.\n\n{message}",
    "Réglages enregistrés":
        "Settings saved",
    "Mode démonstration : aucun téléchargement n'est effectué.":
        "Demo mode: nothing is downloaded.",
    "Mettre à jour la base des fabricants":
        "Update the vendor database",
    "Panther va télécharger le registre officiel des fabricants (IEEE) depuis\n{url}\n(environ 6 Mo) et l'enregistrer dans :\n{user_path}\n\nAucune donnée de votre réseau n'est envoyée. Continuer ?":
        "Panther will download the official vendor registry (IEEE) from\n{url}\n(about 6 MB) and save it to:\n{user_path}\n\nNo data from your network is sent. Continue?",
    "Langue":
        "Language",
    "La langue sera appliquée au prochain démarrage de Panther.":
        "The language will be applied the next time Panther starts.",
    "Réseaux ({n})":
        "Networks ({n})",
    "Réseaux…":
        "Networks…",
    "  ·  +{n} autre(s) réseau(x)":
        "  ·  +{n} other network(s)",
    "  ·  passerelle {gateway}":
        "  ·  gateway {gateway}",
    "  ·  sans passerelle":
        "  ·  no gateway",
    "  {cidr}{vlan}{gw}  ·  {iface}{kind}{extra}":
        "  {cidr}{vlan}{gw}  ·  {iface}{kind}{extra}",
    "Plages mises à jour : relancez le scan pour les prendre en compte.":
        "Ranges updated: run the scan again to apply them.",
    "Exporter le rapport":
        "Export report",
    "Rapport PDF exporté : {basename}":
        "PDF report exported: {basename}",
    "Rapport planifié enregistré : {basename}":
        "Scheduled report saved: {basename}",
    "Exporter":
        "Export",
    "Exporté : {basename}":
        "Exported: {basename}",
    "Rapport PDF":
        "PDF report",
    "Aucun résultat à exporter : lancez d'abord un scan.":
        "No result to export: run a scan first.",
    "Rapports planifiés : réglages enregistrés":
        "Scheduled reports: settings saved",
    "Export":
        "Export",
    "Impossible d'écrire le PDF :\n{e}":
        "Could not write the PDF:\n{e}",
    "Rapport planifié impossible : %s":
        "Scheduled report failed: %s",
    "Rapport planifié impossible : {e}":
        "Scheduled report failed: {e}",
    "Enregistrer la configuration actuelle…":
        "Save the current setup…",
    "Supprimer un profil":
        "Delete a profile",
    "Profil « {name} » enregistré":
        "Profile “{name}” saved",
    "Profil « {name} » supprimé":
        "Profile “{name}” deleted",
    "Relancer le scan":
        "Scan again",
    "Écoute terminée en {elapsed} s":
        "Listening finished in {elapsed} s",
    "  ·  première analyse : {online_count} appareil(s) enregistrés comme connus":
        "  ·  first analysis: {online_count} device(s) saved as known",
    "  ·  analyse de sécurité : référence enregistrée":
        "  ·  security analysis: baseline saved",
    "Automatique":
        "Automatic",
    "Arrêt en cours…":
        "Stopping…",
    "Profil de scan":
        "Scan profile",
    "Nom du profil :":
        "Profile name:",
    "analyse de sécurité non activée (consentement à donner dans le menu Sécurité)":
        "security analysis not enabled (consent must be given in the Security menu)",
    "communauté SNMP inconnue pour {hosts}":
        "unknown SNMP community for {hosts}",
    "Profil « {name} » appliqué : relancez le scan":
        "Profile “{name}” applied: start the scan again",
    "Découverte des hôtes":
        "Discovering hosts",
    "Analyse des appareils":
        "Analysing devices",
    "{phase}  ·  {elapsed} s  ·  profondeur {depth}":
        "{phase}  ·  {elapsed} s  ·  depth {depth}",
    "  ·  historique indisponible ({e})":
        "  ·  history unavailable ({e})",
    "Scan de présence terminé en {elapsed} s":
        "Presence scan finished in {elapsed} s",
    "Scan terminé en {elapsed} s":
        "Scan finished in {elapsed} s",
    "nouvelle exposition":
        "new exposure",
    "nouvelles expositions":
        "new exposures",
    "exposition corrigée":
        "exposure fixed",
    "expositions corrigées":
        "exposures fixed",
    " (menu Scan)":
        " (Scan menu)",
    "{iface}  ·  {link_labels_label}":
        "{iface}  ·  {link_labels_label}",
    "Écoute seule : Panther n'enverra plus rien sur le réseau (il lit la table des voisins du noyau et les baux DHCP)":
        "Listen-only: Panther will no longer send anything on the network (it reads the kernel's neighbour table and DHCP leases)",
    "Écoute seule désactivée":
        "Listen-only disabled",
    "Scan auto : toutes les {minutes} min   ":
        "Auto scan: every {minutes} min   ",
    "Impossible d'enregistrer le profil : {e}":
        "Could not save the profile: {e}",
    "Arrêter le scan ({progress} %)":
        "Stop scan ({progress} %)",
    "Historique indisponible":
        "History unavailable",
    "  ·  {last_new_count} nouvel appareil":
        "  ·  {last_new_count} new device",
    "Panther : nouvelle exposition":
        "Panther: new exposure",
    "doublon possible":
        "possible duplicate",
    "doublons possibles":
        "possible duplicates",
    "Alerte non envoyée : ":
        "Alert not sent: ",
    "Scan interrompu : {devices_count} appareil(s) analysé(s) avant l'arrêt":
        "Scan interrupted: {devices_count} device(s) analysed before stopping",
    "Scan interrompu pendant la découverte : aucun appareil n'avait encore été analysé":
        "Scan interrupted during discovery: no device had been analysed yet",
    "Panther : nouvel appareil sur le réseau":
        "Panther: new device on the network",
    "{hostname} : {title}":
        "{hostname}: {title}",
    "  ·  {w} avertissement(s)":
        "  ·  {w} warning(s)",
    "Alerte envoyée (":
        "Alert sent (",
    "  ·  {off} hors ligne":
        "  ·  {off} offline",
    "JSON générique (Home Assistant, scripts…)":
        "Generic JSON (Home Assistant, scripts…)",
    "Alertes : webhook et e-mail":
        "Alerts: webhook and e-mail",
    "Activer les alertes":
        "Enable alerts",
    "Nouvel appareil sur le réseau":
        "New device on the network",
    "Nouvelle exposition de sécurité, à partir de la gravité :":
        "New security exposure, from severity:",
    "Appareil de confiance passé hors ligne":
        "Trusted device went offline",
    "Seulement pour les scans automatiques (pas quand je scanne moi-même)":
        "Only for automatic scans (not when I scan myself)",
    "Envoyer par webhook":
        "Send by webhook",
    "Format":
        "Format",
    "URL":
        "URL",
    "Envoyer par e-mail (SMTP)":
        "Send by e-mail (SMTP)",
    "Port":
        "Port",
    "Identifiant":
        "Username",
    "Mot de passe":
        "Password",
    "Expéditeur":
        "Sender",
    "Destinataire(s)":
        "Recipient(s)",
    "Secrets (URL du webhook, mot de passe) : {backend}, jamais dans le fichier de réglages. Les messages contiennent les noms et adresses de vos appareils : ne les envoyez qu'à un service de confiance.":
        "Secrets (webhook URL, password): {backend}, never in the settings file. Messages contain the names and addresses of your devices: only send them to a service you trust.",
    "Envoyer un test":
        "Send a test",
    "Effacer les secrets":
        "Erase secrets",
    "Envoi du test…":
        "Sending the test…",
    "https://…":
        "https://…",
    "Secrets effacés.":
        "Secrets erased.",
    "Rapports planifiés":
        "Scheduled reports",
    "Produire un rapport PDF automatiquement":
        "Produce a PDF report automatically",
    "Parcourir…":
        "Browse…",
    " rapports":
        " reports",
    "Fréquence":
        "Frequency",
    "Dossier":
        "Folder",
    "Conserver les":
        "Keep the latest",
    "Dernier rapport : {when}":
        "Last report: {when}",
    "Aucun rapport produit pour l'instant.":
        "No report produced yet.",
    "Générer un rapport maintenant":
        "Generate a report now",
    "Dossier des rapports":
        "Reports folder",
    "Rapport enregistré : {path}":
        "Report saved: {path}",
    "Réseaux à scanner":
        "Networks to scan",
    "Le réseau local est toujours scanné. Cochez d'autres plages (autres VLAN, sous-réseaux routés) ou ajoutez-les à la main. Panther refuse les plages publiques.":
        "The local network is always scanned. Tick other ranges (other VLANs, routed subnets) or add them by hand. Panther refuses public ranges.",
    "Ajouter une plage, par exemple 192.168.20.0/24":
        "Add a range, for example 192.168.20.0/24",
    "Ajouter":
        "Add",
    "Détecter les réseaux joignables":
        "Detect reachable networks",
    "La détection sonde les passerelles .1 et .254 des plages 192.168.X.0/24 et 10.0.X.0/24 (environ 1 000 adresses). Au-delà d'un routeur, les adresses MAC ne sont pas visibles. Ne cochez que des réseaux dont vous êtes responsable.":
        "Detection probes the .1 and .254 gateways of 192.168.X.0/24 and 10.0.X.0/24 ranges (about 1,000 addresses). Beyond a router, MAC addresses are not visible. Only tick networks you are responsible for.",
    "SNMP (optionnel, lecture seule)":
        "SNMP (optional, read-only)",
    "Interroge un routeur ou un switch que vous désignez : sa table ARP donne les adresses MAC et les appareils des autres VLAN, sa table de ports donne le port et le VLAN de chaque appareil.":
        "Queries a router or switch you name: its ARP table gives MAC addresses and the devices of other VLANs, its port table gives each device's port and VLAN.",
    "IP du routeur / switch":
        "Router / switch IP",
    "Communauté (lecture)":
        "Community (read)",
    "v3 (authentification)":
        "v3 (authentication)",
    "v3 : utilisateur et mot de passe (HMAC SHA ou MD5), sans chiffrement : les réponses circulent en clair.":
        "v3: user and password (HMAC SHA or MD5), without encryption: answers travel in clear text.",
    "Mot de passe (8 caractères au moins)":
        "Password (at least 8 characters)",
    "Retirer":
        "Remove",
    "Détection en cours…":
        "Detecting…",
    "URL du webhook (déjà enregistrée : laisser vide pour la garder)":
        "Webhook URL (already saved: leave empty to keep it)",
    "Aucune (réseau de confiance uniquement)":
        "None (trusted network only)",
    "Mot de passe (déjà enregistré : laisser vide pour le garder)":
        "Password (already saved: leave empty to keep it)",
    "Activez le webhook ou l'e-mail pour envoyer un test.":
        "Enable the webhook or e-mail to send a test.",
    "Aucun canal actif.":
        "No active channel.",
    "Un rapport n'est produit que si Panther est ouvert et qu'un scan a eu lieu (activez le scan automatique pour qu'il soit à jour). Seuls les fichiers « rapport-panther-….pdf » de ce dossier sont renouvelés : rien d'autre n'y est supprimé.":
        "A report is only produced if Panther is open and a scan has taken place (enable the automatic scan to keep it up to date). Only files named “rapport-panther-….pdf” in this folder are renewed: nothing else there is deleted.",
    "Aucun résultat : lancez d'abord un scan.":
        "No result: run a scan first.",
    "Utilisateur":
        "User",
    "{host}  ·  v3 {user} ({proto})":
        "{host}  ·  v3 {user} ({proto})",
    "{host}  ·  communauté {dots}":
        "{host}  ·  community {dots}",
    "{found_count} réseau(x) joignable(s) trouvé(s).":
        "{found_count} reachable network(s) found.",
    "Aucun autre réseau joignable détecté (routage ou pare-feu entre les VLAN ?).":
        "No other reachable network detected (routing or firewall between the VLANs?).",
    "Enregistrement impossible : {e}":
        "Could not save: {e}",
    "Impossible : {e}":
        "Not possible: {e}",
    "Seules les adresses privées sont acceptées.":
        "Only private addresses are accepted.",
    "Indiquez la communauté SNMP en lecture seule.":
        "Enter the read-only SNMP community.",
    "« {host} » n'est pas une adresse IP valide.":
        "“{host}” is not a valid IP address.",
    "SNMP v3 : indiquez un utilisateur et un mot de passe de 8 caractères au moins.":
        "SNMP v3: enter a user and a password of at least 8 characters.",
    "  (réseau local)":
        "  (local network)",
    "  (détecté)":
        "  (detected)",
    "  (ajouté)":
        "  (added)",
    "  (autre interface)":
        "  (other interface)",
    "envoyé":
        "sent",
    "échec ({err})":
        "failed ({err})",
    "Analyse de sécurité activée : elle sera effectuée au prochain scan":
        "Security analysis enabled: it will run at the next scan",
    "Analyse de sécurité désactivée":
        "Security analysis disabled",
    "L'analyse de sécurité est désactivée. Activez-la dans le menu Sécurité (lecture seule), puis lancez un scan.":
        "The security analysis is disabled. Enable it in the Security menu (read-only), then run a scan.",
    "Rapport":
        "Report",
    "Aucun résultat d'analyse : activez l'analyse de sécurité (menu Sécurité) puis lancez un scan.":
        "No analysis result: enable the security analysis (Security menu) then run a scan.",
    "Rapport exporté : {basename}":
        "Report exported: {basename}",
    "Journal des événements illisible":
        "Event log unreadable",
    "Activer l'analyse de sécurité ?":
        "Enable the security analysis?",
    "Lancez un scan pour analyser l'exposition des appareils.":
        "Run a scan to analyse the exposure of devices.",
    "\n\nActiver l'analyse ?":
        "\n\nEnable the analysis?",
    "Aucun constat sur {analysed_count} appareil(s) analysé(s).":
        "No finding on {analysed_count} analysed device(s).",
    "   —   double-clic pour voir l'appareil sur la carte.":
        "   —   double-click to see the device on the map.",
    "{rows_count} constat(s) sur {value_count} appareil(s) ({analysed_count} analysés) : ":
        "{rows_count} finding(s) on {value_count} device(s) ({analysed_count} analysed): ",
    "Petit":
        "Small",
    "Normal":
        "Normal",
    "Grand":
        "Large",
    "Très grand":
        "Extra large",
    "L'analyse de sécurité est en lecture seule.\n\nElle regarde les ports ouverts et les bannières, et envoie UNE requête de lecture sans identifiant à certains services pour savoir s'ils répondent sans mot de passe : PING (Redis), version (Memcached), GET / (Elasticsearch), GET /version (Docker), DESCRIBE (flux vidéo RTSP).\n\nElle n'essaie aucun identifiant, ne devine aucun mot de passe et n'exploite aucune faille.\n\nÀ n'activer que sur des réseaux dont vous êtes responsable ou que vous avez l'autorisation d'analyser.":
        "The security analysis is read-only.\n\nIt looks at open ports and banners, and sends ONE read request without credentials to certain services to find out whether they answer without a password: PING (Redis), version (Memcached), GET / (Elasticsearch), GET /version (Docker), DESCRIBE (RTSP video streams).\n\nIt does not try any credentials, does not guess any password and does not exploit any vulnerability.\n\nOnly enable it on networks you are responsible for or are authorised to analyse.",
    "Nouvel appareil":
        "New device",
    "De retour en ligne":
        "Back online",
    "Nouvelle exposition":
        "New exposure",
    "Exposition corrigée":
        "Exposure fixed",
    "Appareils fusionnés":
        "Devices merged",
    "Changement d'adresse IP":
        "IP address changed",
    "Marqué de confiance":
        "Marked as trusted",
    "Confiance retirée":
        "Trust removed",
    "Hors ligne (vu {seen})":
        "Offline (seen {seen})",
    "Vu dans {flags_total} des {flags_count} derniers scans (le plus récent est à droite)":
        "Seen in {flags_total} of the last {flags_count} scans (most recent on the right)",
    "Latence sur les {n} derniers scans : de {low} à {high} ms (en bas : scans sans réponse)":
        "Latency over the last {n} scans: from {low} to {high} ms (bottom: scans with no answer)",
    "Carte réseau":
        "Network map",
    "Journal":
        "Log",
    "Prêt":
        "Ready",
    "Fichier":
        "File",
    "Quitter":
        "Quit",
    "Scan":
        "Scan",
    "Arrêter le scan":
        "Stop scan",
    "Profils de scan":
        "Scan profiles",
    "Scan automatique":
        "Automatic scan",
    "Affichage":
        "View",
    "Recentrer la carte":
        "Recenter map",
    "Centrer sur la sélection":
        "Center on selection",
    "Sélectionner tous les appareils":
        "Select all devices",
    "Animer la carte":
        "Animate the map",
    "Mini-carte":
        "Mini-map",
    "Disposition":
        "Layout",
    "Légende de la carte":
        "Map legend",
    "Afficher les appareils hors ligne":
        "Show offline devices",
    "Thème":
        "Theme",
    "Taille du texte":
        "Text size",
    "Écoute seule (aucune sonde active)":
        "Listen-only (no active probes)",
    "Analyse de sécurité (lecture seule)":
        "Security analysis (read-only)",
    "Aide":
        "Help",
    "  Profondeur":
        "  Depth",
    "Présence : qui est là ? (réutilise les détails du dernier scan complet, très discret).\nRapide : ports courants.\nNormal : bon équilibre.\nApprofondi : plus de ports et des délais plus longs.\nLes scans automatiques utilisent la présence, avec un scan complet au plus toutes les heures.":
        "Presence: who is there? (reuses details from the last full scan, very discreet).\nQuick: common ports.\nNormal: good balance.\nThorough: more ports and longer delays.\nAutomatic scans use presence, with a full scan at most once an hour.",
    "  Interface":
        "  Interface",
    "Réseau à scanner. « Automatique » suit la route par défaut ; choisissez une interface pour scanner un autre réseau (Ethernet, VPN…).":
        "Network to scan. “Automatic” follows the default route; choose an interface to scan another network (Ethernet, VPN…).",
    "  Aucun scan effectué":
        "  No scan yet",
    "Filtrer : nom, IP, type…  tag:xxx  groupe:xxx":
        "Filter: name, IP, type…  tag:xxx  group:xxx",
    "Panther — démonstration":
        "Panther — demo",
    "Date":
        "Date",
    "Événement":
        "Event",
    "Règles de détection : {count} (menu Détection)":
        "Detection rules: {count} (Detection menu)",
    "Exporter le rapport en PDF…":
        "Export report as PDF…",
    "Exporter la carte (PNG, SVG)…":
        "Export map (PNG, SVG)…",
    "Exporter en JSON…":
        "Export as JSON…",
    "Exporter en CSV…":
        "Export as CSV…",
    "Comparer deux scans…":
        "Compare two scans…",
    "Rapports planifiés…":
        "Scheduled reports…",
    "Historique et données…":
        "History and data…",
    "Faire confiance à tous les appareils en ligne…":
        "Trust all online devices…",
    "Fusionner des doublons…":
        "Merge duplicates…",
    "Alertes (webhook, e-mail)…":
        "Alerts (webhook, e-mail)…",
    "Désactivé":
        "Disabled",
    "Toutes les 5 minutes":
        "Every 5 minutes",
    "Toutes les 15 minutes":
        "Every 15 minutes",
    "Toutes les 30 minutes":
        "Every 30 minutes",
    "Toutes les heures":
        "Every hour",
    "Étoile (autour de cette machine)":
        "Star (around this machine)",
    "Hiérarchique (Internet → box → switch → appareils)":
        "Hierarchical (Internet → router → switch → devices)",
    "Regroupée par type d'appareil":
        "Grouped by device type",
    "Réinitialiser les positions de cette disposition":
        "Reset positions of this layout",
    "Automatique (suit le système)":
        "Automatic (follows the system)",
    "Sombre":
        "Dark",
    "Clair":
        "Light",
    "Contraste élevé":
        "High contrast",
    "Voir le rapport de sécurité":
        "View security report",
    "Exporter le rapport (Markdown)…":
        "Export report (Markdown)…",
    "Ce que fait l'analyse…":
        "What the analysis does…",
    "Règles personnalisées…":
        "Custom rules…",
    "Créer une règle pour l'appareil sélectionné…":
        "Create a rule for the selected device…",
    "Assistant de premier lancement…":
        "First-run assistant…",
    "Mettre à jour la base des fabricants…":
        "Update the vendor database…",
    "Ouvrir le journal d'erreurs":
        "Open the error log",
    "À propos de Panther":
        "About Panther",
    "Rapide":
        "Quick",
    "Approfondi":
        "Thorough",
    "avertissement":
        "warning",
    "avertissements":
        "warnings",
    "Analyse de sécurité":
        "Security analysis",
    "Panther – scanner et cartographie de réseau local.\n\nMoteur de scan maison (TCP, ARP, NetBIOS, mDNS), sans dépendance externe.\nÀ n'utiliser que sur des réseaux dont vous avez l'autorisation.":
        "Panther – local network scanner and mapper.\n\nIn-house scan engine (TCP, ARP, NetBIOS, mDNS), no external dependency.\nOnly use it on networks you are authorised to scan.",
    "Je n'utiliserai Panther que sur des réseaux dont j'ai la responsabilité ou l'autorisation.":
        "I will only use Panther on networks I am responsible for or have permission to scan.",
    "Écoute seule : ne rien envoyer sur le réseau":
        "Listen-only: send nothing on the network",
    "Analyse de sécurité en lecture seule (ports ouverts, services sans mot de passe)":
        "Read-only security analysis (open ports, services without a password)",
    "Profondeur":
        "Depth",
    "Étape {i} sur {n}":
        "Step {i} of {n}",
    "Précédent":
        "Back",
    "Passer":
        "Skip",
    "Un outil à utiliser avec discernement":
        "A tool to use responsibly",
    "Apparence":
        "Appearance",
    "Façon de scanner":
        "How to scan",
    "Terminer":
        "Finish",
    "Suivant":
        "Next",
    "Panther envoie des paquets aux appareils d'un réseau pour les reconnaître. Scanner un réseau qui n'est pas le vôtre peut être illégal. Il refuse les plages publiques et n'essaie jamais de mot de passe.":
        "Panther sends packets to the devices of a network to recognise them. Scanning a network that is not yours may be illegal. It refuses public ranges and never tries a password.",
    "Le thème et la taille du texte se changent à tout moment dans le menu Affichage.":
        "The theme and text size can be changed at any time in the View menu.",
    "Rien n'est lancé tant que vous n'appuyez pas sur « Lancer le scan ».":
        "Nothing runs until you press “Start scan”.",
}
