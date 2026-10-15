# Politique de sécurité / Security policy

**Français** ci-dessous · [English version](#english)

## Signaler une faille

Merci de **ne pas ouvrir de ticket public** pour une faille de sécurité.
Utilisez le signalement privé de GitHub :
<https://github.com/0xSystem32/Panther/security/advisories/new>
(onglet *Security* du dépôt → *Report a vulnerability*).

Décrivez ce que vous avez observé, comment le reproduire (version de Panther, système, une capture réseau ou un
fichier d'exemple si possible) et l'impact que vous imaginez. N'incluez pas de données de votre réseau réel que vous
ne voulez pas partager (adresses MAC, noms d'appareils).

Réponse visée : accusé de réception sous 7 jours, correctif ou plan sous 30 jours. Panther est un projet personnel,
sans garantie de délai, mais toute faille confirmée est corrigée en priorité et mentionnée dans les notes de version.

## Versions concernées

Seule la dernière version publiée (0.1.x) est corrigée.

## Ce qui est dans le périmètre

- exécution de code ou lecture/écriture de fichiers déclenchée par des données reçues du réseau (réponses mDNS, SSDP,
  WS-Discovery, SNMP, LLDP/CDP, bannières HTTP/SSH, certificats TLS, baux DHCP) ;
- injection dans l'interface (HTML, formules CSV, en-têtes d'e-mail) à partir de ces données ;
- fuite de secrets (URL de webhook, mot de passe SMTP, communauté SNMP) vers un fichier, le journal ou le réseau ;
- accès à l'interface web locale depuis une autre machine ou un autre site ;
- fichiers de réglages (`rules.json`, `alerts.json`) permettant autre chose que ce qu'ils décrivent.

Hors périmètre : le fait que Panther sonde les appareils d'un réseau (c'est sa fonction ; voir l'usage éthique dans le
README), les failles des appareils qu'il détecte, et un attaquant qui a déjà un accès complet à votre session.

## Choix de conception

- **Entrées non fiables** : tout ce qui vient du réseau est borné en taille, analysé sans `eval` ni motif d'expression
  régulière dangereux, puis affiché en texte brut (infobulles échappées, PDF et interface web échappés, CSV protégé
  contre les formules, en-têtes d'e-mail nettoyés).
- **Interface web** : écoute sur `127.0.0.1` seulement, refuse un en-tête `Host` ou `Origin` étranger (DNS rebinding),
  envoie une politique `Content-Security-Policy` stricte sans script en ligne.
- **Secrets** : trousseau du système (`secret-tool`) si présent, sinon fichier en mode 600 ; jamais dans les réglages ni le journal.
- **Données locales** : `~/.config/Panther/` en mode 700, base et journal en mode 600 ; « Fichier → Historique et
  données → Tout effacer » écrase les pages libérées de la base. Les données ne sont **pas chiffrées** : pour un disque
  exposé, chiffrez le disque ou votre dossier personnel.
- **Aucune requête sortante** hors de votre réseau, sauf ce que vous activez : webhook ou SMTP des alertes, et
  téléchargement de la base IEEE (menu, avec confirmation).
- **Écoute seule** (menu Sécurité) : Panther n'envoie plus aucun paquet de sondage ; il lit la table des voisins du
  noyau et les baux DHCP locaux.

---

## English

### Reporting a vulnerability

Please **do not open a public issue** for a security flaw. Use GitHub's private reporting:
<https://github.com/0xSystem32/Panther/security/advisories/new> (repository *Security* tab → *Report a vulnerability*).

Describe what you observed, how to reproduce it (Panther version, system, a packet capture or sample file if possible) and
the impact you imagine. Do not include data from your real network that you do not want to share (MAC addresses, device
names). Target: acknowledgement within 7 days, fix or plan within 30 days. Panther is a personal project with no guaranteed
delay, but any confirmed flaw is fixed first and mentioned in the release notes. Only the latest release (0.1.x) is fixed.

### In scope

- code execution or file read/write triggered by data received from the network (mDNS, SSDP, WS-Discovery, SNMP, LLDP/CDP
  answers, HTTP/SSH banners, TLS certificates, DHCP leases);
- injection into the interface (HTML, CSV formulas, e-mail headers) from that data;
- leaking secrets (webhook URL, SMTP password, SNMP community) to a file, the log or the network;
- access to the local web interface from another machine or another website;
- settings files (`rules.json`, `alerts.json`) allowing anything other than what they describe.

Out of scope: the fact that Panther probes the devices of a network (that is its job; see the ethical use section of the
README), flaws of the detected devices themselves, and an attacker who already has full access to your session.

### Design choices

- **Untrusted input**: everything from the network is size-bounded, parsed without `eval` or dangerous regular expressions,
  then shown as plain text (escaped tooltips, escaped PDF and web interface, CSV protected against formulas, cleaned e-mail
  headers).
- **Web interface**: listens on `127.0.0.1` only, refuses a foreign `Host` or `Origin` header (DNS rebinding), sends a strict
  `Content-Security-Policy` with no inline script.
- **Secrets**: system keyring (`secret-tool`) when present, otherwise a mode-600 file; never in the settings or the log.
- **Local data**: `~/.config/Panther/` in mode 700, database and log in mode 600; “File → History and data → Erase
  everything” overwrites the freed pages of the database. Data is **not encrypted**: for an exposed disk, encrypt the disk
  or your home folder.
- **No outgoing request** beyond your network except what you enable: the alerts' webhook or SMTP, and the IEEE database
  download (menu, with confirmation).
- **Listen-only mode** (Security menu): Panther sends no probe at all; it reads the kernel's neighbour table and the local
  DHCP leases.
