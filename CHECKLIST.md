# Panther – checklist

Légende : `[x]` fait · `[ ]` à faire · **(en cours)** = chantier actif.
On traite les phases dans l'ordre, un chantier à la fois, avec tests avant de passer au suivant.

## Phase 0 – Base (v1)
- [x] Moteur de scan maison : TCP + UDP + table ARP, sans root, sans nmap
- [x] Nom (DNS inverse, NetBIOS, mDNS), ports, bannières HTTP/SSH, TTL
- [x] Fabricant via MAC (OUI) + détection des MAC aléatoires
- [x] Empreinte OS + classification par règles
- [x] Fenêtre PyQt6 : carte en étoile, liste triable, panneau de détails, filtre
- [x] Thèmes sombre / clair, export JSON et CSV
- [x] Interface web de secours (`--web`) et mode terminal (`--cli`)

## Phase 1 – Détection fiable des appareils + logos  **(terminée)**
- [x] Découverte SSDP/UPnP (TV, imprimantes, box, enceintes) + lecture de la description XML (nom, fabricant, modèle)
- [x] Découverte mDNS/Bonjour : services annoncés (`_ipp`, `_airplay`, `_googlecast`, `_companion-link`, `_hap`…) et modèle (TXT)
- [x] Classification par **score** (plusieurs indices) au lieu d'une cascade de règles
- [x] Niveau de **confiance** et **raisons** affichés dans le panneau (« pourquoi Panther pense que c'est une imprimante »)
- [x] Nouveaux logos : tablette, console de jeux, enceinte connectée, TV distincte de l'ordinateur
- [x] Nom lisible quand le DNS ne répond pas (nom mDNS / UPnP)
- [x] Vraie base fabricants IEEE (`oui.txt`, 40 333 entrées, mise à jour avec `python3 tools/update_oui.py`)
- [x] Tests unitaires de la classification (cas téléphone, imprimante, TV, caméra, NAS, routeur)
- [x] Correction manuelle : renommer un appareil / forcer son type (clic droit, double-clic ou bouton ; mémorisé par adresse MAC)

## Phase 2 – Plusieurs réseaux et VLAN  **(terminée)**
Contraintes à connaître : l'ARP ne traverse pas un routeur (donc pas de MAC/fabricant pour un autre VLAN sans accès SNMP/LLDP), et il faut que le routage inter-VLAN et le pare-feu autorisent les sondes.
- [x] Cibles de scan configurables : plages CIDR saisies à la main (bouton « Réseaux… », réseaux privés uniquement, 4 096 adresses max par plage)
- [x] Découverte automatique des sous-réseaux joignables : `ip route`, interfaces VLAN 802.1Q locales, sondage des passerelles .1/.254
- [x] Découverte des voisins réseau par LLDP/CDP (switch, port, VLAN) : écoute brute (droits `cap_net_raw`) ou `lldpd`, parseurs testés
- [x] Traceroute vers chaque sous-réseau pour savoir quels équipements sont sur le chemin
- [x] Scan à travers le routeur (sondes TCP) avec délais adaptés aux liens plus lents
- [x] Regroupement par VLAN / sous-réseau sur la carte (zones nommées) ; colonne « Réseau » et filtre par plage
- [x] Lecture SNMP optionnelle d'un switch/routeur (tables ARP, MAC, VLAN, ports) pour récupérer les MAC des autres VLAN (client v2c écrit à la main, testé contre un faux agent)
- [x] Avertissement clair quand un VLAN n'est pas joignable (routage ou pare-feu), avec le dernier saut atteint

## Phase 3 – Surveillance continue  **(terminée)**
- [x] Bouton « Arrêter le scan » (résultats partiels conservés)
- [x] Profondeur du scan : rapide (≈ 10 s) / normal / approfondi
- [x] Scan automatique toutes les 5 / 15 / 30 / 60 minutes
- [x] Statut en ligne / hors ligne par appareil (appareils absents estompés, colonne « Statut »)
- [x] Notification de bureau quand un appareil inconnu apparaît (scans automatiques ; référence = première analyse)

## Phase 4 – Historique et appareils connus (SQLite)  **(terminée)**
- [x] Base locale (SQLite) : première / dernière apparition, changements d'IP, historique de présence (barre de présence, disponibilité sur 7 jours), journal des événements
- [x] Appareils « de confiance » vs « non vérifiés » (coche sur la carte, validation en masse après contrôle, journalisé)
- [x] Nom et icône (type) personnalisés conservés d'un scan à l'autre (par adresse MAC)

## Phase 5 – Topologie réelle  **(terminée)**
- [x] Carte hiérarchique : Internet → box → switch → appareils (switch et ports via SNMP, voisin direct via LLDP/CDP, autres réseaux via traceroute) ; votre chemin vers Internet est mis en évidence
- [x] Dispositions de carte au choix : étoile / hiérarchique (menu Affichage → Disposition)
- [x] Positions des nœuds mémorisées (par disposition et par appareil, réinitialisables)

## Phase 6 – Sécurité (opt-in, uniquement sur réseau autorisé)  **(terminée)**
- [x] Alerte ports sensibles ouverts (Telnet, FTP, RDP, VNC, ADB, SMB sur un appareil inattendu, bases de données…), classés par gravité
- [x] Services accessibles sans mot de passe (Redis, Memcached, Elasticsearch, Docker, flux RTSP : une requête de lecture sans identifiant, aucun mot de passe essayé) et services obsolètes (bannières : SSH 1, vsFTPd 2.3.4, Boa, Apache/IIS anciens, libupnp < 1.6.18…)
- [x] Rapport d'exposition par appareil (onglet Sécurité, panneau de détails, export Markdown) ; nouvelles expositions et expositions corrigées dans le journal

## Phase 7 – Confort  **(terminée)**
- [x] Choix de l'interface réseau (Wi-Fi, Ethernet, VPN, virtuelle) : liste rafraîchie à l'ouverture, « Automatique » suit la route par défaut
- [x] Export PDF d'un rapport de scan (résumé, carte, changements, appareils, exposition, avertissements) sans dépendance supplémentaire
- [x] Comparaison de deux scans (nouveaux, disparus, modifiés : IP, nom, type, système, ports, constats de sécurité)

## Phase 8 – Qualité et distribution (pour le CV)  **(terminée)**
- [x] Intégration continue GitHub (`.github/workflows/ci.yml` : tests moteur sur Python 3.12 et 3.13, tests d'interface hors écran, paquets) ; 186 tests, **workflow non exécuté sur GitHub** (pas de dépôt ici)
- [x] `pyproject.toml` et installation `pipx` (paquet `panther/`, commande `panther`, données incluses ; wheel construit et installé dans un environnement vierge)
- [x] Paquet `.deb` (`packaging/build-deb.sh`, dépend de `python3-pyqt6`, contenu et lancement vérifiés après extraction) — AppImage non fait (embarquer Python + Qt, ≈ 150 Mo) : voir AMELIORATIONS.md
- [x] Captures d'écran et GIF de démonstration dans le README (réseau fictif, régénérables avec `tools/make_screenshots.py`)
- [x] Licence MIT et section « usage éthique »

---
À traiter **après les 8 phases** : voir [AMELIORATIONS.md](AMELIORATIONS.md) (consolidation : performance, doublons, vie privée, qualité du code).
