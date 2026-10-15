# Panther – tout ce qu'il reste à faire

Liste complète, à traiter après les 8 phases de [CHECKLIST.md](CHECKLIST.md) (toutes terminées).
Légende : `[x]` fait · `[ ]` à faire · **P1** à faire d'abord · **P2** ensuite · **P3** plus tard ·
effort **S** (< 1 h) · **M** (quelques heures) · **L** (plus d'une journée).

## 0. Vérifier sur du vrai matériel (rien de tout ceci n'a été testé en conditions réelles)
- [ ] **P1 · S** Exécuter la CI sur GitHub (créer le dépôt, pousser) : le workflow n'a jamais tourné ; confirmer Python 3.12
- [ ] **P1 · M** Tester SNMP, LLDP/CDP et la hiérarchie sur un vrai switch administrable (aujourd'hui : faux agent et trames fabriquées)
- [ ] **P1 · M** Tester un vrai VLAN routé (autre plage, traceroute, avertissement « injoignable »)
- [ ] **P1 · S** Tester l'analyse de sécurité sur de vrais appareils (caméra, NAS, Redis de test) et vérifier les faux positifs
- [ ] **P2 · S** Installer le `.deb` avec `apt` sur une machine propre (Debian 13 et Ubuntu 24.04) ; tester les notifications de bureau
- [ ] **P2 · M** Tester sur un gros réseau (≥ 200 appareils) : durée du scan, fluidité de la carte

## 1. Fiabilité et performance
- [x] Identité des appareils par la **MAC d'abord** (changement d'IP = événement, jamais un doublon)
- [x] Découverte par la table ARP : scan **Normal de 98 s à ~11 s** (mêmes appareils) ; les entrées anciennes sont revérifiées par le noyau, le TCP ne sert plus que pour les réseaux routés
- [x] Carte incrémentale pendant le scan (nœuds existants et déplacés intacts, ancienne carte gardée jusqu'au premier appareil trouvé)
- [x] Fusion de doublons : suggestions après chaque scan (même nom, type compatible, MAC aléatoire), fusion manuelle (clic droit), alias de MAC conservés pour les scans futurs et les comparaisons
- [x] Scan de présence (~2 s, quasi aucun trafic) : détails repris du dernier scan complet ; les scans automatiques l'utilisent, avec un scan complet au plus toutes les heures
- [x] Résolution des noms (DNS, NetBIOS, mDNS) parallèle et plafonnée, en même temps que le scan de ports
- [x] Journal d'erreurs `~/.config/Panther/panther.log` (rotatif, exceptions non gérées et threads inclus, `--verbose`, menu Aide ; sans communauté SNMP)
- [x] Noms/types choisis à la main : l'entrée `ip:…` suit l'appareil quand il gagne une MAC, et la fusion de doublons
- [ ] **P3 · M** Distinguer Wi-Fi et câble sur la carte hiérarchique (SNMP / LLDP / tables de bridge) — dépend d'un vrai switch administrable (section 0)
- [x] Fichier > Historique et données : taille et contenu de la base, durée de conservation configurable, purge + compactage

- [ ] **P3 · S** Animer le recalcul final de la carte à la fin d'un scan (les nœuds sautent d'un coup à leur place définitive)

## 2. Détection des appareils
- [x] Règles de détection extensibles (`rules.json`, `docs/REGLES.md`) : 11 conditions, points ou `force`, création depuis un appareil (clic droit), liste avec nombre d'appareils concernés, import/export, fichier traité comme non fiable (motifs à risque refusés)
- [x] Nouvelles sources : titre/`realm`/serveur HTTP et HTTPS, WS-Discovery (ONVIF, imprimantes, Windows), NetBIOS complet (groupe de travail, serveur de fichiers), baux DHCP locaux (dnsmasq, Pi-hole, isc-dhcp)
- [x] Noms de modèles lisibles : table sûre (iPhone 8 à 15, iPad, Mac, Apple TV, HomePod) avec repli sur la famille, familles Samsung, modèles personnalisables (⚠ `iPhone14,2` est un iPhone 13 **Pro**, pas un 13 : vérifié par un test)
- [ ] **P2 · S** Vérifier la table des modèles Apple sur de vrais appareils (et compléter : iPhone 16, Mac récents, Galaxy, Pixel)
- [x] Certificat HTTPS comme indice (sujet, émetteur, noms alternatifs, expiration) : décodeur DER écrit à la main, fabricant de secours sans MAC, règle `cert`, constat « certificat expiré » ; vérifié sur la Livebox (modèle exact lu)
- [ ] **P3 · S** Certains appareils ouvrent le port HTTPS mais n'en livrent ni page ni certificat (ex. un décodeur Sagemcom) : voir si une autre version de TLS ou une attente plus longue suffit
- [ ] **P3 · L** Empreinte du système par réponses TCP/IP (TTL, fenêtre, options), au-delà du TTL
- [ ] **P3 · L** Support IPv6 (découverte NDP, adresses multiples par appareil)

## 3. Fonctions
- [x] Étiquettes, notes et groupes par appareil (« enfants », « domotique »), filtres associés
- [x] Alertes par webhook (Discord, Slack, ntfy, JSON) ou e-mail SMTP, un message groupé par scan, secrets dans le trousseau
- [x] Rapport PDF planifié (quotidien ou hebdomadaire) dans un dossier choisi, nettoyage des plus anciens (seuls ses propres fichiers)
- [x] Export de la carte en PNG/SVG ; export enrichi (confiance, historique)
- [x] Réveil à distance (Wake-on-LAN) d'un appareil hors ligne
- [ ] **P3 · M** Latence et disponibilité par appareil (courbe dans le panneau)
- [ ] **P3 · M** Profils de scan enregistrés (plages, profondeur, interface, SNMP)
- [x] Mise à jour de la base IEEE depuis un menu (avec confirmation)
- [ ] **P3 · M** SNMP v3 (authentification et chiffrement) en plus de v2c — la bibliothèque standard n'a pas AES : au mieux authNoPriv sans dépendance
- [ ] **P3 · L** Plusieurs sites / plusieurs machines d'écoute

## 4. Vie privée et sécurité du logiciel
- [x] « Tout effacer » (Fichier > Historique et données) : base (pages écrasées), noms choisis, étiquettes, journal ; confirmation
- [x] Communauté SNMP dans le trousseau du système (ou fichier 600), migration automatique de l'ancienne configuration
- [x] `SECURITY.md` ; revue des entrées non fiables : infobulles Qt échappées (faille trouvée et corrigée), interface web (CSP, échappement), tests avec texte hostile
- [x] Base protégée : dossier 700, base et journal 600 (pas de chiffrement : la bibliothèque standard n'en offre pas ; chiffrer le disque)
- [ ] **P3 · L** Chiffrement réel de la base (SQLCipher ou `cryptography` en dépendance optionnelle)
- [x] Mode « écoute seule » (menu Sécurité, `--depth ecoute`) : aucune sonde, test qui vérifie qu'aucune fonction réseau n'est appelée

## 5. Interface
- [x] Interface, README, règles et sécurité en anglais (menu Affichage → Langue, `--lang`, langue du système par défaut) : module `i18n.py` maison (français = texte source, catalogue `lang_en.py` de ~790 textes), `tools/i18n_check.py` + tests (textes manquants/périmés, champs identiques, aucun français dans l'interface anglaise), interface web traduite (`/api/strings`), captures anglaises (`docs/img/en/`). Limite : les textes déjà enregistrés (journal, constats) gardent leur langue d'origine
- [x] Mode `--demo` : réseau fictif (16 appareils, 2 réseaux, historique semé), faux moteur qui simule la progression ; configuration temporaire supprimée à la fermeture, réveil à distance et téléchargements désactivés ; sert aussi aux captures du README
- [x] Carte : disposition « regroupée par type » (amas ronds, positions mémorisées à part), mini-carte (visible quand on zoome, clic/glisser), sélection multiple (Maj + glisser, Ctrl + clic, tout sélectionner) avec panneau de synthèse, confiance et étiquettes/groupe en masse, centrage sur la sélection (`Ctrl+Maj+0`)
- [x] Accessibilité : carte aux flèches (Entrée, Échap, +/−, Ctrl+A), focus visible, contrastes WCAG AA vérifiés par test pour les 3 thèmes (AAA pour « contraste élevé »), taille du texte réglable (4 tailles, carte comprise), noms accessibles. Limite : les nœuds de la carte ne sont pas exposés aux lecteurs d'écran (l'onglet Appareils, un tableau, est l'équivalent)
- [x] Thème automatique (suit le système en direct, Qt ≥ 6.5), sombre, clair, contraste élevé
- [x] Assistant de premier lancement (langue, usage responsable obligatoire, apparence, profondeur, écoute seule, analyse de sécurité, scan automatique) ; Aide → Assistant pour le rouvrir

## 6. Qualité du code
- [x] `gui.py` (3 400 lignes) découpé en package `panther/ui/` : 9 modules + 7 mixins pour la fenêtre principale (le plus grand : 447 lignes) ; `gui.py` réexporte les noms publics. Le découpage a révélé un chemin d'icône cassé, désormais couvert par un test
- [x] `ruff` (E, F, W, B, UP, I) propre et `mypy` propre sur tout `panther/` (l'interface masque seulement 10 familles d'erreurs dues aux stubs PyQt6 et aux mixins), dans la CI + `pre-commit`
- [x] Couverture mesurée dans la CI (moteur 91 %, seuil 85 %) ; tests « fuzz » déterministes des analyseurs (SNMP, LLDP/CDP, DNS/mDNS, SSDP, WS-Discovery, NetBIOS, bannières HTTP, baux DHCP, certificats DER)
- [x] Tests de performance : 250 appareils (historique, comparaison, dispositions, exports, carte, mises à jour incrémentales, mini-carte), seuils larges contre les régressions quadratiques
- [x] Tests d'interface automatisés hors écran intégrés à la CI (`tests/test_gui.py`)
- [x] `pre-commit`, `CONTRIBUTING.md`, modèles de tickets

## 7. Distribution
- [ ] **P1 · S** `CHANGELOG.md` et publication automatique d'une version GitHub (wheel + `.deb`) à chaque étiquette
- [ ] **P2 · L** AppImage (Python + Qt embarqués, utilisable sans installation)
- [ ] **P2 · M** Publication sur PyPI (`pipx install panther-netscan`) une fois le nom réservé
- [ ] **P3 · L** Flatpak ou Snap
- [ ] **P3 · S** Page de manuel (`man panther`) et complétion du shell
- [ ] **P3 · L** Support de macOS et Windows (aujourd'hui Linux seulement : `ip`, `/proc/net/arp`, `/sys`)
- [ ] **P3 · M** Site de documentation (captures, tutoriels, cas d'usage)

## Ordre conseillé
1. **Valider** : pousser sur GitHub (CI), tester sur du vrai matériel (section 0).
2. **Vitesse et fluidité** : découverte par ARP, carte incrémentale, doublons (section 1).
3. **Vitrine du CV** : mode `--demo`, anglais, `CHANGELOG`/releases, découpage de `gui.py`.
4. Le reste selon l'envie : détection extensible, alertes, AppImage, PyPI.
