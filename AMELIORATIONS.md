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
- [ ] **P1 · M** Règles de détection extensibles par l'utilisateur (fichier, sans toucher au code) + export/import
- [ ] **P2 · M** Nouvelles sources : titre/en-têtes HTTP(S), WS-Discovery (imprimantes et PC Windows), NBNS, bail DHCP (nom d'hôte)
- [ ] **P2 · M** Correspondance des identifiants de modèle Apple/Samsung/Google (`iPhone14,2` → « iPhone 13 »)
- [ ] **P3 · L** Empreinte du système par réponses TCP/IP (TTL, fenêtre, options), au-delà du TTL
- [ ] **P3 · L** Support IPv6 (découverte NDP, adresses multiples par appareil)

## 3. Fonctions
- [ ] **P2 · M** Étiquettes, notes et groupes par appareil (« enfants », « domotique »), filtres associés
- [ ] **P2 · M** Alertes par e-mail ou webhook (nouvel appareil, nouvelle exposition), en plus de la notification de bureau
- [ ] **P2 · M** Rapport PDF/Markdown planifié (hebdomadaire) dans un dossier choisi
- [ ] **P2 · S** Export de la carte en PNG/SVG ; export enrichi (confiance, historique)
- [ ] **P3 · M** Réveil à distance (Wake-on-LAN) d'un appareil hors ligne
- [ ] **P3 · M** Latence et disponibilité par appareil (courbe dans le panneau)
- [ ] **P3 · M** Profils de scan enregistrés (plages, profondeur, interface, SNMP)
- [ ] **P3 · M** Mise à jour de la base IEEE depuis un menu (avec confirmation)
- [ ] **P3 · M** SNMP v3 (authentification et chiffrement) en plus de v2c
- [ ] **P3 · L** Plusieurs sites / plusieurs machines d'écoute

## 4. Vie privée et sécurité du logiciel
- [ ] **P1 · S** Menu « Effacer l'historique » (la base contient les MAC et noms des appareils de la maison)
- [ ] **P1 · M** Communauté SNMP dans le trousseau du système (libsecret) au lieu de la configuration en clair
- [ ] **P2 · S** Fichier de sécurité `SECURITY.md` (comment signaler une faille) et revue des entrées non fiables (bannières, noms)
- [ ] **P3 · M** Chiffrer ou protéger la base locale (option)
- [ ] **P3 · S** Option de désactivation complète des sondes actives (mode « écoute seule »)

## 5. Interface
- [ ] **P1 · M** Interface et README en anglais (sélecteur FR/EN) : beaucoup de recruteurs lisent l'anglais
- [ ] **P2 · M** Mode `--demo` : réseau fictif intégré pour essayer l'application sans scanner (utile aussi pour les démonstrations)
- [ ] **P2 · M** Carte : regroupement par type, mini-carte, sélection multiple, recentrage sur l'appareil choisi
- [ ] **P2 · S** Accessibilité : navigation au clavier complète, contrastes, tailles de police réglables
- [ ] **P3 · S** Thème qui suit celui du système
- [ ] **P3 · M** Assistant de premier lancement (interface, profondeur, analyse de sécurité)

## 6. Qualité du code
- [ ] **P1 · L** Découper `gui.py` (≈ 1 800 lignes) en modules : carte, dialogues, fenêtre principale
- [ ] **P2 · M** Typage (`mypy`) et analyse statique (`ruff`) dans la CI
- [ ] **P2 · M** Couverture de tests mesurée (objectif ≥ 85 % sur le moteur) et tests « fuzz » des analyseurs (mDNS, SNMP, LLDP, bannières)
- [ ] **P2 · S** Tests de performance (carte avec 250 nœuds, scan simulé)
- [x] Tests d'interface automatisés hors écran intégrés à la CI (`tests/test_gui.py`)
- [ ] **P3 · S** `pre-commit`, `CONTRIBUTING.md`, modèles de tickets

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
