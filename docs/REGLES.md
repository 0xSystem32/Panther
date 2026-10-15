# Règles de détection personnalisées

[English](RULES.md) · **Français**

Panther classe chaque appareil par **score** : plusieurs indices (ports, annonces mDNS/UPnP/WS-Discovery, fabricant,
nom, modèle…) ajoutent des points à un type, le type qui en a le plus l'emporte. Vos règles ajoutent des indices
supplémentaires, **sans toucher au code** : fichier `~/.config/Panther/rules.json`
(menu *Détection → Règles personnalisées…*, ou clic droit sur un appareil → *Créer une règle de détection…*).

```json
{
  "version": 1,
  "rules": [
    { "name": "Imprimante du bureau", "type": "printer", "points": 60,
      "match": { "hostname": "^(hp|brother)-", "ports_any": [9100, 631] } },
    { "name": "Caméras du garage", "type": "camera", "points": 70,
      "match": { "in_network": "192.168.20.0/24", "ports_any": [554] } },
    { "name": "Ma box", "type": "router", "force": true, "match": { "mac_prefix": "aa:bb:cc" } }
  ],
  "models": [
    { "pattern": "^MaCam-", "name": "Ma caméra maison", "type": "camera" }
  ]
}
```

## Règles

| Champ | Rôle |
|---|---|
| `name` | nom de la règle (obligatoire, sert aussi à la retrouver et à la remplacer) |
| `type` | `desktop`, `laptop`, `phone`, `tablet`, `tv`, `settop`, `printer`, `router`, `switch`, `camera`, `server`, `nas`, `console`, `speaker`, `iot`, `unknown` |
| `points` | 1 à 100 (50 par défaut) : s'ajoutent aux indices intégrés, qui gardent leur rôle |
| `force` | `true` : impose le type (confiance 100 %), quels que soient les autres indices |
| `reason` | texte affiché dans les indices de l'appareil (par défaut : « règle « nom » ») |
| `match` | conditions : **toutes** doivent être vraies (au moins une est obligatoire) |

## Conditions (`match`)

| Condition | Valeur | Compare |
|---|---|---|
| `hostname` | expression régulière (ou liste = l'une d'elles) | nom automatique de l'appareil |
| `vendor` | idem | fabricant (base IEEE) |
| `model` | idem | modèle annoncé (mDNS, UPnP, WS-Discovery), identifiants Apple compris |
| `os` | idem | système deviné |
| `banner` | idem | bannières des services (SSH, FTP, titre et `realm` des pages web) |
| `ssdp` | idem | texte UPnP (serveur, nom, fabricant, modèle) |
| `cert` | idem | certificat HTTPS : organisation, nom, noms alternatifs, émetteur (valeurs « bruit » comme `localhost` ou une adresse IP écartées) |
| `ports_any` / `ports_all` | liste de ports | au moins un / tous ouverts |
| `mdns_service` | texte ou liste | services annoncés (`_ipp._tcp`, `_googlecast._tcp`…) |
| `mac_prefix` | `"aa:bb:cc"` ou liste | début de l'adresse MAC (1 à 6 octets) |
| `in_network` | `"192.168.20.0/24"` | l'adresse IP appartient à la plage |
| `gateway` | `true` / `false` | est (ou non) la passerelle |

Les expressions régulières ignorent la casse. Si l'appareil a été renommé à la main, c'est son nom **automatique** qui est comparé.

## Modèles (`models`)

Associent un identifiant de modèle à un nom lisible, et éventuellement à un type (qui devient alors un indice). Ils passent
avant la table intégrée (`iPhone14,2` → « iPhone 13 Pro », etc.). Un identifiant inconnu retombe sur sa famille (« iPhone »),
jamais sur un nom deviné.

## Sécurité du fichier

Un fichier de règles peut s'échanger (menu *Exporter… / Importer…*), il est donc traité comme **non fiable** : 256 Ko au plus,
500 règles au plus, motifs de 200 caractères au plus, motifs à quantificateurs imbriqués (`(a+)+`…, risque de blocage) refusés,
texte testé tronqué à 400 caractères. Une règle invalide est ignorée avec un avertissement ; elle ne casse jamais un scan.
