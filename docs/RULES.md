# Custom detection rules

**English** · [Français](REGLES.md)

Panther classifies every device by **score**: several clues (ports, mDNS/UPnP/WS-Discovery announcements, vendor, name,
model…) add points to a type, and the type with the most points wins. Your rules add extra clues, **without touching the
code**: file `~/.config/Panther/rules.json` (menu *Detection → Custom rules…*, or right-click a device → *Create a
detection rule…*).

```json
{
  "version": 1,
  "rules": [
    { "name": "Office printer", "type": "printer", "points": 60,
      "match": { "hostname": "^(hp|brother)-", "ports_any": [9100, 631] } },
    { "name": "Garage cameras", "type": "camera", "points": 70,
      "match": { "in_network": "192.168.20.0/24", "ports_any": [554] } },
    { "name": "My router", "type": "router", "force": true, "match": { "mac_prefix": "aa:bb:cc" } }
  ],
  "models": [
    { "pattern": "^MyCam-", "name": "My home camera", "type": "camera" }
  ]
}
```

## Rules

| Field | Role |
|---|---|
| `name` | rule name (required; also used to find and replace it) |
| `type` | `desktop`, `laptop`, `phone`, `tablet`, `tv`, `settop`, `printer`, `router`, `switch`, `camera`, `server`, `nas`, `console`, `speaker`, `iot`, `unknown` |
| `points` | 1 to 100 (50 by default): added to the built-in clues, which keep their role |
| `force` | `true`: imposes the type (100 % confidence), whatever the other clues say |
| `reason` | text shown in the device's clues (default: “rule “name””) |
| `match` | conditions: **all** must be true (at least one is required) |

## Conditions (`match`)

| Condition | Value | Compares |
|---|---|---|
| `hostname` | regular expression (or list = any of them) | automatic name of the device |
| `vendor` | same | vendor (IEEE database) |
| `model` | same | announced model (mDNS, UPnP, WS-Discovery), Apple identifiers included |
| `os` | same | guessed system |
| `banner` | same | service banners (SSH, FTP, title and `realm` of web pages) |
| `ssdp` | same | UPnP text (server, name, vendor, model) |
| `cert` | same | HTTPS certificate: organisation, name, alternative names, issuer (“noise” values such as `localhost` or an IP address are dropped) |
| `ports_any` / `ports_all` | list of ports | at least one / all open |
| `mdns_service` | text or list | announced services (`_ipp._tcp`, `_googlecast._tcp`…) |
| `mac_prefix` | `"aa:bb:cc"` or list | start of the MAC address (1 to 6 bytes) |
| `in_network` | `"192.168.20.0/24"` | the IP address belongs to the range |
| `gateway` | `true` / `false` | is (or is not) the gateway |

Regular expressions ignore case. If the device was renamed by hand, its **automatic** name is the one compared.

## Models (`models`)

They map a model identifier to a readable name, and optionally to a type (which then becomes a clue). They take precedence
over the built-in table (`iPhone14,2` → “iPhone 13 Pro”, etc.). An unknown identifier falls back to its family (“iPhone”),
never to a guessed name.

## File safety

A rules file can be exchanged (menu *Export… / Import…*), so it is treated as **untrusted**: 256 KB at most, 500 rules at
most, patterns of 200 characters at most, patterns with nested quantifiers (`(a+)+`…, risk of hanging) refused, tested text
truncated to 400 characters. An invalid rule is ignored with a warning; it never breaks a scan.
