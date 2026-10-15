# Changelog

All notable changes are listed here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/). Le journal est en anglais ; les notes détaillées de développement sont dans
[AMELIORATIONS.md](AMELIORATIONS.md) (français).

## [Unreleased]

### Fixed
- Networks that this machine already carries on another interface (tagged VLAN) are now scanned through ARP (MAC, vendor, type, VLAN
  number; own address recognised) instead of being treated as routed.
- Host probing on routed ranges tries every port at once: an empty /24 costs one timeout instead of one per port (2.5 minutes → 30 s for
  two extra ranges in the lab).

### Added
- **Detection**: custom rules (`rules.json`), HTTP(S) title/realm, HTTPS certificate, WS-Discovery, full NetBIOS, DHCP leases,
  readable model names.
- **Features**: tags, notes and groups; alerts (Discord, Slack, ntfy, JSON, SMTP); scheduled PDF reports; PNG/SVG map export;
  enriched CSV/JSON; Wake-on-LAN; vendor database update from the menu.
- **Privacy**: listen-only mode (nothing is sent), “Erase everything”, SNMP community and alert secrets in the system keyring,
  private data folder (mode 700/600), `SECURITY.md`.
- **Interface**: English and French (`--lang`, View → Language), `--demo` fictional network, grouped-by-type map layout, mini-map,
  multi-selection, system/dark/light/high-contrast themes, adjustable text size, keyboard navigation, a first-launch window that only asks for the language; deep scan and the security analysis are on by default and, like listen-only, set in the Scan menu.
- **Quality**: `panther/gui.py` split into the `panther/ui/` package; ruff and mypy clean; fuzz, performance and packaging tests;
  coverage gate in CI; `CONTRIBUTING.md`, pre-commit, issue templates.
- **Day to day**: a banner under the toolbar when a scan finds new devices (Show / Name… with a suggested name built from the type and
  vendor, e.g. “Téléphone Samsung”) — and devices without a useful name (empty, IP, “device-32”) get such a name automatically, never overriding a name you chose; *File → Period summary* (new, offline, exposures, fixed over 24 h / 7 / 30 days); the “Networks”
  button is now “Ranges to scan” with an explanatory tooltip.
- **Network lab**: `tools/lab.py` builds a virtual network without root (user + network namespaces: 802.1Q VLANs, a router, hosts with
  real services, a fake SNMP switch, real LLDP/CDP frames); `tests/test_lab.py` scans it end to end (skipped where the kernel forbids it).
- **Packaging**: man page, bash and zsh completions, release workflow (wheel + .deb attached to a GitHub release on `v*` tags).

- **Late additions**: latency curve per device, saved scan profiles, SNMP v3 (authNoPriv), TLS certificate read from servers that demand a client certificate (set-top boxes), animated final map layout, iPhone 16 models, IPv6 addresses per device.

- Networks the machine is already connected to (other interfaces, routes, VLANs) are scanned automatically (option in *Networks*); new device type *Set-top box* (operator TV decoders no longer look like TVs).

### Changed
- Scan discovery uses the kernel's ARP table: a normal scan goes from ~98 s to ~11 s on a small network; a presence scan takes ~2 s.
- Device identity is the MAC address first (an IP change is an event, never a duplicate).

### Fixed
- The PDF report pushed the map to the second page, leaving a large blank.
- Scanning a /31 or /32 range crashed the traceroute thread.
- Tooltips rendered HTML found in device names, banners and certificates; they are now escaped.

## [0.1.0] - 2026-10-14

First version: own scan engine (ARP/TCP, SSDP, mDNS, SNMP v2c, LLDP/CDP, traceroute), PyQt6 interface with star and hierarchical
maps, VLAN support, history, scan comparison, read-only security analysis, PDF/Markdown/CSV/JSON reports, web interface, wheel and
.deb packages, CI.
