# Changelog

All notable changes are listed here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/). Le journal est en anglais ; les notes détaillées de développement sont dans
[AMELIORATIONS.md](AMELIORATIONS.md) (français).

## [Unreleased]

### Added
- **Detection**: custom rules (`rules.json`), HTTP(S) title/realm, HTTPS certificate, WS-Discovery, full NetBIOS, DHCP leases,
  readable model names.
- **Features**: tags, notes and groups; alerts (Discord, Slack, ntfy, JSON, SMTP); scheduled PDF reports; PNG/SVG map export;
  enriched CSV/JSON; Wake-on-LAN; vendor database update from the menu.
- **Privacy**: listen-only mode (nothing is sent), “Erase everything”, SNMP community and alert secrets in the system keyring,
  private data folder (mode 700/600), `SECURITY.md`.
- **Interface**: English and French (`--lang`, View → Language), `--demo` fictional network, grouped-by-type map layout, mini-map,
  multi-selection, system/dark/light/high-contrast themes, adjustable text size, keyboard navigation, first-run assistant.
- **Quality**: `panther/gui.py` split into the `panther/ui/` package; ruff and mypy clean; fuzz, performance and packaging tests;
  coverage gate in CI; `CONTRIBUTING.md`, pre-commit, issue templates.
- **Packaging**: man page, bash and zsh completions, release workflow (wheel + .deb attached to a GitHub release on `v*` tags).

- **Late additions**: latency curve per device, saved scan profiles, SNMP v3 (authNoPriv), TLS certificate read from servers that demand a client certificate (set-top boxes), animated final map layout, iPhone 16 models.

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
