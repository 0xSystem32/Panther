# Changelog

All notable changes are listed here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/). The roadmap is in [docs/ROADMAP.md](docs/ROADMAP.md) (French).

## [Unreleased]

## [0.1.0] - 2026-10-15

First release. Linux only.

### Scanning
- Own scan engine in standard-library Python: ARP (kernel neighbour table), TCP probes, SSDP, mDNS, WS-Discovery, NetBIOS,
  DHCP leases, HTTP(S) banners and titles, HTTPS certificates, traceroute, LLDP/CDP, read-only SNMP v2c and v3 (authNoPriv).
- Score-based device classification with the list of clues; custom detection rules (`rules.json`); readable model names.
- Several networks and VLANs: networks the machine is already connected to (other interfaces, routes, tagged VLANs) are scanned
  automatically, tagged VLANs through ARP; ranges can be added by hand. Scan profiles, listen-only mode (nothing is sent).
- Normal scan about 11 s on a small network, presence scan about 2 s; routed ranges are probed with all ports at once.
- IPv6 addresses per device, latency curve per device.

### Interface
- Qt window (dark by default, also light, high contrast, system), English and French, star / hierarchical / grouped-by-type maps,
  mini-map, multi-selection, keyboard navigation, adjustable text size, `--demo` fictional network.
- Banner for new devices, automatic names for anonymous devices (never overriding a name you chose), period summary,
  history with scan comparison, duplicate merging, tags, notes and groups, Wake-on-LAN.
- Local web interface (127.0.0.1 only) and command line.

### Security and privacy
- Optional read-only exposure analysis (sensitive ports, services reachable without a password).
- “Erase everything”, secrets in the system keyring, private data folder (700/600), see `SECURITY.md`.
- Alerts by webhook (Discord, Slack, ntfy, JSON) or SMTP; scheduled PDF reports.

### Packaging and quality
- `installer/install.sh`, `.deb`, wheel, man page, bash and zsh completions, release workflow on `v*` tags.
- ruff and mypy clean, fuzz, performance and packaging tests, coverage gate in CI, and `tools/lab.py`: a virtual network
  (VLANs, router, SNMP switch, LLDP/CDP frames) built without root, used by `tests/test_lab.py`.
