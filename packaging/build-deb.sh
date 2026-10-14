#!/bin/sh
# Construit dist/panther-netscan_<version>_all.deb (Debian 13+, Ubuntu 24.04+ : Python >= 3.12 et python3-pyqt6).
# Pas de Qt embarqué : le paquet dépend de python3-pyqt6 du système.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(python3 -c "import re,sys;print(re.search(r'__version__ = \"(.+?)\"', open(sys.argv[1]).read()).group(1))" "$ROOT/panther/__init__.py")
NAME=panther-netscan
STAGE=$(mktemp -d)
chmod 755 "$STAGE"
trap 'rm -rf "$STAGE"' EXIT
OUT="$ROOT/dist"
mkdir -p "$OUT"

install -d "$STAGE/DEBIAN" "$STAGE/usr/lib/panther" "$STAGE/usr/bin" "$STAGE/usr/share/applications" \
  "$STAGE/usr/share/icons/hicolor/scalable/apps" "$STAGE/usr/share/doc/$NAME"
cp -r "$ROOT/panther" "$STAGE/usr/lib/panther/"
find "$STAGE/usr/lib/panther" -name __pycache__ -type d -prune -exec rm -rf {} +
find "$STAGE/usr/lib/panther" -type d -exec chmod 755 {} + ; find "$STAGE/usr/lib/panther" -type f -exec chmod 644 {} +

cat > "$STAGE/usr/bin/panther" <<'LAUNCH'
#!/bin/sh
exec env PYTHONPATH="/usr/lib/panther${PYTHONPATH:+:$PYTHONPATH}" python3 -m panther "$@"
LAUNCH
chmod 755 "$STAGE/usr/bin/panther"
install -m 644 "$ROOT/packaging/panther.desktop" "$STAGE/usr/share/applications/panther.desktop"
install -m 644 "$ROOT/panther/assets/panther.svg" "$STAGE/usr/share/icons/hicolor/scalable/apps/panther.svg"
install -m 644 "$ROOT/README.md" "$STAGE/usr/share/doc/$NAME/README.md"
{
  echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
  echo "Upstream-Name: Panther"; echo; echo "Files: *"; echo "Copyright: 2026 0xSystem32"; echo "License: MIT"
  sed 's/^/ /; s/^ $/ ./' "$ROOT/LICENSE"
} > "$STAGE/usr/share/doc/$NAME/copyright"
chmod 644 "$STAGE/usr/share/doc/$NAME/copyright"

SIZE=$(du -sk "$STAGE" | cut -f1)
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: $NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: all
Installed-Size: $SIZE
Depends: python3 (>= 3.12), python3-pyqt6
Recommends: traceroute
Suggests: lldpd
Maintainer: 0xSystem32 <0xSystem32@users.noreply.github.com>
Description: Scanner et cartographie de réseau local
 Panther détecte les appareils du réseau (téléphones, imprimantes, TV, caméras,
 NAS, switchs…), dessine la carte du réseau, suit l'historique de présence,
 gère plusieurs réseaux et VLAN (traceroute, SNMP, LLDP/CDP), compare deux scans
 et exporte des rapports PDF. Une analyse d'exposition optionnelle, en lecture
 seule, signale les services accessibles sans mot de passe.
 .
 À n'utiliser que sur des réseaux dont vous avez la responsabilité.
CONTROL
cat > "$STAGE/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
python3 -m compileall -q /usr/lib/panther >/dev/null 2>&1 || true
exit 0
POST
cat > "$STAGE/DEBIAN/prerm" <<'PRE'
#!/bin/sh
set -e
find /usr/lib/panther -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
exit 0
PRE
chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"

dpkg-deb --root-owner-group --build "$STAGE" "$OUT/${NAME}_${VERSION}_all.deb" >/dev/null
echo "$OUT/${NAME}_${VERSION}_all.deb"
