#!/bin/sh
# Installateur Panther pour Linux (sans droits administrateur).
#   ./installer/install.sh                 installe dans ~/.local/share/panther
#   ./installer/install.sh --uninstall     désinstalle (la configuration ~/.config/Panther est conservée)
#   ./installer/install.sh --prefix DIR    autre dossier d'installation
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/panther"
BIN="$HOME/.local/bin"
ACTION=install

while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall) ACTION=uninstall ;;
    --prefix) shift; PREFIX="${1:?--prefix demande un dossier}" ;;
    -h|--help) sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; exit 2 ;;
  esac
  shift
done

[ "$(uname -s)" = Linux ] || { echo "Panther ne fonctionne que sous Linux pour le moment." >&2; exit 1; }
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"

if [ "$ACTION" = uninstall ]; then
  rm -rf "$PREFIX" "$BIN/panther" "$APPS/panther.desktop"
  echo "Panther désinstallé. Vos réglages et l'historique restent dans ~/.config/Panther (à supprimer à la main si besoin)."
  exit 0
fi

PY=""
for c in python3.13 python3.12 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 12))' 2>/dev/null; then PY=$c; break; fi
done
[ -n "$PY" ] || { echo "Python 3.12 ou plus récent est nécessaire." >&2; exit 1; }

echo "Installation dans $PREFIX avec $($PY --version)…"
"$PY" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/python" -m pip install --quiet --upgrade pip
if [ "${PANTHER_NO_DEPS:-}" = 1 ]; then   # utilisé par les tests : pas de téléchargement de PyQt6
  "$PREFIX/venv/bin/python" -m pip install --quiet --no-deps "$ROOT"
else
  "$PREFIX/venv/bin/python" -m pip install --quiet "$ROOT"
fi

mkdir -p "$BIN" "$APPS"
cat > "$BIN/panther" <<EOF
#!/bin/sh
exec "$PREFIX/venv/bin/python" -m panther "\$@"
EOF
chmod 755 "$BIN/panther"

ICON="$PREFIX/panther.svg"
cp "$ROOT/panther/assets/panther.svg" "$ICON"
cat > "$APPS/panther.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Panther
Comment=Scanner et cartographie de réseau local
Exec=$BIN/panther
Icon=$ICON
Categories=Network;System;
Terminal=false
EOF

echo "Terminé. Lancez « panther » (ou « panther --demo » pour essayer sans rien scanner)."
case ":$PATH:" in *":$BIN:"*) ;; *) echo "Ajoutez $BIN à votre PATH pour lancer « panther » depuis un terminal." ;; esac
