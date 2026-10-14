#!/bin/sh
# Lance Panther depuis les sources. Crée le venv et installe PyQt6 au premier lancement.
cd "$(dirname "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt || exit 1
fi
exec .venv/bin/python -m panther "$@"
