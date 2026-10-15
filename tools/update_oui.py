"""Télécharge le registre officiel IEEE (oui.csv) et génère oui.txt pour Panther.

    python3 tools/update_oui.py            # télécharge puis écrit oui.txt
    python3 tools/update_oui.py oui.csv    # convertit un oui.csv déjà téléchargé
"""
import csv
import io
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from panther import fingerprint

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "panther", "oui.txt")
MAX_BYTES = 30 * 1024 * 1024


def read_source(arg):
    if arg:
        with open(arg, encoding="utf-8-sig", newline="") as f:
            return f.read()
    req = urllib.request.Request(URL, headers={"User-Agent": "Panther-oui-updater"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise SystemExit("Fichier anormalement gros, abandon.")
    return data.decode("utf-8-sig")


def convert(text):
    rows = {}
    for rec in csv.DictReader(io.StringIO(text)):
        prefix, org = (rec.get("Assignment") or "").strip().upper(), (rec.get("Organization Name") or "").strip()
        if len(prefix) == 6 and all(c in "0123456789ABCDEF" for c in prefix) and org:
            rows[prefix] = fingerprint.canonical_vendor(org.replace(";", ","))
    return rows


def main():
    rows = convert(read_source(sys.argv[1] if len(sys.argv) > 1 else None))
    if len(rows) < 1000:
        raise SystemExit(f"Seulement {len(rows)} entrées : fichier invalide, oui.txt inchangé.")
    with open(OUT, "w", encoding="utf-8") as f:
        for k in sorted(rows):
            f.write(f"{k};{rows[k]}\n")
    print(f"{len(rows)} fabricants écrits dans {os.path.abspath(OUT)}")


if __name__ == "__main__":
    main()
