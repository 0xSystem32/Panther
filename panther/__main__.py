"""Point d'entrée : `panther` (fenêtre), `panther --cli`, `panther --web`."""
import argparse
import os
import time

from . import __version__, fingerprint
from . import log as plog


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog="panther", description="Scanner et carte de réseau local")
    ap.add_argument("--version", action="version", version=f"Panther {__version__}")
    ap.add_argument("--cli", action="store_true", help="scanner et afficher un tableau (sans interface)")
    ap.add_argument("--web", action="store_true", help="interface web locale au lieu de la fenêtre")
    ap.add_argument("--target", action="append", default=[], metavar="CIDR",
                    help="plage supplémentaire à scanner (VLAN, sous-réseau routé), répétable")
    ap.add_argument("--depth", choices=("rapide", "normal", "approfondi"), default="normal", help="profondeur du scan (mode --cli)")
    ap.add_argument("--iface", help="interface réseau à scanner (mode --cli ; défaut : route par défaut)")
    ap.add_argument("--security", action="store_true",
                    help="active l'analyse de sécurité en lecture seule (mode --cli) ; à n'utiliser que sur vos réseaux")
    ap.add_argument("--verbose", action="store_true", help="journal détaillé (aussi affiché sur la console)")
    ap.add_argument("--port", type=int, default=8765, help="port de l'interface web")
    return ap.parse_args(argv)


def run_cli(a):
    from .scanner import Scanner
    sc = Scanner()
    sc.start(a.target, depth=a.depth, security=a.security, iface=a.iface)
    while sc.snapshot()["status"] == "scanning":
        time.sleep(1)
    r = sc.snapshot()
    if r["status"] == "error":
        raise SystemExit(r["error"])
    for w in r.get("warnings", []):
        print("Attention :", w)
    print(f"{'IP':<16}{'MAC':<19}{'Nom':<18}{'Type':<9}{'OS':<26}{'Fabricant':<22}{'Réseau':<18}" + ("Exposition" if a.security else ""))
    for d in r["devices"]:
        line = (f"{d['ip']:<16}{d['mac']:<19}{d['hostname'][:16]:<18}{d['type']:<9}{d['os'][:24]:<26}"
                f"{d['vendor'][:20]:<22}{d.get('network', ''):<18}")
        if a.security and d.get("security") is not None:
            from . import security
            line += security.worst(d["security"]) or "aucun constat"
        print(line)


def main(argv=None):
    a = parse_args(argv)
    plog.setup(verbose=a.verbose)
    fingerprint.load_extra_oui(os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.txt"))
    if a.cli:
        run_cli(a)
    elif a.web:
        from .server import serve
        serve(a.port)
    else:
        try:
            from . import gui
        except ImportError as e:  # PyQt6 absent : on l'explique au lieu d'afficher une trace
            raise SystemExit(f"L'interface graphique demande PyQt6 ({e}).\n"
                             "Installez-le (pip install PyQt6) ou utilisez --cli / --web.")
        gui.main()


if __name__ == "__main__":
    main()
