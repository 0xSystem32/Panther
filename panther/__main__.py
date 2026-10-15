"""Point d'entrée : `panther` (fenêtre), `panther --cli`, `panther --web`."""
import argparse
import os
import sys
import time

from . import __version__, fingerprint, i18n
from . import log as plog
from .i18n import tr


def _lang_from(argv):
    """Langue demandée par --lang (lue avant l'analyse complète pour traduire l'aide), sinon celle du système."""
    argv = list(sys.argv[1:] if argv is None else argv)
    for i, x in enumerate(argv):
        if x.startswith("--lang="):
            return x.split("=", 1)[1]
        if x == "--lang" and i + 1 < len(argv):
            return argv[i + 1]
    return None


def parse_args(argv=None):
    i18n.set_language(_lang_from(argv) or i18n.detect())
    ap = argparse.ArgumentParser(prog="panther", description=tr("Scanner et carte de réseau local"))
    ap.add_argument("--version", action="version", version=f"Panther {__version__}")
    ap.add_argument("--cli", action="store_true", help=tr("scanner et afficher un tableau (sans interface)"))
    ap.add_argument("--web", action="store_true", help=tr("interface web locale au lieu de la fenêtre"))
    ap.add_argument("--target", action="append", default=[], metavar="CIDR",
                    help=tr("plage supplémentaire à scanner (VLAN, sous-réseau routé), répétable"))
    ap.add_argument("--depth", choices=("ecoute", "rapide", "normal", "approfondi"), default="normal",
                    help=tr("profondeur du scan (mode --cli) ; ecoute = aucune sonde envoyée"))
    ap.add_argument("--iface", help=tr("interface réseau à scanner (mode --cli ; défaut : route par défaut)"))
    ap.add_argument("--security", action="store_true",
                    help=tr("active l'analyse de sécurité en lecture seule (mode --cli) ; à n'utiliser que sur vos réseaux"))
    ap.add_argument("--demo", action="store_true",
                    help=tr("réseau fictif pour essayer l'interface : aucun scan, aucune configuration lue ni écrite"))
    ap.add_argument("--lang", choices=tuple(i18n.LANGUAGES), help=tr("langue de l'interface (défaut : celle du système)"))
    ap.add_argument("--verbose", action="store_true", help=tr("journal détaillé (aussi affiché sur la console)"))
    ap.add_argument("--port", type=int, default=8765, help=tr("port de l'interface web"))
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
        print(tr("Attention :"), w)
    heads = ("IP", "MAC", tr("Nom"), tr("Type"), tr("Système"), tr("Fabricant"), tr("Réseau"))
    print("".join(f"{h:<{w}}" for h, w in zip(heads, (16, 19, 18, 9, 26, 22, 18))) + (tr("Exposition") if a.security else ""))
    for d in r["devices"]:
        line = (f"{d['ip']:<16}{d['mac']:<19}{d['hostname'][:16]:<18}{d['type']:<9}{d['os'][:24]:<26}"
                f"{d['vendor'][:20]:<22}{d.get('network', ''):<18}")
        if a.security and d.get("security") is not None:
            from . import security
            line += security.worst(d["security"]) or tr("aucun constat")
        print(line)


def main(argv=None):
    a = parse_args(argv)
    demo_dir = None
    if a.demo:
        if a.cli or a.web:
            raise SystemExit(tr("--demo s'utilise avec la fenêtre (sans --cli ni --web)."))
        try:
            from . import demo
            demo_dir = demo.isolate()  # avant tout le reste : la vraie configuration n'est jamais touchée
        except ImportError as e:
            raise SystemExit(tr("Le mode démonstration demande PyQt6 ({e}).", e=e)) from e
    plog.setup(verbose=a.verbose)
    fingerprint.load_all_oui(os.path.dirname(os.path.abspath(__file__)))
    if a.cli:
        run_cli(a)
    elif a.web:
        from .server import serve
        serve(a.port)
    else:
        try:
            from . import gui
        except ImportError as e:  # PyQt6 absent : on l'explique au lieu d'afficher une trace
            raise SystemExit(tr("L'interface graphique demande PyQt6 ({e}).\nInstallez-le (pip install PyQt6) ou utilisez --cli / --web.", e=e)) from e
        try:
            gui.main(demo=a.demo, lang=a.lang)
        finally:
            if demo_dir:
                demo.cleanup(demo_dir)


if __name__ == "__main__":
    main()
