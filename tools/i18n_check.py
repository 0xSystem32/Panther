"""Contrôle des traductions : toute chaîne passée à tr() / N_() / plural() doit exister dans `panther/lang_en.py`.

    python3 tools/i18n_check.py            # affiche les clés manquantes et les entrées inutiles
    python3 tools/i18n_check.py --dump     # liste les clés (ordre du code) pour écrire de nouvelles traductions

Le test `tests/test_i18n.py` utilise les mêmes fonctions.
"""
import ast
import os
import re
import string
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PKG = os.path.join(ROOT, "panther")
FIELD = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)[^{}]*\}")


def _literal(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def collect(pkg=PKG):
    """-> ({clé: [(fichier, ligne)]}, [(fichier, ligne, source)] des appels dont l'argument n'est pas une chaîne littérale)."""
    keys, dynamic = {}, []
    for name in sorted(os.listdir(pkg)):
        if not name.endswith(".py") or name == "lang_en.py":
            continue
        path = os.path.join(pkg, name)
        with open(path, encoding="utf-8") as f:
            src = f.read()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func.id if isinstance(node.func, ast.Name) else None
            if fn in ("tr", "N_") and node.args:
                lit = _literal(node.args[0])
                if lit is not None:
                    keys.setdefault(lit, []).append((name, node.lineno))
                elif isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):  # f-string ou concaténation : la traduction ne pourrait pas la retrouver
                    dynamic.append((name, node.lineno, ast.get_source_segment(src, node)))
                # sinon : variable (valeur marquée N_ ailleurs) traduite à l'affichage
            elif fn == "plural" and len(node.args) == 3:
                for a in node.args[1:]:
                    lit = _literal(a)
                    if lit is not None:
                        keys.setdefault(lit, []).append((name, node.lineno))
    return keys, dynamic


def fields(text):
    """Noms des champs {x} d'un gabarit (les accolades doublées ne comptent pas)."""
    return {f for _lit, f, _spec, _conv in string.Formatter().parse(text) if f}


def main():
    keys, dynamic = collect()
    if "--dump" in sys.argv:
        for k in keys:
            print(repr(k))
        return 0
    sys.path.insert(0, ROOT)
    from panther.lang_en import EN
    missing = [k for k in keys if k not in EN]
    unused = [k for k in EN if k not in keys]
    for k in missing:
        print("MANQUANT :", repr(k), keys[k][0])
    for k in unused:
        print("INUTILE  :", repr(k))
    for f, line, s in dynamic:
        print("DYNAMIQUE:", f, line, s)
    print(f"{len(keys)} textes, {len(missing)} manquants, {len(unused)} inutiles, {len(dynamic)} appels non littéraux")
    return 1 if missing or unused or dynamic else 0


if __name__ == "__main__":
    sys.exit(main())
