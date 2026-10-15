"""Identifiant de modèle -> nom lisible (« iPhone14,2 » -> « iPhone 13 Pro »).

La table ne contient que des correspondances sûres ; un identifiant inconnu retombe sur sa famille (« iPhone »)
plutôt que sur un nom deviné. Les modèles définis par l'utilisateur (`rules.json`, section « models ») passent avant.
"""
import re

from . import rules
from .i18n import language

_GEN = re.compile(r"\((\d+)e génération\)")


def _ordinal(n):
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def _localize(name):
    """La table est écrite en français (« iPad (7e génération) ») : en anglais, « iPad (7th generation) »."""
    return _GEN.sub(lambda m: f"({_ordinal(int(m.group(1)))} generation)", name) if language() == "en" else name

_IPHONE = {
    "iPhone10,1": "iPhone 8", "iPhone10,4": "iPhone 8", "iPhone10,2": "iPhone 8 Plus", "iPhone10,5": "iPhone 8 Plus",
    "iPhone10,3": "iPhone X", "iPhone10,6": "iPhone X", "iPhone11,2": "iPhone XS", "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max", "iPhone11,8": "iPhone XR", "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max", "iPhone12,8": "iPhone SE (2e génération)", "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12", "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max", "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max", "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (3e génération)", "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max", "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max", "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus",
    "iPhone17,5": "iPhone 16e",
}
_IPAD = {
    "iPad7,5": "iPad (6e génération)", "iPad7,6": "iPad (6e génération)", "iPad7,11": "iPad (7e génération)",
    "iPad7,12": "iPad (7e génération)", "iPad11,6": "iPad (8e génération)", "iPad11,7": "iPad (8e génération)",
    "iPad12,1": "iPad (9e génération)", "iPad12,2": "iPad (9e génération)", "iPad13,18": "iPad (10e génération)",
    "iPad13,19": "iPad (10e génération)", "iPad11,1": "iPad mini (5e génération)", "iPad11,2": "iPad mini (5e génération)",
    "iPad14,1": "iPad mini (6e génération)", "iPad14,2": "iPad mini (6e génération)", "iPad11,3": "iPad Air (3e génération)",
    "iPad11,4": "iPad Air (3e génération)", "iPad13,1": "iPad Air (4e génération)", "iPad13,2": "iPad Air (4e génération)",
    "iPad13,16": "iPad Air (5e génération)", "iPad13,17": "iPad Air (5e génération)",
}
for _i in range(1, 5):
    _IPAD[f"iPad8,{_i}"] = "iPad Pro 11 pouces (1re génération)"
for _i in range(5, 9):
    _IPAD[f"iPad8,{_i}"] = "iPad Pro 12,9 pouces (3e génération)"
for _i in (9, 10):
    _IPAD[f"iPad8,{_i}"] = "iPad Pro 11 pouces (2e génération)"
for _i in (11, 12):
    _IPAD[f"iPad8,{_i}"] = "iPad Pro 12,9 pouces (4e génération)"
for _i in range(4, 8):
    _IPAD[f"iPad13,{_i}"] = "iPad Pro 11 pouces (3e génération)"
for _i in range(8, 12):
    _IPAD[f"iPad13,{_i}"] = "iPad Pro 12,9 pouces (5e génération)"

_MAC = {
    "MacBookAir10,1": "MacBook Air (M1, 2020)", "MacBookPro17,1": "MacBook Pro 13 pouces (M1, 2020)",
    "MacBookPro18,3": "MacBook Pro 14 pouces (M1 Pro, 2021)", "MacBookPro18,4": "MacBook Pro 14 pouces (M1 Max, 2021)",
    "MacBookPro18,1": "MacBook Pro 16 pouces (M1 Pro, 2021)", "MacBookPro18,2": "MacBook Pro 16 pouces (M1 Max, 2021)",
    "Mac14,2": "MacBook Air (M2, 2022)", "Mac14,7": "MacBook Pro 13 pouces (M2, 2022)", "Macmini9,1": "Mac mini (M1, 2020)",
    "Mac14,3": "Mac mini (M2, 2023)", "iMac21,1": "iMac 24 pouces (M1, 2021)", "iMac21,2": "iMac 24 pouces (M1, 2021)",
}
_OTHER = {
    "AppleTV5,3": "Apple TV HD", "AppleTV6,2": "Apple TV 4K (1re génération)", "AppleTV11,1": "Apple TV 4K (2e génération)",
    "AppleTV14,1": "Apple TV 4K (3e génération)", "AudioAccessory1,1": "HomePod", "AudioAccessory1,2": "HomePod",
    "AudioAccessory5,1": "HomePod mini", "AudioAccessory6,1": "HomePod (2e génération)",
}
EXACT = {**_IPHONE, **_IPAD, **_MAC, **_OTHER}

# type de l'appareil déduit de la famille de l'identifiant
_FAMILY_TYPE = (("iPhone", "phone"), ("iPad", "tablet"), ("MacBook", "laptop"), ("iMac", "desktop"), ("Macmini", "desktop"),
                ("AppleTV", "tv"), ("AudioAccessory", "speaker"))
# (motif, nom générique, type) : repli quand l'identifiant exact n'est pas dans la table
FAMILIES = [
    (re.compile(r"^iPhone\d+,\d+$"), "iPhone", "phone"), (re.compile(r"^iPad\d+,\d+$"), "iPad", "tablet"),
    (re.compile(r"^MacBook(Pro|Air)?\d+,\d+$"), "MacBook", "laptop"), (re.compile(r"^Macmini\d+,\d+$"), "Mac mini", "desktop"),
    (re.compile(r"^iMac\d+,\d+$"), "iMac", "desktop"), (re.compile(r"^Mac\d+,\d+$"), "Mac", None),
    (re.compile(r"^AppleTV\d+,\d+$"), "Apple TV", "tv"), (re.compile(r"^AudioAccessory\d+,\d+$"), "HomePod", "speaker"),
    (re.compile(r"^SM-T\w+$", re.I), "Samsung Galaxy Tab", "tablet"),
    (re.compile(r"^SM-[GAMSNFZ]\w+$", re.I), "Samsung Galaxy", "phone"),
    (re.compile(r"^(UE|QE|UN|QN)\d{2}\w+$"), "TV Samsung", "tv"),
]


def friendly(identifier, rs=None):
    """{name, type, source} ou None. `source` : « utilisateur », « table » ou « famille »."""
    ident = (identifier or "").strip()
    if not ident:
        return None
    um = rules.user_model(ident, rs)
    if um:
        return {"name": um[0], "type": um[1], "source": "utilisateur"}
    if ident in EXACT:
        kind = next((t for p, t in _FAMILY_TYPE if ident.startswith(p)), None)
        return {"name": _localize(EXACT[ident]), "type": kind, "source": "table"}
    for rx, name, kind in FAMILIES:
        if rx.match(ident):
            return {"name": _localize(f"{name} ({ident})" if name.startswith("Samsung") or name.startswith("TV") else name), "type": kind, "source": "famille"}
    return None


def describe(identifier, rs=None):
    """« iPhone 13 Pro (iPhone14,2) », « iPhone (iPhone99,9) » ou l'identifiant brut."""
    f = friendly(identifier, rs)
    if not f:
        return identifier or ""
    return f["name"] if identifier in f["name"] else f"{f['name']} ({identifier})"
