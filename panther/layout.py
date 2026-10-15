"""Topologie en arbre : Internet → box → switch(s) → appareils, et chemins vers les autres réseaux.

Module pur (aucune dépendance graphique) : `build_tree` déduit qui est relié à quoi à partir de ce que
Panther sait vraiment (passerelle, port de switch lu en SNMP, voisins LLDP/CDP, chemins traceroute) ;
`hierarchical_positions` en calcule une disposition lisible. Sans information de switch, les appareils
sont simplement rattachés à la passerelle : on ne dessine jamais un lien qu'on ne connaît pas.
"""
import math
from collections import defaultdict

from . import store
from .i18n import tr


def dkey(d):
    return d.get("key") or store.key_for(d)


class Tree:
    def __init__(self):
        self.nodes = {}                      # id -> {id, kind, label, dev, sub, dashed, port}
        self.children = defaultdict(list)    # id -> [ids] (ordre d'insertion)
        self.parent = {}
        self.roots = []

    def add(self, nid, kind, label, parent=None, dev=None, sub="", dashed=False, port=""):
        if nid in self.nodes:
            return nid
        self.nodes[nid] = {"id": nid, "kind": kind, "label": label, "dev": dev, "sub": sub, "dashed": dashed, "port": port}
        if parent is None:
            self.roots.append(nid)
        else:
            self.children[parent].append(nid)
            self.parent[nid] = parent
        return nid

    def ancestors(self, nid):
        out = []
        while nid in self.parent:
            nid = self.parent[nid]
            out.append(nid)
        return out


def _net_label(cidr, info):
    vlan = (info.get(cidr) or {}).get("vlan")
    return cidr + (f" · VLAN {vlan}" if vlan else "")


def build_tree(devices, local_cidr, networks_info=(), paths=None, neighbors=(), snmp_info=()):
    """Construit l'arbre de la topologie. `devices` inclut les appareils hors ligne."""
    paths, info = paths or {}, {n["cidr"]: n for n in networks_info}
    t = Tree()
    local = [d for d in devices if d.get("network", local_cidr) == local_cidr]
    me = next((d for d in local if d.get("is_self")), None)
    gw = next((d for d in local if d.get("is_gateway")), None)
    if gw:
        root = t.add("virt:internet", "internet", "Internet")
        t.add(dkey(gw), "device", "", root, dev=gw)
        top = dkey(gw)
    elif me:
        t.add(dkey(me), "device", "", None, dev=me)
        top = dkey(me)
    else:
        top = None
    by_ip = {d["ip"]: d for d in devices}

    # --- switchs : appareils de type « switch » (port de table lue en SNMP ou voisin LLDP)
    names, switches = {}, [d for d in local if d.get("type") == "switch" and d is not gw]
    for d in switches:
        k = dkey(d)
        t.add(k, "device", "", top, dev=d)
        names[(d.get("hostname") or "").lower()] = k
        names[d["ip"]] = k
    for s in snmp_info:                      # le nom SNMP d'un switch peut différer de son nom réseau
        d = by_ip.get(s.get("host"))
        if d and dkey(d) in t.nodes and s.get("name"):
            names[s["name"].lower()] = dkey(d)

    # --- appareils locaux : rattachés au switch indiqué par SNMP, sinon à la passerelle
    for d in local:
        k = dkey(d)
        if k in t.nodes or top is None:
            continue
        parent = top
        sw = (d.get("switch") or "").lower()
        if sw and sw in names:
            parent = names[sw]
        elif d.get("is_self"):               # voisin LLDP/CDP direct : le switch auquel on est branché
            for n in neighbors:
                cand = names.get(n.get("mgmt_ip", "")) or names.get((n.get("name") or "").lower())
                if cand:
                    parent = cand
                    break
        t.add(k, "device", "", parent, dev=d, port=d.get("switch_port", ""))

    # --- autres réseaux : chaîne de routeurs (traceroute) puis un nœud « réseau »
    groups = defaultdict(list)
    for d in devices:
        if d.get("network", local_cidr) != local_cidr:
            groups[d["network"]].append(d)
    for n in networks_info:
        if n["cidr"] != local_cidr:
            groups.setdefault(n["cidr"], [])
    for cidr in sorted(groups):
        if top is None:
            break
        in_net = {d["ip"] for d in groups[cidr]}
        parent, gap = top, 0
        for hop in paths.get(cidr, []):
            if hop is None:
                if not t.nodes[parent]["kind"] == "gap":
                    gap += 1
                    parent = t.add(f"virt:gap:{cidr}:{gap}", "gap", "?", parent, sub=tr("saut sans réponse"), dashed=True)
            elif hop in in_net or (gw and hop == gw["ip"]):
                continue                      # la cible elle-même, ou la passerelle déjà dessinée
            elif hop in by_ip:                # un routeur du chemin qui est aussi un appareil scanné
                parent = t.add(dkey(by_ip[hop]), "device", "", parent, dev=by_ip[hop])
            else:
                parent = t.add(f"virt:hop:{hop}", "hop", hop, parent, sub="routeur", dashed=False)
        net = t.add(f"virt:net:{cidr}", "net", _net_label(cidr, info), parent, sub=tr("aucun appareil") if not groups[cidr] else "",
                    dashed=not groups[cidr])
        for d in groups[cidr]:
            t.add(dkey(d), "device", "", net, dev=d)
    return t


def hierarchical_positions(tree, col_w=135, row_h=155, max_cols=8):
    """Positions {id: (x, y)} : parents centrés au-dessus de leurs enfants ; les feuilles d'un même parent
    sont rangées en grille (max_cols par ligne) pour ne pas produire une ligne démesurée."""
    pos = {}

    def split(nid):
        kids = tree.children.get(nid, [])
        return [k for k in kids if not tree.children.get(k)], [k for k in kids if tree.children.get(k)]

    def width(nid):
        leaves, branches = split(nid)
        blocks = [width(b) for b in branches]
        if leaves:
            blocks.append(min(len(leaves), max_cols) * col_w)
        return max(col_w, sum(blocks)) if blocks else col_w

    def place(nid, left, y):
        w = width(nid)
        pos[nid] = (left + w / 2, y)
        leaves, branches = split(nid)
        x = left
        for b in branches:
            place(b, x, y + row_h)
            x += width(b)
        if leaves:
            cols = min(len(leaves), max_cols)
            for i, lf in enumerate(leaves):
                r, c = divmod(i, cols)
                pos[lf] = (x + c * col_w + col_w / 2, y + row_h + r * row_h * 0.85)

    left = 0
    for r in tree.roots:
        place(r, left, 0)
        left += width(r) + col_w
    # centre l'ensemble autour de x = 0
    if pos:
        xs = [p[0] for p in pos.values()]
        mid = (min(xs) + max(xs)) / 2
        pos = {k: (x - mid, y) for k, (x, y) in pos.items()}
    return pos


def type_clusters(devices, spacing=100, gap=70):
    """Disposition « regroupée par type » : un amas rond par type d'appareil (les plus nombreux d'abord), rangés en lignes.

    -> (positions {clé: (x, y)}, amas [{kind, count, x, y, r}]) centrés sur (0, 0). Pure et déterministe : mêmes appareils, mêmes
    positions. Les appareils d'un amas sont sur des anneaux de 6, 12, 18… places (un seul au centre)."""
    groups = defaultdict(list)
    for d in devices:
        if not d.get("virtual"):
            groups[d.get("type") or "unknown"].append(d)
    order = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    shapes = []                                   # (kind, devices, positions relatives, rayon de l'amas)
    for kind, devs in order:
        devs = sorted(devs, key=lambda d: (tuple(int(x) for x in d["ip"].split(".")) if d.get("ip", "").count(".") == 3 else (0,), dkey(d)))
        n, rel = len(devs), []
        if n == 1:
            rel, radius = [(0.0, 0.0)], 0.0
        elif n <= 6:
            radius = max(spacing * 0.75, spacing * n / (2 * math.pi))
            rel = [(radius * math.cos(-math.pi / 2 + i * 2 * math.pi / n), radius * math.sin(-math.pi / 2 + i * 2 * math.pi / n)) for i in range(n)]
        else:
            left, ring, rel = n, 1, []
            while left > 0:
                cap, radius = 6 * ring, spacing * ring
                k = min(cap, left)
                rel += [(radius * math.cos(-math.pi / 2 + i * 2 * math.pi / k), radius * math.sin(-math.pi / 2 + i * 2 * math.pi / k)) for i in range(k)]
                left -= k; ring += 1
        shapes.append((kind, devs, rel, max(radius, 0) + 75))
    # rangement en lignes (étagères) : largeur visée = un rectangle un peu plus large que haut (carte facile à lire)
    row_width = max(2 * max((sh[3] for sh in shapes), default=0), math.sqrt(sum((2 * sh[3] + gap) ** 2 for sh in shapes) * 1.6))
    placed, x, y, row_h = [], 0.0, 0.0, 0.0
    for kind, devs, rel, r in shapes:
        if x and x + 2 * r > row_width:
            x, y, row_h = 0.0, y + row_h + gap, 0.0
        placed.append((kind, devs, rel, r, x + r, y + r))
        x += 2 * r + gap
        row_h = max(row_h, 2 * r)
    if not placed:
        return {}, []
    min_x, max_x = min(c[4] - c[3] for c in placed), max(c[4] + c[3] for c in placed)
    min_y, max_y = min(c[5] - c[3] for c in placed), max(c[5] + c[3] for c in placed)
    ox, oy = (min_x + max_x) / 2, (min_y + max_y) / 2
    pos, clusters = {}, []
    for kind, devs, rel, r, cx, cy in placed:
        clusters.append({"kind": kind, "count": len(devs), "x": cx - ox, "y": cy - oy, "r": r})
        for d, (dx, dy) in zip(devs, rel):
            pos[dkey(d)] = (cx - ox + dx, cy - oy + dy)
    return pos, clusters
