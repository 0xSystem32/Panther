"""Mémoire des appareils (SQLite, stdlib) : historique de présence, journal d'événements, confiance.

Une ligne par appareil, clé = adresse MAC (ou IP quand il n'y a pas de MAC, par exemple au-delà
d'un routeur). Chaque scan terminé est enregistré ; le journal garde les événements utiles :
nouvel appareil, changement d'IP, passage hors ligne, retour en ligne, confiance accordée/retirée.
"""
import hashlib
import json
import os
import re
import sqlite3
import time

from . import compare, privacy, security, store
from .i18n import tr

PATH = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "Panther", "panther.db")
OFFLINE_DAYS = 14        # au-delà, un appareil absent n'est plus affiché
OFFLINE_AFTER = 2        # nombre de scans manqués avant de le déclarer hors ligne (évite les faux « hors ligne »)
KEEP_SCANS_DAYS = 90     # durée de conservation de la présence détaillée
KEEP_EVENTS_DAYS = 365
VERSION = 7
KEEP_SNAPSHOTS = True

_BASE = """CREATE TABLE IF NOT EXISTS devices(
    key TEXT PRIMARY KEY, mac TEXT, ip TEXT, name TEXT, type TEXT, vendor TEXT, network TEXT,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL)"""


def _migrate(con):
    v = con.execute("PRAGMA user_version").fetchone()[0]
    if v < 1:  # v0 = base de la Phase 3 (sans confiance ni historique)
        cols = {r[1] for r in con.execute("PRAGMA table_info(devices)")}
        for col, ddl in (("trusted", "INTEGER NOT NULL DEFAULT 0"), ("online", "INTEGER NOT NULL DEFAULT 1"),
                         ("misses", "INTEGER NOT NULL DEFAULT 0")):
            if col not in cols:
                con.execute(f"ALTER TABLE devices ADD COLUMN {col} {ddl}")
        con.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, "
                    "depth TEXT, networks TEXT)")
        con.execute("CREATE TABLE IF NOT EXISTS seen(scan_id INTEGER NOT NULL, key TEXT NOT NULL, ip TEXT)")
        con.execute("CREATE INDEX IF NOT EXISTS seen_key ON seen(key, scan_id)")
        con.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, "
                    "key TEXT, name TEXT, kind TEXT NOT NULL, detail TEXT)")
        con.execute("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)")
    if v < 2:  # positions des nœuds sur la carte (une par disposition et par appareil)
        con.execute("CREATE TABLE IF NOT EXISTS positions(layout TEXT NOT NULL, key TEXT NOT NULL, x REAL NOT NULL, "
                    "y REAL NOT NULL, PRIMARY KEY(layout, key))")
    if v < 3:  # constats de sécurité suivis dans le temps
        con.execute("CREATE TABLE IF NOT EXISTS findings(key TEXT NOT NULL, rule TEXT NOT NULL, severity TEXT, title TEXT, "
                    "first_seen REAL NOT NULL, last_seen REAL NOT NULL, PRIMARY KEY(key, rule))")
        con.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
    if v < 4:  # instantanés des scans (dédoublonnés) pour pouvoir les comparer
        con.execute("CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT UNIQUE NOT NULL, data TEXT NOT NULL)")
        if "snapshot_id" not in {r[1] for r in con.execute("PRAGMA table_info(scans)")}:
            con.execute("ALTER TABLE scans ADD COLUMN snapshot_id INTEGER")
    if v < 5:  # fusion d'appareils : une ancienne MAC devient l'alias de l'appareil actuel
        con.execute("CREATE TABLE IF NOT EXISTS aliases(alias TEXT PRIMARY KEY, key TEXT NOT NULL)")
    if v < 6:  # étiquettes, notes et groupe choisis par l'utilisateur
        con.execute("CREATE TABLE IF NOT EXISTS device_meta(key TEXT PRIMARY KEY, note TEXT NOT NULL DEFAULT '', "
                    "tags TEXT NOT NULL DEFAULT '', grp TEXT NOT NULL DEFAULT '')")
    if v < 7:  # latence mesurée (ping) à chaque scan complet
        if "rtt" not in [r[1] for r in con.execute("PRAGMA table_info(seen)")]:
            con.execute("ALTER TABLE seen ADD COLUMN rtt REAL")
    con.execute(f"PRAGMA user_version={VERSION}")


def _connect():
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    con = sqlite3.connect(PATH, timeout=5)
    con.row_factory = sqlite3.Row
    con.execute(_BASE)
    _migrate(con)
    privacy.harden(PATH)  # la base décrit votre réseau : lisible par vous seul
    return con


def _key(dev):
    """Identité d'un appareil : la clé résolue au dernier enregistrement, sinon MAC (ou IP à défaut)."""
    return dev.get("key") or store.key_for(dev)


def _rekey(con, old, new, mac):
    """Un appareil connu sous une ancienne clé (ex. « ip:10.0.0.5 ») gagne sa MAC : on garde tout son historique."""
    con.execute("UPDATE devices SET key=?, mac=? WHERE key=?", (new, mac, old))
    con.execute("UPDATE seen SET key=? WHERE key=?", (new, old))
    con.execute("UPDATE events SET key=? WHERE key=?", (new, old))
    store.move_override(old, new)  # le nom/type choisi à la main suit l'appareil


def _resolve(con, d, seen_keys):
    """Retrouve l'appareil en base : MAC d'abord, l'IP n'est qu'un indice quand la MAC manque d'un côté.
    Évite les doublons quand l'adresse IP change ou quand la MAC n'est pas lisible pour un scan."""
    key = store.key_for(d)
    alias = con.execute("SELECT key FROM aliases WHERE alias=?", (key,)).fetchone()
    if alias:  # cette MAC a été fusionnée avec un autre appareil
        if alias["key"] not in seen_keys and con.execute("SELECT 1 FROM devices WHERE key=?", (alias["key"],)).fetchone():
            return alias["key"]
        # l'appareil fusionné n'existe plus, ou l'autre MAC est déjà présente dans ce scan : on garde l'identité brute
        if alias["key"] in seen_keys:
            return key
        con.execute("DELETE FROM aliases WHERE alias=?", (key,))
    if con.execute("SELECT 1 FROM devices WHERE key=?", (key,)).fetchone():
        return key
    if d.get("mac"):
        old = "ip:" + d["ip"]  # connu jusque-là sans MAC (au-delà d'un routeur, avant SNMP…)
        if old not in seen_keys and con.execute("SELECT 1 FROM devices WHERE key=?", (old,)).fetchone():
            _rekey(con, old, key, d["mac"])
    else:
        r = con.execute("SELECT key FROM devices WHERE ip=? AND network=? AND key NOT LIKE 'ip:%'", (d["ip"], d.get("network", ""))).fetchall()
        free = [x["key"] for x in r if x["key"] not in seen_keys]
        if len(free) == 1:  # même IP, même réseau, un seul appareil connu avec MAC : c'est lui
            return free[0]
    return key


def _event(con, now, key, name, kind, detail=""):
    con.execute("INSERT INTO events(ts, key, name, kind, detail) VALUES(?,?,?,?,?)", (now, key, name, kind, detail))
    return (kind, key, name, detail)


def record_scan(devices, now=None, networks=None, depth="normal"):
    """Enregistre un scan terminé. -> {new: [clés], baseline: bool, events: int}.

    `networks` : plages réellement scannées ; seuls les appareils de ces plages peuvent être déclarés
    absents. La toute première analyse sert de référence : rien n'y est « nouveau »."""
    now = now or time.time()
    con = _connect()
    try:
        baseline = con.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
        scan_id = con.execute("INSERT INTO scans(ts, depth, networks) VALUES(?,?,?)",
                              (now, depth, ",".join(networks or []))).lastrowid
        new: list = []
        seen_keys: set = set()
        n_events, recs, evs = 0, [], []
        for d in devices:
            if not d.get("online", True):
                continue
            key = _resolve(con, d, seen_keys)
            d["key"] = key
            seen_keys.add(key)
            recs.append(compare.snapshot_record(d))
            name = d.get("auto_hostname", d["hostname"])
            vals = (d["ip"], d["mac"], name, d.get("auto_type", d["type"]), d["vendor"], d.get("network", ""), now)
            row = con.execute("SELECT ip, online FROM devices WHERE key=?", (key,)).fetchone()
            if row is None:
                con.execute("INSERT INTO devices(ip, mac, name, type, vendor, network, last_seen, key, first_seen, "
                            "online, misses) VALUES(?,?,?,?,?,?,?,?,?,1,0)", vals + (key, now))
                evs.append(_event(con, now, key, name or d["ip"], "first_seen", tr("première analyse") if baseline else d["ip"]))
                n_events += 1
                if not baseline:
                    new.append(key)
            else:
                if row["ip"] != d["ip"]:
                    evs.append(_event(con, now, key, name or d["ip"], "ip_changed", f"{row['ip']} → {d['ip']}"))
                    n_events += 1
                if not row["online"]:
                    evs.append(_event(con, now, key, name or d["ip"], "online", tr("de retour sur le réseau")))
                    n_events += 1
                con.execute("UPDATE devices SET ip=?, mac=COALESCE(NULLIF(?, ''), mac), name=?, type=?, vendor=?, network=?, "
                            "last_seen=?, online=1, misses=0 WHERE key=?", vals + (key,))
            rtt = d.get("rtt")
            con.execute("INSERT INTO seen(scan_id, key, ip, rtt) VALUES(?,?,?,?)",
                        (scan_id, key, d["ip"], float(rtt) if isinstance(rtt, (int, float)) and 0 <= rtt < 60000 else None))
        if networks:  # appareils connus de ces plages mais absents de ce scan
            marks = ",".join("?" * len(networks))
            for r in con.execute(f"SELECT key, ip, name, online, misses FROM devices WHERE network IN ({marks})",
                                 list(networks)).fetchall():
                if r["key"] in seen_keys:
                    continue
                misses = r["misses"] + 1
                went_off = r["online"] and misses >= OFFLINE_AFTER
                con.execute("UPDATE devices SET misses=?, online=? WHERE key=?",
                            (misses, 0 if went_off else r["online"], r["key"]))
                if went_off:
                    evs.append(_event(con, now, r["key"], r["name"] or r["ip"], "offline", tr("absent de {misses} scans", misses=misses)))
                    n_events += 1
        con.execute("UPDATE scans SET snapshot_id=? WHERE id=?", (_save_snapshot(con, recs), scan_id))
        con.execute("DELETE FROM seen WHERE scan_id IN (SELECT id FROM scans WHERE ts < ?)", (now - KEEP_SCANS_DAYS * 86400,))
        con.execute("DELETE FROM scans WHERE ts < ?", (now - KEEP_SCANS_DAYS * 86400,))
        con.execute("DELETE FROM snapshots WHERE id NOT IN (SELECT snapshot_id FROM scans WHERE snapshot_id IS NOT NULL)")
        con.execute("DELETE FROM events WHERE ts < ?", (now - KEEP_EVENTS_DAYS * 86400,))
        con.commit()
        return {"new": new, "baseline": baseline, "events": n_events, "event_list": evs}
    finally:
        con.close()


def _save_snapshot(con, recs):
    """Un instantané identique au précédent n'est stocké qu'une fois (un scan toutes les 5 min reste léger)."""
    data = json.dumps(sorted(recs, key=lambda r: r["key"]), sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha1(data.encode()).hexdigest()
    row = con.execute("SELECT id FROM snapshots WHERE hash=?", (digest,)).fetchone()
    if row:
        return row["id"]
    return con.execute("INSERT INTO snapshots(hash, data) VALUES(?,?)", (digest, data)).lastrowid


MAX_TAGS, MAX_TAG_LEN, MAX_NOTE, MAX_GROUP = 12, 30, 2000, 40


def clean_tags(tags):
    """Liste d'étiquettes propre : sans doublons (casse ignorée), sans virgules ni retours à la ligne, bornée."""
    out, seen = [], set()
    for t in (tags if isinstance(tags, (list, tuple)) else str(tags or "").split(",")):
        t = " ".join(str(t).replace("\n", " ").replace(",", " ").split())[:MAX_TAG_LEN]
        if t and t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return out[:MAX_TAGS]


def _meta_map(con):
    return {r["key"]: {"note": r["note"], "tags": [t for t in r["tags"].split("\n") if t], "group": r["grp"]}
            for r in con.execute("SELECT key, note, tags, grp FROM device_meta")}


def _merge_meta(con, into, src):
    m = _meta_map(con)
    a, b = m.get(into), m.get(src)
    if not b:
        return
    merged_tags = clean_tags((a or {}).get("tags", []) + b["tags"])
    note = " | ".join(x for x in ((a or {}).get("note", ""), b["note"]) if x)[:MAX_NOTE]
    group = (a or {}).get("group") or b["group"]
    con.execute("INSERT OR REPLACE INTO device_meta(key, note, tags, grp) VALUES(?,?,?,?)", (into, note, "\n".join(merged_tags), group))
    con.execute("DELETE FROM device_meta WHERE key=?", (src,))


def set_meta(dev, note=None, tags=None, group=None):
    """Enregistre étiquettes, note et groupe d'un appareil (champs omis : inchangés ; tout vide : entrée supprimée)."""
    key = _key(dev)
    con = _connect()
    try:
        cur = _meta_map(con).get(key, {"note": "", "tags": [], "group": ""})
        note = cur["note"] if note is None else str(note).strip()[:MAX_NOTE]
        tags = cur["tags"] if tags is None else clean_tags(tags)
        group = cur["group"] if group is None else " ".join(str(group).split())[:MAX_GROUP]
        if note or tags or group:
            con.execute("INSERT OR REPLACE INTO device_meta(key, note, tags, grp) VALUES(?,?,?,?)", (key, note, "\n".join(tags), group))
        else:
            con.execute("DELETE FROM device_meta WHERE key=?", (key,))
        con.commit()
        dev["note"], dev["tags"], dev["group"] = note, tags, group
    finally:
        con.close()


def meta_groups():
    """Groupes déjà utilisés (pour les proposer à la saisie)."""
    con = _connect()
    try:
        return sorted({m["group"] for m in _meta_map(con).values() if m["group"]}, key=str.lower)
    finally:
        con.close()


def alias_map():
    """{ancienne MAC: MAC de l'appareil actuel} pour les appareils fusionnés."""
    con = _connect()
    try:
        return {r["alias"]: r["key"] for r in con.execute("SELECT alias, key FROM aliases")}
    finally:
        con.close()


def _canonical(con, records):
    """Les instantanés anciens portent l'ancienne clé : on la remplace par la clé actuelle (comparaisons cohérentes après fusion)."""
    al = {r["alias"]: r["key"] for r in con.execute("SELECT alias, key FROM aliases")}
    for r in records:
        r["key"] = al.get(r["key"], r["key"])
    return records


def merge_devices(into_key, from_key, now=None):
    """Regroupe `from_key` dans `into_key` : historique de présence, journal, constats, positions, confiance et réglages
    manuels ; l'ancienne clé devient un alias (les futurs scans qui la voient sont rattachés à `into_key`)."""
    now = now or time.time()
    if into_key == from_key:
        raise ValueError(tr("Impossible de fusionner un appareil avec lui-même."))
    con = _connect()
    try:
        a = con.execute("SELECT * FROM devices WHERE key=?", (into_key,)).fetchone()
        b = con.execute("SELECT * FROM devices WHERE key=?", (from_key,)).fetchone()
        if a is None or b is None:
            raise ValueError(tr("Appareil inconnu dans l'historique."))
        con.execute("UPDATE seen SET key=? WHERE key=?", (into_key, from_key))
        con.execute("UPDATE events SET key=? WHERE key=?", (into_key, from_key))
        con.execute("INSERT OR IGNORE INTO findings(key, rule, severity, title, first_seen, last_seen) "
                    "SELECT ?, rule, severity, title, first_seen, last_seen FROM findings WHERE key=?", (into_key, from_key))
        con.execute("DELETE FROM findings WHERE key=?", (from_key,))
        con.execute("INSERT OR IGNORE INTO positions(layout, key, x, y) SELECT layout, ?, x, y FROM positions WHERE key=?", (into_key, from_key))
        con.execute("DELETE FROM positions WHERE key=?", (from_key,))
        con.execute("UPDATE devices SET first_seen=?, last_seen=?, trusted=? WHERE key=?",
                    (min(a["first_seen"], b["first_seen"]), max(a["last_seen"], b["last_seen"]), max(a["trusted"], b["trusted"]), into_key))
        con.execute("DELETE FROM devices WHERE key=?", (from_key,))
        _merge_meta(con, into_key, from_key)
        con.execute("UPDATE aliases SET key=? WHERE key=?", (into_key, from_key))
        con.execute("INSERT OR REPLACE INTO aliases(alias, key) VALUES(?, ?)", (from_key, into_key))
        store.move_override(from_key, into_key, keep_src=False)
        _event(con, now, into_key, a["name"] or a["ip"], "merged", tr("fusionné avec {name} ({from_key})", name=b['name'] or b['ip'], from_key=from_key))
        con.commit()
    finally:
        con.close()


def last_snapshot_map():
    """Appareils du dernier scan enregistré, par clé : sert au scan de présence (ne pas tout réanalyser)."""
    con = _connect()
    try:
        row = con.execute("SELECT n.data FROM scans s JOIN snapshots n ON n.id = s.snapshot_id "
                          "WHERE s.snapshot_id IS NOT NULL ORDER BY s.id DESC LIMIT 1").fetchone()
        return {r["key"]: r for r in _canonical(con, json.loads(row["data"]))} if row else {}
    finally:
        con.close()


def list_scans(limit=200):
    """Scans comparables, du plus récent au plus ancien : [{id, ts, depth, networks, count}]."""
    con = _connect()
    try:
        return [dict(r) for r in con.execute(
            "SELECT s.id, s.ts, s.depth, s.networks, (SELECT COUNT(*) FROM seen WHERE scan_id=s.id) AS count "
            "FROM scans s WHERE s.snapshot_id IS NOT NULL ORDER BY s.id DESC LIMIT ?", (limit,))]
    finally:
        con.close()


def load_snapshot(scan_id):
    """Appareils en ligne lors d'un scan (liste d'enregistrements), ou None."""
    con = _connect()
    try:
        row = con.execute("SELECT n.data FROM scans s JOIN snapshots n ON n.id = s.snapshot_id WHERE s.id=?", (scan_id,)).fetchone()
        return _canonical(con, json.loads(row["data"])) if row else None
    finally:
        con.close()


def db_stats():
    """Taille et contenu de la base : {size, devices, scans, events, snapshots, oldest_scan}."""
    con = _connect()
    try:
        n = lambda t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        oldest = con.execute("SELECT MIN(ts) FROM scans").fetchone()[0]
        out = {"devices": n("devices"), "scans": n("scans"), "events": n("events"), "snapshots": n("snapshots"), "oldest_scan": oldest}
    finally:
        con.close()
    out["size"] = os.path.getsize(PATH) if os.path.exists(PATH) else 0
    return out


def purge(scans_days, events_days=None, now=None):
    """Supprime la présence détaillée et les instantanés de plus de `scans_days` jours et le journal de plus de `events_days`
    (par défaut identique), puis compacte le fichier. -> {scans, events} supprimés. Les appareils connus sont conservés."""
    now = now or time.time()
    events_days = scans_days if events_days is None else events_days
    con = _connect()
    try:
        cutoff = now - scans_days * 86400
        old = [r[0] for r in con.execute("SELECT id FROM scans WHERE ts < ?", (cutoff,))]
        con.execute("DELETE FROM seen WHERE scan_id IN (SELECT id FROM scans WHERE ts < ?)", (cutoff,))
        con.execute("DELETE FROM scans WHERE ts < ?", (cutoff,))
        con.execute("DELETE FROM snapshots WHERE id NOT IN (SELECT snapshot_id FROM scans WHERE snapshot_id IS NOT NULL)")
        ev = con.execute("DELETE FROM events WHERE ts < ?", (now - events_days * 86400,)).rowcount
        con.commit()
        con.execute("VACUUM")  # rend l'espace au disque
        return {"scans": len(old), "events": ev}
    finally:
        con.close()


def erase_all():
    """Efface tout l'historique : appareils, scans, présence, journal, instantanés, positions, constats, alias, étiquettes et notes.
    Les pages libérées sont écrasées (secure_delete) puis le fichier est compacté. -> nombre de lignes supprimées."""
    con = _connect()
    try:
        con.execute("PRAGMA secure_delete=ON")
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        removed = 0
        for t in tables:
            removed += con.execute(f'DELETE FROM "{t}"').rowcount  # noms issus de sqlite_master, jamais de l'utilisateur
        con.commit()
        con.execute("VACUUM")
        return removed
    finally:
        con.close()


def _stub(row):
    """Appareil absent du scan courant, reconstruit depuis la base (mêmes champs qu'un appareil scanné)."""
    return {"ip": row["ip"], "mac": row["mac"] or "", "vendor": row["vendor"] or "", "hostname": row["name"] or "",
            "ports": [], "services": [], "banners": {}, "ttl": None, "is_gateway": False, "is_self": False,
            "random_mac": False, "online": False, "os": "", "type": row["type"] or "unknown", "confidence": 0,
            "reasons": [], "model": "", "mdns_services": [], "mdns_names": [], "mdns_txt": {}, "ssdp": {},
            "network": row["network"] or "", "vlan": None, "path": [], "last_seen": row["last_seen"],
            "first_seen": row["first_seen"], "trusted": bool(row["trusted"]), "key": row["key"]}


def known_offline(online_keys, cidrs, now=None, days=OFFLINE_DAYS):
    """Appareils connus des réseaux scannés, vus récemment mais absents de ce scan."""
    if not cidrs:
        return []
    now = now or time.time()
    con = _connect()
    try:
        marks = ",".join("?" * len(cidrs))
        rows = con.execute(f"SELECT * FROM devices WHERE network IN ({marks}) AND last_seen >= ? ORDER BY ip",
                           (*cidrs, now - days * 86400)).fetchall()
        online_keys, meta = set(online_keys), _meta_map(con)
        out = []
        for r in rows:
            if r["key"] in online_keys:
                continue
            d = _stub(r)
            m = meta.get(r["key"], {})
            d["note"], d["tags"], d["group"] = m.get("note", ""), list(m.get("tags", [])), m.get("group", "")
            out.append(d)
        return out
    finally:
        con.close()


def annotate(devices, now=None):
    """Ajoute `trusted`, `first_seen`, `last_seen` aux appareils d'un scan."""
    now = now or time.time()
    con = _connect()
    try:
        rows = {r["key"]: r for r in con.execute("SELECT key, trusted, first_seen, last_seen FROM devices")}
        meta = _meta_map(con)
        for d in devices:
            r = rows.get(_key(d))
            m = meta.get(_key(d), {})
            d["note"], d["tags"], d["group"] = m.get("note", ""), list(m.get("tags", [])), m.get("group", "")
            d["trusted"] = bool(r and r["trusted"])
            if r:
                d["first_seen"] = r["first_seen"]
                d.setdefault("last_seen", r["last_seen"])
    finally:
        con.close()


def set_trusted(devices, trusted, now=None):
    """Marque des appareils (dicts) comme de confiance ou non ; consigné dans le journal."""
    now = now or time.time()
    con = _connect()
    try:
        for d in devices:
            key = _key(d)
            cur = con.execute("UPDATE devices SET trusted=? WHERE key=? AND trusted<>?", (1 if trusted else 0, key, 1 if trusted else 0))
            if cur.rowcount:
                _event(con, now, key, d.get("auto_hostname", d["hostname"]) or d["ip"],
                       "trusted" if trusted else "untrusted")
            d["trusted"] = bool(trusted)
        con.commit()
    finally:
        con.close()


def forget(dev):
    """Oublie un appareil : disparaît des appareils connus et de l'historique de présence."""
    con = _connect()
    try:
        key = _key(dev)
        con.execute("DELETE FROM devices WHERE key=?", (key,))
        con.execute("DELETE FROM seen WHERE key=?", (key,))
        con.execute("DELETE FROM positions WHERE key=?", (key,))
        con.execute("DELETE FROM findings WHERE key=?", (key,))
        con.execute("DELETE FROM aliases WHERE key=? OR alias=?", (key, key))
        con.execute("DELETE FROM device_meta WHERE key=?", (key,))
        con.commit()
    finally:
        con.close()


def record_findings(devices, now=None):
    """Suit les constats de sécurité dans le temps. -> {new: [(appareil, constat)], fixed: [(appareil, titre)], baseline}.
    La première analyse de sécurité sert de référence (rien n'y est « nouveau »). Seuls les appareils analysés
    (`security` est une liste, même vide) sont examinés."""
    now = now or time.time()
    con = _connect()
    try:
        baseline = con.execute("SELECT v FROM meta WHERE k='security_baseline'").fetchone() is None
        new, fixed, analysed = [], [], 0
        for d in devices:
            if d.get("security") is None or not d.get("online", True):
                continue
            analysed += 1
            key = _key(d)
            name = d.get("auto_hostname", d["hostname"]) or d["ip"]
            current = {f["id"]: f for f in d["security"]}
            old = {r["rule"]: r for r in con.execute("SELECT rule, title FROM findings WHERE key=?", (key,))}
            for rid, f in current.items():
                if rid in old:
                    con.execute("UPDATE findings SET last_seen=?, severity=?, title=? WHERE key=? AND rule=?", (now, f["severity"], f["title"], key, rid))
                else:
                    con.execute("INSERT INTO findings(key, rule, severity, title, first_seen, last_seen) VALUES(?,?,?,?,?,?)",
                                (key, rid, f["severity"], f["title"], now, now))
                    if not baseline:
                        _event(con, now, key, name, "exposure", f"{f['title']} ({security.LABELS[f['severity']].lower()})")
                        new.append((d, f))
            for rid, r in old.items():
                if rid not in current:
                    con.execute("DELETE FROM findings WHERE key=? AND rule=?", (key, rid))
                    _event(con, now, key, name, "exposure_fixed", r["title"])
                    fixed.append((d, r["title"]))
        if analysed:  # la référence n'existe qu'une fois un appareil réellement analysé
            con.execute("INSERT OR REPLACE INTO meta(k, v) VALUES('security_baseline', '1')")
        con.commit()
        return {"new": new, "fixed": fixed, "baseline": baseline}
    finally:
        con.close()


def save_position(layout, key, x, y):
    con = _connect()
    try:
        con.execute("INSERT INTO positions(layout, key, x, y) VALUES(?,?,?,?) "
                    "ON CONFLICT(layout, key) DO UPDATE SET x=excluded.x, y=excluded.y", (layout, key, float(x), float(y)))
        con.commit()
    finally:
        con.close()


def load_positions(layout):
    con = _connect()
    try:
        return {r["key"]: (r["x"], r["y"]) for r in con.execute("SELECT key, x, y FROM positions WHERE layout=?", (layout,))}
    finally:
        con.close()


def clear_positions(layout):
    con = _connect()
    try:
        con.execute("DELETE FROM positions WHERE layout=?", (layout,))
        con.commit()
    finally:
        con.close()


def recent_events(limit=300, key=None):
    con = _connect()
    try:
        q, args = "SELECT ts, key, name, kind, detail FROM events", []
        if key:
            q += " WHERE key=?"; args.append(key)
        return [dict(r) for r in con.execute(q + " ORDER BY ts DESC, id DESC LIMIT ?", (*args, limit))]
    finally:
        con.close()


_IP_LIKE = re.compile(r"[0-9a-fA-F:.]{2,45}")
SUMMARY_KINDS = ("first_seen", "offline", "online", "exposure", "exposure_fixed", "ip_changed")


def period_summary(days=7, now=None, limit=200):
    """Ce qui s'est passé sur la période : {days, scans, groups: {kind: [{ts, name, detail, key}]}, devices: {kind: nombre d'appareils distincts}}.
    Lecture seule du journal. Les listes sont bornées (`limit` par catégorie) ; les nombres, eux, sont exacts."""
    now = time.time() if now is None else now
    since = now - days * 86400
    con = _connect()
    try:
        scans = con.execute("SELECT COUNT(*) FROM scans WHERE ts>=?", (since,)).fetchone()[0]
        groups: dict = {k: [] for k in SUMMARY_KINDS}
        distinct: dict = {k: set() for k in SUMMARY_KINDS}
        marks = ",".join("?" * len(SUMMARY_KINDS))
        for r in con.execute(f"SELECT ts, key, name, kind, detail FROM events WHERE ts>=? AND kind IN ({marks}) ORDER BY ts DESC, id DESC",
                             (since, *SUMMARY_KINDS)):
            if r["kind"] == "first_seen" and not _IP_LIKE.fullmatch(r["detail"] or ""):
                continue  # la première analyse (référence) n'est pas une arrivée : son détail est un texte, celui d'une vraie arrivée est l'adresse IP
            distinct[r["kind"]].add(r["key"] or r["name"])
            if len(groups[r["kind"]]) < limit:
                groups[r["kind"]].append({"ts": r["ts"], "name": r["name"] or "", "detail": r["detail"] or "", "key": r["key"]})
        return {"days": days, "scans": scans, "groups": groups, "devices": {k: len(v) for k, v in distinct.items()}}
    finally:
        con.close()


def latency_series(dev, last=60):
    """Latence de l'appareil à chacun de ses derniers scans de son réseau : [(horodatage, ms ou None, présent)], du plus ancien au plus récent.
    `ms` est None quand il n'y a pas de mesure (scan de présence, ou appareil absent) ; `présent` dit s'il a répondu à ce scan."""
    key = _key(dev)
    con = _connect()
    try:
        net = dev.get("network", "")
        rows = con.execute("SELECT id, ts, networks FROM scans ORDER BY id DESC LIMIT ?", (last * 4,)).fetchall()
        scans = [s for s in rows if not net or not s["networks"] or net in s["networks"].split(",")][:last]
        got = {r["scan_id"]: r["rtt"] for r in con.execute("SELECT scan_id, rtt FROM seen WHERE key=?", (key,))}
        return [(s["ts"], got.get(s["id"]), s["id"] in got) for s in reversed(scans)]
    finally:
        con.close()


def latency_summary(series):
    """Statistiques d'une série de `latency_series` : {n, min, avg, max, last, missed} (ms ; `missed` = scans où l'appareil n'a pas répondu).
    None s'il n'y a aucune mesure."""
    vals = [ms for _ts, ms, _present in series if ms is not None]
    if not vals:
        return None
    return {"n": len(vals), "min": min(vals), "avg": sum(vals) / len(vals), "max": max(vals), "last": vals[-1],
            "missed": sum(1 for _ts, _ms, present in series if not present)}


def device_summary(dev, last=48, now=None):
    """Historique d'un appareil : présence sur les `last` derniers scans de son réseau, % sur 7 jours, événements."""
    now = now or time.time()
    key = _key(dev)
    con = _connect()
    try:
        row = con.execute("SELECT first_seen, last_seen, trusted FROM devices WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        net = dev.get("network", "")
        scans = [s for s in con.execute("SELECT id, ts, networks FROM scans WHERE ts >= ? ORDER BY id", (row["first_seen"] - 1,))
                 if not net or not s["networks"] or net in s["networks"].split(",")]
        seen = {r["scan_id"] for r in con.execute("SELECT scan_id FROM seen WHERE key=?", (key,))}
        flags = [s["id"] in seen for s in scans]
        week = [s["id"] in seen for s in scans if s["ts"] >= now - 7 * 86400]
        return {"first_seen": row["first_seen"], "last_seen": row["last_seen"], "trusted": bool(row["trusted"]),
                "presence": flags[-last:], "scans": len(flags),
                "uptime7": round(100 * sum(week) / len(week)) if week else None,
                "events": recent_events(8, key)}
    finally:
        con.close()
