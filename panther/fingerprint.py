"""Identification des appareils : fabricant (OUI), type, OS."""
import re

from .i18n import N_, tr

# Mini table OUI (préfixe 3 octets -> fabricant). Extensible via oui.txt ("AABBCC;Fabricant").
OUI = {
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "3C5AB4": "Google", "F4F5D8": "Google", "001A11": "Google",
    "3C0754": "Apple", "A45E60": "Apple", "F0DCE2": "Apple", "28CFE9": "Apple", "98E0D9": "Apple",
    "5CF6DC": "Samsung", "8C7712": "Samsung", "FCA13E": "Samsung", "00166C": "Samsung",
    "001599": "Samsung",
    "001BA9": "Brother", "30055C": "Brother",
    "001438": "HP", "3C4A92": "HP", "9457A5": "HP", "FCB3BC": "HP",
    "000C29": "VMware", "005056": "VMware", "080027": "VirtualBox", "525400": "QEMU/KVM",
    "00155D": "Microsoft Hyper-V",
    "001132": "Synology",
    "50C7BF": "TP-Link", "F4F26D": "TP-Link", "14CC20": "TP-Link", "EC086B": "TP-Link",
    "3810D5": "AVM (Fritz!Box)", "C80E14": "AVM (Fritz!Box)",
    "00000C": "Cisco", "001B54": "Cisco",
    "B0A737": "Roku", "CC6DA0": "Roku", "18B430": "Nest",
    "44650D": "Amazon", "FCA667": "Amazon", "A002DC": "Amazon",
    "5CCF7F": "Espressif (IoT)", "240AC4": "Espressif (IoT)", "A4CF12": "Espressif (IoT)",
    "30AEA4": "Espressif (IoT)",
}
# Table volontairement réduite : déposer la liste IEEE complète dans oui.txt
# (format "AABBCC;Fabricant") pour une couverture totale.

KINDS = ("desktop", "laptop", "phone", "tablet", "tv", "printer", "router", "switch", "camera", "server",
         "nas", "console", "speaker", "iot", "unknown")
PRINTER_VENDORS = {"Canon", "Brother", "Epson", "HP", "Xerox", "Lexmark", "Ricoh", "Kyocera"}
MOBILE_VENDORS = {"Samsung", "Xiaomi", "Huawei", "OnePlus", "Oppo", "Google"}
ROUTER_VENDORS = {"TP-Link", "Netgear", "D-Link", "AVM (Fritz!Box)", "MikroTik", "Ubiquiti", "Cisco"}
CAMERA_VENDORS = {"Hikvision", "Dahua", "Reolink", "Amcrest"}
TV_VENDORS = {"Roku", "Vestel"}


# Noms IEEE -> nom court utilisé par les règles (« Apple, Inc. » -> « Apple »).
_CANON = [("Sony (PlayStation)", r"sony interactive"), ("Apple", r"apple"), ("Samsung", r"samsung"),
          ("HP", r"hewlett|hp inc|\bhp\b"), ("Brother", r"brother"), ("Canon", r"canon"),
          ("Epson", r"epson"), ("Xerox", r"xerox"), ("Lexmark", r"lexmark"), ("Ricoh", r"ricoh"),
          ("Kyocera", r"kyocera"), ("TP-Link", r"tp-?link"), ("Netgear", r"netgear"),
          ("D-Link", r"d-?link"), ("Cisco", r"cisco"), ("Huawei", r"huawei"), ("Xiaomi", r"xiaomi"),
          ("Google", r"google"), ("Amazon", r"amazon"), ("Sony", r"\bsony\b"), ("Roku", r"roku"),
          ("Synology", r"synology"), ("Espressif (IoT)", r"espressif"), ("Raspberry Pi", r"raspberry"),
          ("Hikvision", r"hikvision"), ("Dahua", r"dahua"), ("VMware", r"vmware"),
          ("Microsoft", r"microsoft"), ("Intel", r"intel corporate"), ("Ubiquiti", r"ubiquiti"),
          ("MikroTik", r"mikrotik|routerboard"), ("AVM (Fritz!Box)", r"\bavm\b"),
          ("Nest", r"nest labs"), ("Reolink", r"reolink"), ("Amcrest", r"amcrest"), ("Sonos", r"sonos"),
          ("Nintendo", r"nintendo"), ("OnePlus", r"oneplus"), ("Oppo", r"oppo")]
_CANON_RE = re.compile("|".join(f"({p})" for _, p in _CANON), re.I)
_SUFFIX_RE = re.compile(r"[,.]?\s*\b(inc|ltd|llc|gmbh|co|corp|corporation|company|limited|s\.?a|b\.?v)\b\.?", re.I)


def canonical_vendor(name):
    m = _CANON_RE.search(name)
    if m:
        return _CANON[m.lastindex - 1][0]
    return _SUFFIX_RE.sub("", name).strip(" ,.;")[:40] or name[:40]


def load_extra_oui(path):
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if ";" in line:
                    k, v = line.strip().split(";", 1)
                    OUI[k.replace(":", "").upper()[:6]] = v
    except OSError:
        pass


_TAIL_RE = re.compile(r"(?:[ ,.]+(?:inc|ltd|llc|gmbh|co|corp|corporation|company|limited|sas|sa|ag|ab|as|a\.s|bv|spa|srl|"
                      r"plc|technology|technologies|broadband|elektronik|electronics|san|ve|tic))+\.?$", re.I)


def shorten_vendor(name):
    """« Vestel Elektronik San ve Tic. A.S » -> « Vestel » (nom d'origine si tout serait retiré)."""
    return _TAIL_RE.sub("", name).strip(" ,.") or name


def load_all_oui(package_dir):
    """Base livrée avec Panther, puis celle de l'utilisateur (`~/.config/Panther/oui.txt`) qui la complète et la corrige."""
    import os
    from . import ouiupdate
    load_extra_oui(os.path.join(package_dir, "oui.txt"))
    load_extra_oui(ouiupdate.USER_PATH)


def vendor_of(mac):
    if not mac:
        return ""
    return shorten_vendor(OUI.get(mac.replace(":", "").upper()[:6], ""))


def is_random_mac(mac):
    """Bit 'localement administré' => adresse aléatoire (téléphones modernes)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, AttributeError):
        return False


def guess_os(ttl, ports, vendor, hostname, banners, model=""):
    text = " ".join(banners.values()).lower()
    if "iphone" in model or "ipad" in model:
        return "iOS / iPadOS"
    if "macbook" in model or "imac" in model or "mac mini" in model or "macmini" in model:
        return "macOS"
    if "appletv" in model or "apple tv" in model:
        return "tvOS"
    if "android" in model or "android tv" in model:
        return "Android"
    h = (hostname or "").lower()
    if "ubuntu" in text or "debian" in text:
        return "Linux (" + ("Ubuntu" if "ubuntu" in text else "Debian") + ")"
    if "raspbian" in text or vendor == "Raspberry Pi":
        return "Linux (Raspberry Pi OS)"
    if "win32" in text or "microsoft-iis" in text or 3389 in ports or 135 in ports:
        return "Windows"
    if 445 in ports and 22 not in ports and (ttl or 0) > 64:
        return "Windows"
    if vendor.startswith("Apple") or 62078 in ports or "iphone" in h or "ipad" in h \
            or "macbook" in h or "mac" in h.split("-")[0:1]:
        if 62078 in ports or "iphone" in h or "ipad" in h:
            return "iOS / iPadOS"
        return "macOS / iOS"
    if 5555 in ports or "android" in h or vendor in {"Samsung", "Xiaomi", "Huawei"}:
        return "Android"
    if 9100 in ports or 631 in ports:
        return tr("Firmware imprimante")
    if ttl:
        if ttl > 128:
            return tr("Équipement réseau (Cisco/embarqué)")
        if ttl > 64:
            return "Windows"
        return "Linux / Unix"
    return tr("Inconnu")


# --- classification par score ------------------------------------------------------
PORT_HINTS = {9100: ("printer", 40, N_("port d'impression 9100")), 631: ("printer", 40, N_("port d'impression IPP 631")),
              515: ("printer", 30, N_("port d'impression LPD 515")), 554: ("camera", 30, N_("flux vidéo RTSP (554)")),
              8009: ("tv", 30, N_("port Google Cast (8009)")), 8008: ("tv", 20, N_("port Google Cast (8008)")),
              8060: ("tv", 45, N_("contrôle Roku (8060)")), 62078: ("phone", 45, N_("synchronisation iOS (62078)")),
              5555: ("phone", 15, N_("ADB Android (5555)")), 3389: ("desktop", 30, N_("Bureau à distance (3389)")),
              135: ("desktop", 15, N_("RPC Windows (135)")), 445: ("desktop", 10, N_("partage SMB (445)")),
              5000: ("nas", 15, N_("interface NAS (5000)")), 5001: ("nas", 15, N_("interface NAS (5001)")),
              3306: ("server", 25, N_("MySQL (3306)")), 5432: ("server", 25, N_("PostgreSQL (5432)")),
              6379: ("server", 25, N_("Redis (6379)")), 27017: ("server", 25, N_("MongoDB (27017)"))}

MDNS_HINTS = {"_ipp._tcp": ("printer", 50), "_ipps._tcp": ("printer", 50), "_printer._tcp": ("printer", 50),
              "_pdl-datastream._tcp": ("printer", 50), "_scanner._tcp": ("printer", 30),
              "_googlecast._tcp": ("tv", 45), "_androidtvremote2._tcp": ("tv", 50),
              "_airplay._tcp": ("tv", 25), "_raop._tcp": ("speaker", 20), "_amzn-wplay._tcp": ("speaker", 40),
              "_companion-link._tcp": ("phone", 25), "_apple-mobdev2._tcp": ("phone", 40),
              "_hap._tcp": ("iot", 35), "_homekit._tcp": ("iot", 30), "_spotify-connect._tcp": ("speaker", 30),
              "_sonos._tcp": ("speaker", 60), "_workstation._tcp": ("desktop", 25),
              "_afpovertcp._tcp": ("desktop", 15), "_rfb._tcp": ("desktop", 15),
              "_smb._tcp": ("desktop", 10), "_daap._tcp": ("desktop", 10)}

# motif sur le modèle / nom annoncé -> (type, points). Premier motif utile gagne par type.
MODEL_PATTERNS = [
    (r"iphone", "phone", 70), (r"ipad|galaxy tab|kindle|tablet|surface go", "tablet", 70),
    (r"macbook", "laptop", 70), (r"imac|mac ?mini|mac ?pro|mac studio", "desktop", 70),
    (r"apple ?tv|appletv", "tv", 70), (r"homepod|audioaccessory", "speaker", 70),
    (r"chromecast|google tv", "tv", 70), (r"nest (audio|mini|hub)|google home", "speaker", 65),
    (r"bravia|smart ?tv|webos|tizen|roku|fire ?tv|android ?tv|shield|tv\b|televis|vewd|hbbtv|netcast|vidaa|opera tv", "tv", 60),
    (r"playstation|ps[345]\b|xbox|nintendo", "console", 70),
    (r"catalyst|procurve|managed switch|poe switch|\bswitch\b|\bsw[-_ ]?\d|^sw[-_]|[-_]sw\b|unifi switch", "switch", 55),
    (r"laserjet|officejet|deskjet|pixma|\bmfc-|\bdcp-|ecotank|workforce|photosmart|designjet|"
     r"printer|imprimante|\benvy\b|ricoh|kyocera|lexmark|xerox", "printer", 70),
    (r"ipcam|\bcam(era)?\b|\bnvr\b|\bdvr\b|doorbell|hikvision|dahua|reolink", "camera", 55),
    (r"synology|diskstation|qnap|\bnas\b|readynas|wd my cloud", "nas", 60),
    (r"echo|alexa|sonos|speaker|enceinte|soundbar", "speaker", 55),
    (r"internetgatewaydevice|router|\bbox\b|livebox|freebox|fritz|bbox|gateway", "router", 45),
    (r"galaxy|pixel|redmi|oneplus|android|xiaomi|huawei|oppo|poco", "phone", 40),
    (r"laptop|notebook|thinkpad|latitude|xps|zenbook|vivobook|pavilion|portable", "laptop", 50),
    (r"desktop|\bpc\b|workstation|tower", "desktop", 35),
]

VENDOR_PRIORS = {"printer": (PRINTER_VENDORS, 25), "camera": (CAMERA_VENDORS, 40), "tv": (TV_VENDORS, 30),
                 "router": (ROUTER_VENDORS, 20), "phone": (MOBILE_VENDORS, 10),
                 "server": ({"VMware", "VirtualBox", "QEMU/KVM", "Microsoft Hyper-V", "Raspberry Pi"}, 30),
                 "nas": ({"Synology"}, 50), "iot": ({"Espressif (IoT)", "Nest"}, 40),
                 "speaker": ({"Amazon", "Sonos"}, 25),
                 "console": ({"Sony (PlayStation)", "Nintendo"}, 40)}


def _model_text(dev):
    txt = dev.get("mdns_txt") or {}
    parts = [txt.get(k, "") for k in ("model", "md", "am", "ty", "product", "usb_mdl", "fn", "rpmd")]
    ss = dev.get("ssdp") or {}
    wd = dev.get("wsd") or {}
    parts += [ss.get("model", ""), ss.get("friendly", ""), ss.get("dtype", ""), wd.get("hardware", ""), wd.get("name", "")]
    return " ".join(p for p in parts if p).lower()


def classify_detail(dev):
    """Retourne (type, confiance 0-100, raisons[]). Chaque indice ajoute des points à un type."""
    score, why = {}, {}

    def add(kind, pts, reason):
        score[kind] = score.get(kind, 0) + pts
        why.setdefault(kind, []).append(tr(reason))

    if dev.get("is_self"):
        kind = dev.get("self_kind", "desktop")
        return kind, 100, [tr("Cette machine")]
    if dev.get("is_gateway"):
        add("router", 60, N_("passerelle par défaut du réseau"))
    if dev.get("is_switch") and not dev.get("is_gateway"):
        add("switch", 80, N_("équipement de commutation (table de ports SNMP ou voisin LLDP)"))
    for p in dev["ports"]:
        if p in PORT_HINTS:
            k, pts, r = PORT_HINTS[p]
            add(k, pts, r)
    for svc in dev.get("mdns_services", []):
        if svc in MDNS_HINTS:
            k, pts = MDNS_HINTS[svc]
            add(k, pts, tr("annonce mDNS {svc}", svc=svc))
    wtypes = " ".join((dev.get("wsd") or {}).get("types", [])).lower()  # WS-Discovery : types annoncés par l'appareil
    if "networkvideotransmitter" in wtypes:
        add("camera", 60, N_("WS-Discovery : caméra ONVIF"))
    if "printdevicetype" in wtypes or "printerservice" in wtypes:
        add("printer", 60, N_("WS-Discovery : imprimante"))
    elif "scandevicetype" in wtypes or "scannerservice" in wtypes:
        add("printer", 25, N_("WS-Discovery : scanner"))
    if "computer" in wtypes:
        add("desktop", 40, N_("WS-Discovery : ordinateur"))
    nb = dev.get("netbios") or {}
    if nb.get("file_server") or nb.get("workgroup"):
        add("desktop", 20, N_("NetBIOS : poste Windows / partage Samba"))
    ssdp = dev.get("ssdp") or {}
    dtype = (ssdp.get("dtype") or "").lower()
    if "printer" in dtype:
        add("printer", 60, N_("UPnP : imprimante"))
    if "internetgatewaydevice" in dtype:
        add("router", 50, N_("UPnP : passerelle Internet"))
    if "mediarenderer" in dtype:
        add("tv", 25, N_("UPnP : lecteur multimédia"))
    seen = set()
    for label, text, factor in ((N_("modèle"), _model_text(dev), 1.0),
                                (N_("nom"), " ".join([dev.get("hostname") or ""] + dev.get("mdns_names", []) + [dev.get("http_info") or ""]).lower(), 0.6),
                                (N_("certificat"), ((dev.get("cert") or {}).get("indicators") or "").lower(), 0.6)):
        for pat, kind, pts in MODEL_PATTERNS:
            if kind not in seen and re.search(pat, text):
                add(kind, pts * factor, tr("{label} évocateur ({match})", label=tr(label), match=re.search(pat, text).group(0).strip()))
                seen.add(kind)
    v = dev["vendor"]
    for kind, (vendors, pts) in VENDOR_PRIORS.items():
        if v and any(v.startswith(x) for x in vendors):
            add(kind, pts, tr("fabricant {vendor}", vendor=v))
    if v == "Apple" and dev.get("mdns_services") is not None and not score:
        add("phone", 10, N_("fabricant Apple"))
    if dev.get("random_mac"):
        add("phone", 20, N_("adresse MAC aléatoire (appareil mobile)"))
        add("tablet", 8, N_("adresse MAC aléatoire (appareil mobile)"))
    osn = dev.get("os", "")
    if osn == "iOS / iPadOS":
        add("phone", 20, N_("système iOS"))
    elif osn == "Android":
        add("phone", 25, N_("système Android"))
    elif osn.startswith("Windows"):
        add("desktop", 25, N_("système Windows"))
    elif osn.startswith("macOS"):
        add("desktop", 15, N_("système macOS"))
    from . import rules  # import tardif : `rules` dépend de ce module
    um = rules.user_model(dev.get("model", ""))  # modèle défini par l'utilisateur, avec un type
    if um and um[1]:
        add(um[1], 70, tr("modèle « {model} » (défini par vous)", model=um[0]))
    forced = None
    for rk, pts, reason, force in rules.evaluate(dev):  # règles personnalisées de l'utilisateur
        add(rk, pts, reason)
        forced = forced or ((rk, reason) if force else None)
    if forced:
        return forced[0], 100, [forced[1]] + [r for r in why.get(forced[0], []) if r != forced[1]][:4]
    if not score:
        return "unknown", 0, [tr("aucun indice exploitable")]
    kind = max(score, key=score.get)
    if score[kind] < 15:
        return "unknown", int(score[kind]), why[kind]
    return kind, int(min(100, score[kind])), why[kind][:6]


def classify(dev):
    return classify_detail(dev)[0]


def confidence_label(conf):
    return tr("élevée") if conf >= 70 else tr("moyenne") if conf >= 40 else tr("faible")


def vendor_hint(mac):
    """Étiquette lisible pour les MAC aléatoires."""
    return tr("MAC aléatoire") if is_random_mac(mac) else ""
