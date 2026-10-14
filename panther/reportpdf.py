"""Rapport de scan en PDF. `build_html` est pur (testable sans interface) ; `write_pdf` utilise Qt
(QTextDocument + QPdfWriter) : aucune dépendance supplémentaire."""
import html
import time

from . import compare
from . import security

TYPE_LABELS = {"desktop": "Ordinateur", "laptop": "Portable", "phone": "Téléphone", "tablet": "Tablette", "tv": "TV / multimédia",
               "printer": "Imprimante", "router": "Routeur / box", "switch": "Switch", "camera": "Caméra", "server": "Serveur",
               "nas": "NAS", "console": "Console de jeux", "speaker": "Enceinte connectée", "iot": "Objet connecté", "unknown": "Non identifié"}
SEV_COLORS = {"critique": "#b91c1c", "élevé": "#c2410c", "moyen": "#b7791f", "faible": "#4b5563", "info": "#4b5563"}


def esc(v):
    return html.escape("" if v is None else str(v))


def _ip_key(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (0,)


def _table(headers, rows, widths=None):
    th = "".join(f'<th align="left" bgcolor="#e5e7eb" style="padding:4px;">{esc(h)}</th>' for h in headers)
    body = "".join("<tr>" + "".join(f'<td style="padding:3px;{st}">{c}</td>' for c, st in row) + "</tr>" for row in rows)
    return f'<table width="100%" border="0" cellspacing="0" cellpadding="3"><tr>{th}</tr>{body}</table>'


def build_html(devices, networks=(), when=None, image_name=None, security_on=False, warnings=(), changes=None, image_width=680):
    """Rapport complet en HTML (sous-ensemble compris par Qt). Toute donnée venant du réseau est échappée."""
    when = time.localtime(when or time.time())
    devs = [d for d in devices if not d.get("virtual")]
    online = [d for d in devs if d.get("online", True)]
    offline = [d for d in devs if not d.get("online", True)]
    out = ['<h1 style="color:#1f2937;">Rapport de scan réseau</h1>',
           f'<p style="color:#6b7280;">Panther · {esc(time.strftime("%d/%m/%Y à %H:%M", when))}'
           + (f" · réseaux : {esc(', '.join(networks))}" if networks else "") + "</p>",
           "<h2>Résumé</h2>"]
    kinds = {}
    for d in online:
        kinds[d.get("type", "unknown")] = kinds.get(d.get("type", "unknown"), 0) + 1
    out.append(f"<p><b>{len(online)}</b> appareil(s) en ligne · <b>{len(offline)}</b> hors ligne · "
               f"<b>{sum(1 for d in online if d.get('trusted'))}</b> de confiance · "
               f"<b>{sum(1 for d in online if d.get('new'))}</b> nouveau(x) lors de ce scan</p>")
    if kinds:
        out.append("<p>" + " · ".join(f"{esc(TYPE_LABELS.get(k, k))} : {n}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])) + "</p>")
    if image_name:
        out += ["<h2>Carte du réseau</h2>", f'<p><img src="{esc(image_name)}" width="{int(image_width)}"></p>']
    if changes:
        out += ["<h2>Changements depuis le scan précédent</h2>",
                f"<p>{len(changes['new'])} nouveau(x) · {len(changes['gone'])} disparu(s) · {len(changes['changed'])} modifié(s) · "
                f"{changes['same']} inchangé(s)</p>"]
        lines = [f"<li><b>Nouveau</b> : {esc(r['name'] or r['ip'])} ({esc(r['ip'])})</li>" for r in changes["new"]]
        lines += [f"<li><b>Disparu</b> : {esc(r['name'] or r['ip'])} ({esc(r['ip'])})</li>" for r in changes["gone"]]
        lines += [f"<li><b>Modifié</b> : {esc(c['rec']['name'] or c['rec']['ip'])} – "
                  + esc(" ; ".join(compare.format_change(*ch) for ch in c["changes"])) + "</li>" for c in changes["changed"]]
        if lines:
            out.append("<ul>" + "".join(lines) + "</ul>")
    rows = []
    for d in sorted(devs, key=lambda x: _ip_key(x.get("ip", ""))):
        grey = "" if d.get("online", True) else "color:#9ca3af;"
        status = "Hors ligne" if not d.get("online", True) else "Nouveau" if d.get("new") else "En ligne"
        rows.append([(esc(d.get("hostname") or d.get("ip")), grey), (esc(d.get("ip")), grey), (esc(d.get("mac")), grey),
                     (esc(d.get("vendor")), grey), (esc(TYPE_LABELS.get(d.get("type"), d.get("type"))), grey),
                     (esc(d.get("os")), grey), (esc(status) + (" ✓" if d.get("trusted") else ""), grey)])
    out += ["<h2>Appareils</h2>", _table(["Nom", "Adresse IP", "Adresse MAC", "Fabricant", "Type", "Système", "Statut"], rows)]
    analysed = [d for d in online if d.get("security") is not None]
    if security_on and analysed:
        c = security.count_by_severity(analysed)
        out += ["<h2>Exposition (analyse en lecture seule)</h2>",
                "<p>" + (" · ".join(f"{security.LABELS[s]} : {n}" for s, n in c.items() if n) or "Aucun constat")
                + f" sur {len(analysed)} appareil(s) analysé(s). Aucun mot de passe n'a été essayé.</p>"]
        frows = [[(f'<b>{esc(security.LABELS[f["severity"]])}</b>', f"color:{SEV_COLORS[f['severity']]};"),
                  (esc(d.get("hostname") or d.get("ip")) + f' <span style="color:#6b7280;">({esc(d.get("ip"))})</span>', ""),
                  (esc(f["title"]) + (f" (port {esc(f['port'])})" if f.get("port") else ""), ""), (esc(f["remedy"]), "color:#4b5563;")]
                 for d in sorted(analysed, key=lambda x: -security.RANK.get(security.worst(x["security"]), -1)) for f in d["security"]]
        if frows:
            out.append(_table(["Gravité", "Appareil", "Constat", "Recommandation"], frows))
    if warnings:
        out += ["<h2>Avertissements du scan</h2>", "<ul>" + "".join(f"<li>{esc(w)}</li>" for w in warnings) + "</ul>"]
    out.append('<p style="color:#9ca3af;"><br>Généré par Panther. À n\'utiliser que sur des réseaux dont vous avez la responsabilité.</p>')
    return "<html><body>" + "\n".join(out) + "</body></html>"


def write_pdf(path, html_text, image=None, image_name="map"):
    """Écrit le PDF (A4, marges 15 mm). `image` : QImage de la carte, référencée par `image_name` dans le HTML."""
    from PyQt6.QtCore import QMarginsF, QSizeF, QUrl
    from PyQt6.QtGui import QFont, QPageLayout, QPageSize, QPdfWriter, QTextDocument
    w = QPdfWriter(path)
    w.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    w.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
    w.setResolution(96)  # 1 px = 1/96 pouce : la largeur de l'image du HTML correspond à la page
    w.setTitle("Rapport de scan réseau – Panther")
    w.setCreator("Panther")
    doc = QTextDocument()
    doc.setDefaultFont(QFont("sans-serif", 9))
    if image is not None:
        doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(image_name), image)
    doc.documentLayout().setPaintDevice(w)
    doc.setPageSize(QSizeF(w.width(), w.height()))
    doc.setHtml(html_text)
    doc.print(w)
