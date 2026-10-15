"""Rapport de scan en PDF. `build_html` est pur (testable sans interface) ; `write_pdf` utilise Qt
(QTextDocument + QPdfWriter) : aucune dépendance supplémentaire."""
import html
import time

from . import compare, security
from .i18n import tr
from .labels import TYPE_LABELS

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


def map_width(image, max_w=680, max_h=470):
    """Largeur (px) de la carte dans le rapport : elle doit tenir dans la première page à côté du résumé, sinon Qt la repousse
    à la page suivante en laissant un grand blanc."""
    if image is None or image.width() <= 0 or image.height() <= 0:
        return max_w
    return max(200, min(max_w, int(max_h * image.width() / image.height())))


def build_html(devices, networks=(), when=None, image_name=None, security_on=False, warnings=(), changes=None, image_width=680):
    """Rapport complet en HTML (sous-ensemble compris par Qt). Toute donnée venant du réseau est échappée."""
    when = time.localtime(when or time.time())
    devs = [d for d in devices if not d.get("virtual")]
    online = [d for d in devs if d.get("online", True)]
    offline = [d for d in devs if not d.get("online", True)]
    out = [f'<h1 style="color:#1f2937;">{esc(tr("Rapport de scan réseau"))}</h1>',
           f'<p style="color:#6b7280;">Panther · {esc(time.strftime(tr("%d/%m/%Y à %H:%M"), when))}'
           + (esc(tr(" · réseaux : {networks}", networks=", ".join(networks))) if networks else "") + "</p>",
           f"<h2>{esc(tr('Résumé'))}</h2>"]
    kinds: dict = {}
    for d in online:
        kinds[d.get("type", "unknown")] = kinds.get(d.get("type", "unknown"), 0) + 1
    out.append("<p>" + tr("<b>{online}</b> appareil(s) en ligne · <b>{offline}</b> hors ligne · <b>{trusted}</b> de confiance · "
                         "<b>{new}</b> nouveau(x) lors de ce scan", online=len(online), offline=len(offline),
                         trusted=sum(1 for d in online if d.get("trusted")), new=sum(1 for d in online if d.get("new"))) + "</p>")
    if kinds:
        out.append("<p>" + " · ".join(f"{esc(TYPE_LABELS.get(k, k))} : {n}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])) + "</p>")
    if image_name:
        out += [f"<h2>{esc(tr('Carte du réseau'))}</h2>", f'<p><img src="{esc(image_name)}" width="{int(image_width)}"></p>']
    if changes:
        out += [f"<h2>{esc(tr('Changements depuis le scan précédent'))}</h2>",
                "<p>" + tr("{new} nouveau(x) · {gone} disparu(s) · {changed} modifié(s) · {same} inchangé(s)", new=len(changes["new"]),
                           gone=len(changes["gone"]), changed=len(changes["changed"]), same=changes["same"]) + "</p>"]
        lines = [f"<li><b>{esc(tr('Nouveau'))}</b> : {esc(r['name'] or r['ip'])} ({esc(r['ip'])})</li>" for r in changes["new"]]
        lines += [f"<li><b>{esc(tr('Disparu'))}</b> : {esc(r['name'] or r['ip'])} ({esc(r['ip'])})</li>" for r in changes["gone"]]
        lines += [f"<li><b>{esc(tr('Modifié'))}</b> : {esc(c['rec']['name'] or c['rec']['ip'])} – "
                  + esc(" ; ".join(compare.format_change(*ch) for ch in c["changes"])) + "</li>" for c in changes["changed"]]
        if lines:
            out.append("<ul>" + "".join(lines) + "</ul>")
    rows = []
    for d in sorted(devs, key=lambda x: _ip_key(x.get("ip", ""))):
        grey = "" if d.get("online", True) else "color:#9ca3af;"
        status = tr("Hors ligne") if not d.get("online", True) else tr("Nouveau") if d.get("new") else tr("En ligne")
        rows.append([(esc(d.get("hostname") or d.get("ip")), grey), (esc(d.get("ip")), grey), (esc(d.get("mac")), grey),
                     (esc(d.get("vendor")), grey), (esc(TYPE_LABELS.get(d.get("type"), d.get("type"))), grey),
                     (esc(d.get("os")), grey), (esc(status) + (" ✓" if d.get("trusted") else ""), grey)])
    out += [f"<h2>{esc(tr('Appareils'))}</h2>",
            _table([tr("Nom"), tr("Adresse IP"), tr("Adresse MAC"), tr("Fabricant"), tr("Type"), tr("Système"), tr("Statut")], rows)]
    analysed = [d for d in online if d.get("security") is not None]
    if security_on and analysed:
        c = security.count_by_severity(analysed)
        out += [f"<h2>{esc(tr('Exposition (analyse en lecture seule)'))}</h2>",
                "<p>" + esc((" · ".join(f"{security.LABELS[s]} : {n}" for s, n in c.items() if n) or tr("Aucun constat"))
                            + tr(" sur {count} appareil(s) analysé(s). Aucun mot de passe n'a été essayé.", count=len(analysed))) + "</p>"]
        frows = [[(f'<b>{esc(security.LABELS[f["severity"]])}</b>', f"color:{SEV_COLORS[f['severity']]};"),
                  (esc(d.get("hostname") or d.get("ip")) + f' <span style="color:#6b7280;">({esc(d.get("ip"))})</span>', ""),
                  (esc(f["title"]) + (esc(tr(" (port {port})", port=f["port"])) if f.get("port") else ""), ""), (esc(f["remedy"]), "color:#4b5563;")]
                 for d in sorted(analysed, key=lambda x: -security.RANK.get(security.worst(x["security"]), -1)) for f in d["security"]]
        if frows:
            out.append(_table([tr("Gravité"), tr("Appareil"), tr("Constat"), tr("Recommandation")], frows))
    if warnings:
        out += [f"<h2>{esc(tr('Avertissements du scan'))}</h2>", "<ul>" + "".join(f"<li>{esc(w)}</li>" for w in warnings) + "</ul>"]
    out.append('<p style="color:#9ca3af;"><br>' + esc(tr("Généré par Panther. À n'utiliser que sur des réseaux dont vous avez la responsabilité.")) + "</p>")
    return "<html><body>" + "\n".join(out) + "</body></html>"


def write_pdf(path, html_text, image=None, image_name="map"):
    """Écrit le PDF (A4, marges 15 mm). `image` : QImage de la carte, référencée par `image_name` dans le HTML."""
    from PyQt6.QtCore import QMarginsF, QSizeF, QUrl
    from PyQt6.QtGui import QFont, QPageLayout, QPageSize, QPdfWriter, QTextDocument
    w = QPdfWriter(path)
    w.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    w.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
    w.setResolution(96)  # 1 px = 1/96 pouce : la largeur de l'image du HTML correspond à la page
    w.setTitle(tr("Rapport de scan réseau") + " – Panther")
    w.setCreator("Panther")
    doc = QTextDocument()
    doc.setDefaultFont(QFont("sans-serif", 9))
    if image is not None:
        doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(image_name), image)
    layout = doc.documentLayout()
    if layout is not None:
        layout.setPaintDevice(w)
    doc.setPageSize(QSizeF(w.width(), w.height()))
    doc.setHtml(html_text)
    doc.print(w)
