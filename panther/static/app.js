const ICONS = { // tracés 24x24
  desktop:'<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>',
  laptop:'<rect x="5" y="5" width="14" height="10" rx="1.5"/><path d="M2 19h20"/>',
  phone:'<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>',
  printer:'<path d="M7 9V3h10v6M7 17H4v-7h16v7h-3"/><rect x="7" y="14" width="10" height="7"/>',
  router:'<rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 17h.01M11 17h.01M8 10a6 6 0 018 0M5.5 7.5a10 10 0 0113 0"/>',
  tv:'<rect x="3" y="5" width="18" height="12" rx="1.5"/><path d="M9 21l1-4M15 21l-1-4M10 8.5l4 2-4 2z"/>',
  tablet:'<rect x="5" y="2" width="14" height="20" rx="2"/><path d="M11 18h2"/>',
  console:'<rect x="2" y="7" width="20" height="10" rx="4"/><path d="M7 10v4M5 12h4M16 11h.01M18 13h.01"/>',
  speaker:'<rect x="6" y="2" width="12" height="20" rx="2.5"/><circle cx="12" cy="15" r="3"/><circle cx="12" cy="7" r="1"/>',
  camera:'<path d="M3 8h13v9H3zM16 11l5-3v9l-5-3"/>',
  server:'<rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/>',
  nas:'<rect x="5" y="3" width="14" height="18" rx="1.5"/><path d="M9 8h6M9 12h6M9 16h.01"/>',
  iot:'<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>',
  unknown:'<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 114 2c-.9.6-1.5 1-1.5 2M12 17h.01"/>'
};
let S = {labels: {}};   // textes traduits, fournis par le serveur (/api/strings)
const fmt = (t, o) => String(t).replace(/\{(\w+)\}/g, (_, k) => esc(o[k]));
const LABEL = t => S.labels[t] || S.labels.unknown || t;
const svg = document.getElementById('map'), panel = document.getElementById('panel');
let devices = [], selected = null, timer = null;

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ico = (t, x, y, s) => `<svg class="ico" x="${x-s/2}" y="${y-s/2}" width="${s}" height="${s}" viewBox="0 0 24 24">${ICONS[t]||ICONS.unknown}</svg>`;

function draw() {
  const W = 900, H = 640, cx = W/2, cy = H/2;
  const me = devices.find(d => d.is_self);
  const others = devices.filter(d => !d.is_self);
  const gw = others.filter(d => d.is_gateway), rest = others.filter(d => !d.is_gateway);
  const pos = new Map(); if (me) pos.set(me.ip, [cx, cy]);
  const ring = (list, r, off) => list.forEach((d, i) => {
    const a = off + i * 2 * Math.PI / Math.max(list.length, 1);
    pos.set(d.ip, [cx + r * 1.35 * Math.cos(a), cy + r * Math.sin(a)]);
  });
  ring(gw, 150, -Math.PI/2); ring(rest, 255, -Math.PI/2 + .3);
  let html = '';
  for (const d of others) { const [x, y] = pos.get(d.ip);
    html += `<line class="link ${d.is_gateway?'gw':''}" x1="${cx}" y1="${cy}" x2="${x}" y2="${y}"/>`; }
  for (const d of devices) { const [x, y] = pos.get(d.ip);
    const r = d.is_self || d.is_gateway ? 34 : 28;
    const name = d.hostname || d.ip;
    html += `<g class="node ${selected===d.ip?'sel':''}" data-ip="${esc(d.ip)}"><circle cx="${x}" cy="${y}" r="${r}"/>${ico(d.type,x,y,r)}
      <text x="${x}" y="${y+r+16}">${esc(name.slice(0,22))}</text><text class="sub" x="${x}" y="${y+r+30}">${d.is_self?esc(S.this_machine):esc(d.ip)}</text></g>`; }
  svg.innerHTML = html;
  svg.querySelectorAll('.node').forEach(n => n.onclick = () => { selected = n.dataset.ip; draw(); details(); });
}

function details() {
  const d = devices.find(x => x.ip === selected); if (!d) return;
  const row = (k, v) => v ? `<dt>${k}</dt><dd>${v}</dd>` : '';
  panel.innerHTML = `<h2>${esc(d.hostname || d.ip)}</h2><dl>
    ${row(S.type, esc(LABEL(d.type)))}${row(S.ip, esc(d.ip))}${row(S.mac, esc(d.mac))}${row(S.vendor, esc(d.vendor))}
    ${row(S.os, esc(d.os))}${row('TTL', esc(d.ttl))}
    ${row(S.services, d.services.map(s => `<span class="tag">${esc(s)}</span>`).join(''))}
    ${row(S.banners, Object.entries(d.banners).map(([p, b]) => `${p}: ${esc(b)}`).join('<br>'))}</dl>`;
}

async function poll() {
  const s = await (await fetch('/api/state')).json();
  devices = s.devices; draw(); if (selected) details();
  document.getElementById('fill').style.width = s.progress + '%';
  document.getElementById('net').textContent = s.network ? fmt(S.network, {cidr: s.network.cidr, gateway: s.network.gateway}) : '';
  document.getElementById('count').textContent = fmt(S.count, {n: devices.length});
  const btn = document.getElementById('scan'), busy = s.status === 'scanning';
  btn.disabled = busy; btn.textContent = busy ? fmt(S.scanning, {progress: s.progress}) : S.scan;
  if (s.status === 'error') panel.innerHTML = `<p class="hint">${fmt(S.error, {error: s.error})}</p>`;
  if (!busy && timer) { clearInterval(timer); timer = null; }
}
document.getElementById('scan').onclick = async () => {
  await fetch('/api/scan', {method: 'POST'}); selected = null;
  panel.innerHTML = `<p class="hint">${esc(S.scan_hint)}</p>`;
  timer = timer || setInterval(poll, 1000); poll();
};
(async () => {
  try { S = await (await fetch('/api/strings')).json(); } catch (e) { /* sans textes traduits : libellés vides */ }
  document.documentElement.lang = S.lang || 'fr';
  document.getElementById('scan').textContent = S.scan;
  panel.innerHTML = `<p class="hint">${esc(S.hint)}</p>`;
  poll();
})();
