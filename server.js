// VERTEX WEB — Admin panel service (pure Node, no dependencies)
// Serves: the editor UI (login-protected), /api/content, and the PUBLIC /content.json
// that vertex-web-tanger.onrender.com + the Pages mirror fetch to apply overrides.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.ADMIN_PASSWORD || '';
const SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';
const GH_TOKEN = process.env.GITHUB_TOKEN || '';
const GH_REPO = process.env.GITHUB_REPO || 'Bofrahi12/vertex-web';
const DATA_FILE = path.join(__dirname, 'data.json');
const DEFAULT_CONTENT = require('./default-content.json');

function mergeDefaults(c) {
  const d = DEFAULT_CONTENT;
  for (const k of Object.keys(d)) if (c[k] === undefined) c[k] = JSON.parse(JSON.stringify(d[k]));
  if (Array.isArray(c.projects) && Array.isArray(d.projects)) {
    const byPid = {}; d.projects.forEach(p => { byPid[p.pid] = p; });
    c.projects.forEach(p => { const dp = byPid[p.pid]; if (dp) for (const k of Object.keys(dp)) if (p[k] === undefined) p[k] = dp[k]; });
  }
  return c;
}
function loadContent() {
  try {
    const c = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (c && Array.isArray(c.packs) && Array.isArray(c.projects)) return mergeDefaults(c);
  } catch (e) {}
  return JSON.parse(JSON.stringify(DEFAULT_CONTENT));
}
let content = loadContent();
function persist() { try { fs.writeFileSync(DATA_FILE, JSON.stringify(content, null, 1)); } catch (e) {} }

async function commitToGitHub() {
  if (!GH_TOKEN) return 'local';
  const api = 'https://api.github.com/repos/' + GH_REPO + '/contents/site-content.json';
  const headers = { 'Authorization': 'Bearer ' + GH_TOKEN, 'Accept': 'application/vnd.github+json', 'User-Agent': 'vertex-admin', 'Content-Type': 'application/json' };
  let sha = null;
  try { const r = await fetch(api, { headers }); if (r.ok) sha = (await r.json()).sha; } catch (e) {}
  const body = { message: 'Admin panel: تحديث محتوى الموقع', content: Buffer.from(JSON.stringify(content, null, 1), 'utf8').toString('base64') };
  if (sha) body.sha = sha;
  const r = await fetch(api, { method: 'PUT', headers, body: JSON.stringify(body) });
  if (!r.ok) throw new Error('github ' + r.status);
  return 'github';
}

function sign(v) { return crypto.createHmac('sha256', SECRET).update(v).digest('hex'); }
function makeCookie() { const exp = String(Date.now() + 30 * 24 * 3600 * 1000); return exp + '.' + sign(exp); }
function authed(req) {
  const raw = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.indexOf('vxadm=') === 0);
  if (!raw) return false;
  const parts = raw.slice(6).split('.');
  if (parts.length !== 2 || sign(parts[0]) !== parts[1]) return false;
  return Date.now() < parseInt(parts[0], 10);
}
function readBody(req) {
  return new Promise(res => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > 2e6) req.destroy(); });
    req.on('end', () => res(b));
  });
}
function send(res, code, body, type, extra) {
  const headers = { 'Content-Type': type || 'text/plain; charset=utf-8' };
  if (extra) Object.assign(headers, extra);
  res.writeHead(code, headers); res.end(body);
}

const LOGIN_HTML = '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>لوحة تحكم VERTEX WEB</title><style>body{background:#07080c;color:#f2efe9;font-family:system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.box{background:#0c1017;border:1px solid rgba(215,164,65,.45);border-radius:18px;padding:30px 26px;width:min(92vw,360px);text-align:center}h1{color:#f0c569;font-size:1.3rem;margin:0 0 6px}p{color:#a8a294;font-size:.88rem}input{width:100%;box-sizing:border-box;background:#0a0d14;border:1px solid rgba(240,232,216,.2);border-radius:10px;color:#fff;padding:13px;font-size:1rem;margin:14px 0}button{width:100%;background:#d7a441;color:#191204;border:0;border-radius:10px;padding:13px;font-size:1rem;font-weight:800;cursor:pointer}.err{color:#ff9c9c;min-height:1.2em;font-size:.85rem}</style></head><body><form class="box" method="POST" action="/login"><h1>VERTEX WEB</h1><p>لوحة تحكم الموقع — خاصة بصاحب الموقع</p><div class="err" id="err"></div><input type="password" name="password" placeholder="كلمة السر" autocomplete="current-password" required><button type="submit">دخول</button></form><script>if (location.search.indexOf("e=1") > -1) document.getElementById("err").textContent = "كلمة السر غير صحيحة";</script></body></html>';

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  try {
    if (u.pathname === '/content.json') {
      return send(res, 200, JSON.stringify(content), 'application/json; charset=utf-8', { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
    }
    if (u.pathname === '/health') return send(res, 200, 'ok');
    if (u.pathname === '/login' && req.method === 'POST') {
      const body = await readBody(req);
      const pw = new URLSearchParams(body).get('password') || '';
      const ok = PASSWORD && pw.length === PASSWORD.length && crypto.timingSafeEqual(Buffer.from(pw), Buffer.from(PASSWORD));
      if (ok) return send(res, 302, '', 'text/plain', { 'Set-Cookie': 'vxadm=' + makeCookie() + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000', 'Location': '/' });
      return send(res, 302, '', 'text/plain', { 'Location': '/?e=1' });
    }
    if (u.pathname === '/logout') return send(res, 302, '', 'text/plain', { 'Set-Cookie': 'vxadm=; Path=/; Max-Age=0', 'Location': '/' });
    if (u.pathname === '/api/content') {
      if (!authed(req)) return send(res, 401, '{"error":"auth"}', 'application/json');
      if (req.method === 'GET') return send(res, 200, JSON.stringify(content), 'application/json; charset=utf-8');
      if (req.method === 'POST') {
        const body = await readBody(req);
        let c;
        try { c = JSON.parse(body); } catch (e) { return send(res, 400, '{"error":"json"}', 'application/json'); }
        if (!Array.isArray(c.packs) || c.packs.length < 1 || !Array.isArray(c.projects) || !Array.isArray(c.faq)) return send(res, 400, '{"error":"shape"}', 'application/json');
        for (const p of c.packs) { p.price = Math.max(0, parseInt(p.price, 10) || 0); p.name = String(p.name || '').slice(0, 60); }
        c.whatsapp = String(c.whatsapp || '').replace(/\D/g, '').slice(0, 15);
        if (c.homeProjects !== undefined && !Array.isArray(c.homeProjects)) return send(res, 400, '{"error":"shape"}', 'application/json');
        const cleanProj = (arr) => { if (!Array.isArray(arr)) return; for (const p of arr) { p.name = String(p.name || '').slice(0, 90); p.desc = String(p.desc || '').slice(0, 320); p.hidden = !!p.hidden; } };
        cleanProj(c.projects); cleanProj(c.homeProjects);
        if (c.texts && typeof c.texts === 'object' && !Array.isArray(c.texts)) { for (const k of Object.keys(c.texts)) c.texts[k] = String(c.texts[k] || '').slice(0, 300); } else c.texts = {};
        content = c; persist();
        let mode = 'local';
        try { mode = await commitToGitHub(); } catch (e) { mode = 'local'; }
        return send(res, 200, JSON.stringify({ ok: true, mode }), 'application/json');
      }
    }
    if (u.pathname === '/') {
      if (!authed(req)) return send(res, 200, LOGIN_HTML, 'text/html; charset=utf-8');
      return send(res, 200, UI_HTML, 'text/html; charset=utf-8');
    }
    return send(res, 404, 'not found');
  } catch (e) {
    return send(res, 500, 'error');
  }
});

const UI_HTML = `<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>لوحة تحكم VERTEX WEB</title>
<style>
body{background:#07080c;color:#f2efe9;font-family:system-ui,sans-serif;margin:0;padding:0 0 120px}
header{position:sticky;top:0;background:#0c1017ee;backdrop-filter:blur(8px);border-bottom:1px solid rgba(215,164,65,.35);padding:12px 16px;display:flex;justify-content:space-between;align-items:center;z-index:5}
header b{color:#f0c569}header a{color:#a8a294;font-size:.85rem}
main{max-width:760px;margin:0 auto;padding:16px}
section{background:#0c1017;border:1px solid rgba(240,232,216,.13);border-radius:16px;padding:18px;margin:0 0 16px}
h2{color:#f0c569;font-size:1.05rem;margin:0 0 4px}.hint{color:#a8a294;font-size:.8rem;margin:0 0 12px}
label{display:block;font-size:.82rem;font-weight:700;margin:10px 0 4px}
input,textarea{width:100%;box-sizing:border-box;background:#0a0d14;border:1px solid rgba(240,232,216,.2);border-radius:10px;color:#fff;padding:11px 12px;font-size:.95rem}
textarea{min-height:64px;resize:vertical}
.pack{display:grid;grid-template-columns:1fr 130px;gap:10px;align-items:end;border-bottom:1px dashed rgba(240,232,216,.12);padding-bottom:12px}
.row{display:flex;align-items:center;gap:8px;padding:9px 0;border-bottom:1px dashed rgba(240,232,216,.1)}
.row .nm{flex:1;font-size:.92rem}.row .nm small{display:block;color:#a8a294;font-size:.72rem}
.row.off{opacity:.42}
.mini{background:#1a2130;color:#f2efe9;border:1px solid rgba(240,232,216,.22);border-radius:9px;padding:8px 11px;font-size:.85rem;cursor:pointer;white-space:nowrap}
.mini.warn{border-color:rgba(255,156,156,.5);color:#ffb3b3}
.faqrow{border-bottom:1px dashed rgba(240,232,216,.1);padding:10px 0}
.faqrow .bar{display:flex;gap:8px;margin-top:8px}
#publish{position:fixed;bottom:0;right:0;left:0;background:#0c1017f2;border-top:1px solid rgba(215,164,65,.4);padding:12px 16px;display:flex;gap:12px;align-items:center;z-index:6}
#pubBtn{flex:1;background:#d7a441;color:#191204;border:0;border-radius:12px;padding:15px;font-size:1.05rem;font-weight:900;cursor:pointer}
#status{font-size:.85rem;color:#a8a294;flex:1}
</style></head><body>
<header><b>لوحة تحكم VERTEX WEB</b><span><a href="https://vertex-web-tanger.onrender.com" target="_blank" rel="noopener">معاينة الموقع ↗</a> · <a href="/logout">خروج</a></span></header>
<main>
<section><h2>الأسعار والباقات</h2><p class="hint">بدّل الاسم أو الثمن ثم اضغط «نشر التعديلات». الثمن يتبدل في الموقع كامل (الباقات + سطر الأسعار).</p><div id="packs"></div></section>
<section><h2>التواصل</h2><p class="hint">رقم الواتساب بصيغة دولية بلا + (مثال: 212693981822) — كيتبدل في أزرار الموقع كاملة.</p>
<label>رقم واتساب</label><input id="wa" inputmode="numeric">
<label>البريد الإلكتروني</label><input id="em" type="email"></section>
<section><h2>بطاقات الصفحة الرئيسية</h2><p class="hint">هادو هما البطاقات اللي كيبانو في أول الموقع (قسم «الأعمال»). بدّل الاسم والوصف، رتّب بالأزرار ↑ ↓، ولا خفي أي بطاقة.</p><div id="home"></div></section>
<section><h2>نصوص الصفحة الرئيسية</h2><p class="hint">عناوين ونصوص أقسام الصفحة الرئيسية. ملاحظة: النص المعدّل يظهر بالعربية في كل اللغات حتى تتم ترجمته.</p><div id="texts"></div></section>
<section><h2>المشاريع (المعرض)</h2><p class="hint">بدّل الاسم والوصف، رتّب بالأزرار ↑ ↓، و«إخفاء» كيحيّد المشروع من المعرض بلا ما يتمسح.</p><div id="projects"></div></section>
<section><h2>الأسئلة الشائعة</h2><p class="hint">عدّل السؤال والجواب، رتّب، أو أخفِ أي سؤال. ملاحظة: النص المعدّل يظهر بالعربية في كل اللغات حتى تتم ترجمته.</p><div id="faqs"></div></section>
</main>
<div id="publish"><span id="status">جاهز</span><button id="pubBtn" type="button">نشر التعديلات</button></div>
<script>
var C = null;
function el(id){ return document.getElementById(id); }
function esc(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;'); }
var TEXT_LABELS = { workTitle: 'عنوان قسم الأعمال', workSub: 'نص قسم الأعمال', svcTitle: 'عنوان الخدمات', svcSub: 'نص الخدمات', priceTitle: 'عنوان الأسعار', procTitle: 'عنوان طريقة العمل', numTitle: 'عنوان الأرقام', aboutTitle: 'عنوان قسم «علينا»', avisTitle: 'عنوان الآراء', faqTitle: 'عنوان الأسئلة الشائعة', contactTitle: 'عنوان التواصل' };
function projRows(listKey, arr){
  return (arr || []).map(function(p, i){
    return '<div class="faqrow' + (p.hidden ? ' off' : '') + '"><label>الاسم</label><input data-pn="' + listKey + ':' + i + '" value="' + esc(p.name) + '">' +
      '<label>الوصف</label><textarea data-pd="' + listKey + ':' + i + '">' + esc(p.desc || '') + '</textarea>' +
      '<div class="bar"><button class="mini" data-mv="' + listKey + ':' + i + ':-1">↑</button><button class="mini" data-mv="' + listKey + ':' + i + ':1">↓</button>' +
      '<button class="mini warn" data-hd="' + listKey + ':' + i + '">' + (p.hidden ? 'إظهار' : 'إخفاء') + '</button><span style="color:#a8a294;font-size:.72rem">' + esc(p.pid) + '</span></div></div>';
  }).join('');
}
function render(){
  el('packs').innerHTML = C.packs.map(function(p, i){
    return '<div class="pack"><div><label>اسم الباقة</label><input data-pack-name="' + i + '" value="' + esc(p.name) + '"></div><div><label>الثمن (درهم)</label><input data-pack-price="' + i + '" type="number" min="0" value="' + p.price + '"></div></div>';
  }).join('');
  el('wa').value = C.whatsapp; el('em').value = C.email;
  el('home').innerHTML = projRows('homeProjects', C.homeProjects);
  el('texts').innerHTML = Object.keys(TEXT_LABELS).map(function(k){
    return '<label>' + TEXT_LABELS[k] + '</label><input data-tx="' + k + '" value="' + esc((C.texts || {})[k] || '') + '">';
  }).join('');
  el('projects').innerHTML = projRows('projects', C.projects);
  el('faqs').innerHTML = C.faq.map(function(f, i){
    return '<div class="faqrow' + (f.hidden ? ' off' : '') + '"><label>السؤال</label><input data-fq="' + i + '" value="' + esc(f.q) + '">' +
      '<label>الجواب</label><textarea data-fa="' + i + '">' + esc(f.a) + '</textarea>' +
      '<div class="bar"><button class="mini" data-fup="' + i + '">↑</button><button class="mini" data-fdn="' + i + '">↓</button>' +
      '<button class="mini warn" data-fhide="' + i + '">' + (f.hidden ? 'إظهار' : 'إخفاء') + '</button></div></div>';
  }).join('');
}
function collect(){
  C.packs.forEach(function(p, i){ p.name = document.querySelector('[data-pack-name="' + i + '"]').value; p.price = parseInt(document.querySelector('[data-pack-price="' + i + '"]').value, 10) || 0; });
  C.whatsapp = el('wa').value.replace(/\\D/g, ''); C.email = el('em').value;
  ['projects', 'homeProjects'].forEach(function(k){ (C[k] || []).forEach(function(p, i){ var n = document.querySelector('[data-pn="' + k + ':' + i + '"]'); var d = document.querySelector('[data-pd="' + k + ':' + i + '"]'); if (n) p.name = n.value; if (d) p.desc = d.value; }); });
  C.texts = C.texts || {}; Object.keys(TEXT_LABELS).forEach(function(k){ var t = document.querySelector('[data-tx="' + k + '"]'); if (t) C.texts[k] = t.value; });
  C.faq.forEach(function(f, i){ f.q = document.querySelector('[data-fq="' + i + '"]').value; f.a = document.querySelector('[data-fa="' + i + '"]').value; });
}
function move(arr, i, d){ var j = i + d; if (j < 0 || j >= arr.length) return; var t = arr[i]; arr[i] = arr[j]; arr[j] = t; }
document.addEventListener('click', function(e){
  var b = e.target.closest('button'); if (!b) return;
  if (b.hasAttribute('data-mv')) { collect(); var mp = b.getAttribute('data-mv').split(':'); move(C[mp[0]], parseInt(mp[1], 10), parseInt(mp[2], 10)); render(); return; }
  if (b.hasAttribute('data-hd')) { collect(); var hp = b.getAttribute('data-hd').split(':'); var it = C[hp[0]][parseInt(hp[1], 10)]; it.hidden = !it.hidden; render(); return; }
  var acts = [['fup', C && C.faq, -1], ['fdn', C && C.faq, 1]];
  for (var k = 0; k < acts.length; k++){
    var key = 'data-' + acts[k][0];
    if (b.hasAttribute(key)) { collect(); move(acts[k][1], parseInt(b.getAttribute(key), 10), acts[k][2]); render(); return; }
  }
  if (b.hasAttribute('data-fhide')) { collect(); var j = parseInt(b.getAttribute('data-fhide'), 10); C.faq[j].hidden = !C.faq[j].hidden; render(); return; }
});
el('pubBtn').addEventListener('click', function(){
  collect();
  el('status').textContent = 'كننشرو…';
  fetch('/api/content', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(C) })
    .then(function(r){ return r.json(); })
    .then(function(j){ el('status').textContent = j.ok ? 'تم النشر ✓ — الموقع كيتحدث في أقل من دقيقة' : 'وقع مشكل، عاود المحاولة'; })
    .catch(function(){ el('status').textContent = 'وقع مشكل في الاتصال'; });
});
fetch('/api/content').then(function(r){ return r.json(); }).then(function(j){ C = j; render(); el('status').textContent = 'تم التحميل — عدّل ثم انشر'; });
</script></body></html>`;

server.listen(PORT, () => console.log('vertex-admin on ' + PORT));
