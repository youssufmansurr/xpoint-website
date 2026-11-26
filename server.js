'use strict';
const express = require('express'), multer = require('multer'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const ROOT = __dirname, PORT = process.env.PORT || 3000, PROD = process.env.NODE_ENV === 'production';
const DATA = process.env.DATA_DIR || path.join(ROOT, 'data'), UP = process.env.UPLOAD_DIR || path.join(ROOT, 'uploads');
[DATA, UP, path.join(DATA, 'backups')].forEach(d => fs.mkdirSync(d, { recursive: true }));

/* ---------- storage helpers ---------- */
const rd = (f, d) => { try { return JSON.parse(fs.readFileSync(path.join(DATA, f), 'utf8')); } catch (e) { return d; } };
const wr = (f, o) => { const p = path.join(DATA, f); fs.writeFileSync(p + '.tmp', JSON.stringify(o, null, 2)); fs.renameSync(p + '.tmp', p); };
const DEF = JSON.parse(fs.readFileSync(path.join(ROOT, 'defaults.json'), 'utf8'));
const isObj = v => v && typeof v === 'object' && !Array.isArray(v);
const merge = (d, o) => { if (!isObj(d)) return o === undefined ? d : o; const r = {}; for (const k of Object.keys(d)) r[k] = isObj(d[k]) ? merge(d[k], isObj(o) ? o[k] : undefined) : (o && o[k] !== undefined ? o[k] : d[k]); return r; };
const getContent = () => merge(DEF, rd('content.json', {}));

/* ---------- sanitizing (admin text is stored without tags; FAQ answers allow b/br/a) ---------- */
const URLK = new Set(['facebook', 'instagram', 'linkHref', 'image']);
const okUrl = v => v === '' || /^(https?:\/\/|\/uploads\/|#)/i.test(v);
const cleanHtml = s => s.split(/(<\/?(?:b|br|a)(?:\s[^>]*)?>)/i).map((p, i) => {
  if (i % 2 === 0) return p.replace(/[<>]/g, '');
  const t = p.match(/^<(\/?)(b|br|a)/i), c = t[1], n = t[2].toLowerCase();
  if (n === 'br') return '<br>'; if (n === 'b') return c ? '</b>' : '<b>'; if (c) return '</a>';
  const h = (p.match(/href\s*=\s*"([^"]*)"/i) || [])[1] || '';
  return /^(https?:\/\/|tel:|mailto:|#)/i.test(h) ? '<a class="lnk" href="' + h + '" target="_blank" rel="noopener">' : '<a>';
}).join('');
const deep = (v, k) => {
  if (Array.isArray(v)) return v.slice(0, 200).map(x => deep(x, k));
  if (isObj(v)) { const o = {}; for (const [kk, vv] of Object.entries(v)) o[kk.replace(/[^\w]/g, '')] = deep(vv, kk); return o; }
  if (typeof v === 'string') { v = v.slice(0, 4000); if (k === 'a') return cleanHtml(v); v = v.replace(/[<>]/g, ''); return URLK.has(k) && !okUrl(v.trim()) ? '' : v; }
  return typeof v === 'number' || typeof v === 'boolean' ? v : '';
};

/* ---------- auth ---------- */
const secretFile = path.join(DATA, 'secret');
const SECRET = process.env.SECRET || (fs.existsSync(secretFile) ? fs.readFileSync(secretFile, 'utf8') : (() => { const s = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(secretFile, s, { mode: 0o600 }); return s; })());
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const setPw = pw => { const salt = crypto.randomBytes(16).toString('hex'); wr('auth.json', { salt, hash: hashPw(pw, salt) }); };
if (!rd('auth.json')) {
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  setPw(pw);
  if (!process.env.ADMIN_PASSWORD) console.log('\n  >> Admin password (first run): ' + pw + '\n  >> غيّرها من لوحة التحكم بعد أول دخول\n');
}
const checkPw = pw => { const a = rd('auth.json'); if (!a || typeof pw !== 'string') return false; const x = Buffer.from(hashPw(pw, a.salt), 'hex'), y = Buffer.from(a.hash, 'hex'); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const sign = e => e + '.' + crypto.createHmac('sha256', SECRET).update(String(e)).digest('hex');
const cookie = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(c => c[0]));
const authed = req => { const t = cookie(req).xp_s; if (!t) return false; const [e, h] = t.split('.'); return !!h && Number(e) > Date.now() && t === sign(e); };
const need = (req, res, next) => authed(req) ? next() : res.status(401).json({ error: 'unauthorized' });

/* ---------- tiny rate limiter ---------- */
const hits = new Map();
const limit = (name, max, ms) => (req, res, next) => {
  const k = name + req.ip, n = Date.now(), r = (hits.get(k) || []).filter(t => n - t < ms);
  if (r.length >= max) return res.status(429).json({ error: 'too_many_requests' });
  r.push(n); hits.set(k, r); next();
};
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (!v.some(t => n - t < 3600e3)) hits.delete(k); }, 600e3).unref();

/* ---------- app ---------- */
const app = express();
if (PROD) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' }); if (req.path.startsWith('/admin') || req.path.startsWith('/api/admin')) res.set({ 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store' }); next(); });
app.use(express.json({ limit: '1mb' }));

const esc = s => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
app.get('/', (req, res) => {
  const c = getContent(); let h = fs.readFileSync(path.join(ROOT, 'public/index.html'), 'utf8');
  h = h.replace('<!--CONTENT-->', () => '<script>window.__C=' + JSON.stringify(c).replace(/</g, '\\u003c') + '</script>');
  if (c.site.title) h = h.replace(/<title>.*?<\/title>/, () => '<title>' + esc(c.site.title) + '</title>');
  if (c.site.description) h = h.replace(/(<meta name="description" content=")[^"]*"/, (m, a) => a + esc(c.site.description) + '"');
  res.set('Cache-Control', 'no-cache').type('html').send(h);
});
app.get('/api/content', (req, res) => res.set('Cache-Control', 'no-cache').json(getContent()));
app.use('/uploads', express.static(UP, { maxAge: '7d', index: false }));

/* public: contact form leads */
app.post('/api/leads', limit('lead', 5, 10 * 60e3), (req, res) => {
  const b = req.body || {}, s = (v, n) => String(v || '').replace(/[<>]/g, '').trim().slice(0, n);
  if (b.hp) return res.json({ ok: true });
  const l = { id: crypto.randomUUID(), ts: new Date().toISOString(), name: s(b.name, 80), phone: s(b.phone, 30), time: s(b.time, 10), method: s(b.method, 20), interest: s(b.interest, 60), status: 'new' };
  if (!l.name || l.phone.replace(/\D/g, '').length < 10) return res.status(400).json({ error: 'invalid' });
  const all = rd('leads.json', []); all.unshift(l); wr('leads.json', all.slice(0, 5000)); res.json({ ok: true });
});

/* auth endpoints */
app.post('/api/login', limit('login', 6, 15 * 60e3), (req, res) => {
  if (!checkPw((req.body || {}).password)) return res.status(401).json({ error: 'bad_password' });
  const e = Date.now() + 12 * 3600e3;
  res.set('Set-Cookie', 'xp_s=' + sign(e) + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200' + (PROD ? '; Secure' : '')).json({ ok: true });
});
app.post('/api/logout', (req, res) => res.set('Set-Cookie', 'xp_s=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0').json({ ok: true }));
app.get('/api/admin/me', need, (req, res) => res.json({ ok: true }));
app.post('/api/admin/password', need, (req, res) => {
  const b = req.body || {};
  if (!checkPw(b.current)) return res.status(400).json({ error: 'wrong_current' });
  if (typeof b.next !== 'string' || b.next.length < 8) return res.status(400).json({ error: 'too_short' });
  setPw(b.next); res.json({ ok: true });
});

/* content */
app.get('/api/admin/content', need, (req, res) => res.json(getContent()));
app.put('/api/admin/content', need, (req, res) => {
  if (!isObj(req.body)) return res.status(400).json({ error: 'invalid' });
  const cur = path.join(DATA, 'content.json');
  if (fs.existsSync(cur)) { fs.copyFileSync(cur, path.join(DATA, 'backups', 'content-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json')); const bk = fs.readdirSync(path.join(DATA, 'backups')).sort(); bk.slice(0, Math.max(0, bk.length - 30)).forEach(f => fs.unlinkSync(path.join(DATA, 'backups', f))); }
  wr('content.json', deep(merge(DEF, req.body))); res.json(getContent());
});
app.get('/api/admin/backups', need, (req, res) => res.json(fs.readdirSync(path.join(DATA, 'backups')).filter(f => /^content-.*\.json$/.test(f)).sort().reverse()));
app.post('/api/admin/restore', need, (req, res) => {
  const n = String((req.body || {}).name || ''); if (!/^content-[\w-]+\.json$/.test(n)) return res.status(400).json({ error: 'invalid' });
  const f = path.join(DATA, 'backups', n); if (!fs.existsSync(f)) return res.status(404).json({ error: 'not_found' });
  const cur = path.join(DATA, 'content.json'); if (fs.existsSync(cur)) fs.copyFileSync(cur, path.join(DATA, 'backups', 'content-' + new Date().toISOString().replace(/[:.]/g, '-') + '-before-restore.json'));
  fs.copyFileSync(f, cur); res.json(getContent());
});

/* media */
const EXT = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' };
const upload = multer({ storage: multer.diskStorage({ destination: UP, filename: (r, f, cb) => cb(null, crypto.randomBytes(12).toString('hex') + '.' + EXT[f.mimetype]) }), limits: { fileSize: 6 * 1024 * 1024, files: 1 }, fileFilter: (r, f, cb) => cb(null, !!EXT[f.mimetype]) });
app.post('/api/admin/upload', need, (req, res) => upload.single('file')(req, res, err => {
  if (err || !req.file) return res.status(400).json({ error: err && err.code === 'LIMIT_FILE_SIZE' ? 'too_large' : 'invalid_file' });
  res.json({ url: '/uploads/' + req.file.filename, name: req.file.filename });
}));
app.get('/api/admin/media', need, (req, res) => res.json(fs.readdirSync(UP).filter(f => /^[a-f0-9]{24}\.(jpg|png|webp|gif)$/.test(f)).map(f => ({ name: f, url: '/uploads/' + f, size: fs.statSync(path.join(UP, f)).size, ts: fs.statSync(path.join(UP, f)).mtimeMs })).sort((a, b) => b.ts - a.ts)));
app.delete('/api/admin/media/:name', need, (req, res) => {
  if (!/^[a-f0-9]{24}\.(jpg|png|webp|gif)$/.test(req.params.name)) return res.status(400).json({ error: 'invalid' });
  try { fs.unlinkSync(path.join(UP, req.params.name)); } catch (e) { } res.json({ ok: true });
});

/* leads */
app.get('/api/admin/leads', need, (req, res) => res.json(rd('leads.json', [])));
app.patch('/api/admin/leads/:id', need, (req, res) => {
  const a = rd('leads.json', []), l = a.find(x => x.id === req.params.id); if (!l) return res.status(404).json({ error: 'not_found' });
  if (['new', 'contacted', 'closed'].includes((req.body || {}).status)) l.status = req.body.status; wr('leads.json', a); res.json(l);
});
app.delete('/api/admin/leads/:id', need, (req, res) => { wr('leads.json', rd('leads.json', []).filter(x => x.id !== req.params.id)); res.json({ ok: true }); });
app.get('/api/admin/leads.csv', need, (req, res) => {
  const q = v => '"' + String(v).replace(/"/g, '""').replace(/^([=+\-@])/, "'$1") + '"';
  const rows = rd('leads.json', []).map(l => [l.ts, l.name, l.phone, l.time, l.method, l.interest, l.status].map(q).join(','));
  res.type('text/csv; charset=utf-8').set('Content-Disposition', 'attachment; filename="leads.csv"').send('\ufeff' + ['التاريخ,الاسم,الموبايل,الميعاد,الطريقة,الاهتمام,الحالة'].concat(rows).join('\n'));
});

app.get('/admin', (req, res) => res.sendFile(path.join(ROOT, 'admin/index.html')));
app.use(express.static(path.join(ROOT, 'public'), { index: false }));
app.use((req, res) => res.status(404).type('text').send('Not found'));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'server_error' }); });
app.listen(PORT, () => console.log('X-Point running on http://localhost:' + PORT + '  |  admin: /admin'));
