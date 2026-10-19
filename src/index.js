// iristaxfiling.com: static landing page plus a visitor log.
// Every HTML page view is recorded (IP, approximate location from Cloudflare, network, page, referrer, browser) in a
// Durable Object with SQLite storage. /visitors shows the log as a table behind a password (secret VISITORS_PASSWORD).

const SESSION_COOKIE = 'visitors_session';
const SESSION_SECONDS = 8 * 3600;
const PAGE_SIZE = 100;
const RETENTION_DAYS = 180;
const MAX_ROWS = 200000;
const MAX_FAILURES = 5;
const FAILURE_WINDOW_MS = 15 * 60 * 1000;

const encoder = new TextEncoder();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/visitors' || url.pathname === '/visitors/') return visitorsPage(request, env, url);

    const response = await env.ASSETS.fetch(request);
    if (request.method === 'GET' && (response.headers.get('content-type') || '').startsWith('text/html')) {
      ctx.waitUntil(record(request, env, url, response.status).catch(() => {}));
    }
    return response;
  },
};

const logStub = (env) => env.VISITOR_LOG.get(env.VISITOR_LOG.idFromName('global'));

const BOT = /bot|crawl|spider|slurp|curl|wget|python-requests|httpclient|headless|facebookexternalhit|preview|monitor|uptime|scan/i;

async function record(request, env, url, status) {
  const cf = request.cf || {};
  const ua = request.headers.get('user-agent') || '';
  const row = {
    ts: Date.now(),
    ip: request.headers.get('cf-connecting-ip') || '',
    country: cf.country || '',
    region: cf.region || '',
    city: cf.city || '',
    timezone: cf.timezone || '',
    org: cf.asOrganization || '',
    asn: Number(cf.asn) || 0,
    path: (url.pathname + url.search).slice(0, 300),
    referrer: (request.headers.get('referer') || '').slice(0, 300),
    ua: ua.slice(0, 300),
    bot: BOT.test(ua) ? 1 : 0,
    status,
  };
  await logStub(env).fetch('https://log/add', { method: 'POST', body: JSON.stringify(row) });
}

/* ---------- password and session ---------- */

const sha256 = async (s) => new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(s)));

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function passwordMatches(input, secret) {
  const [a, b] = await Promise.all([sha256(input), sha256(secret)]);
  return sameBytes(a, b);
}

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

async function sign(secret, message) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(message))));
}

async function newSession(secret) {
  const exp = Date.now() + SESSION_SECONDS * 1000;
  return `${exp}.${await sign(secret, `visitors:${exp}`)}`;
}

async function sessionValid(request, secret) {
  const cookie = (request.headers.get('cookie') || '').split(/;\s*/).find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  if (!cookie) return false;
  const [exp, mac] = cookie.slice(SESSION_COOKIE.length + 1).split('.');
  if (!exp || !mac || !(Number(exp) > Date.now())) return false;
  return sameBytes(encoder.encode(await sign(secret, `visitors:${exp}`)), encoder.encode(mac));
}

/* ---------- /visitors ---------- */

const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function page(status, body, extraHeaders = {}, signedIn = false) {
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const signOut = signedIn
    ? `<form method="post" action="/visitors"><input type="hidden" name="action" value="logout"><button class="btn g" type="submit">Sign out</button></form>`
    : '';
  return new Response(
    `<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
      `<meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#050a1f"><title>Visitors | IrisTaxFiling</title>` +
      `<script nonce="${nonce}">try{document.documentElement.setAttribute("data-theme",localStorage.getItem("irisfile-theme")==="light"?"light":"dark")}catch(e){}</script>` +
      `<style>${CSS}</style></head><body><header><div class="wrap"><nav class="nav">` +
      `<a class="logo" href="/" aria-label="IrisTaxFiling.com home">Iris<b>TaxFiling</b><i>.com</i></a><span class="pill">Visitors</span>` +
      `<div class="navcta">${signOut}<button class="tgl" id="theme" type="button" aria-label="Switch theme"><span aria-hidden="true">&#9728;</span></button></div>` +
      `</nav></div></header><main class="wrap">${body}</main>` +
      `<script nonce="${nonce}">var r=document.documentElement,t=document.getElementById("theme");function s(m,v){r.setAttribute("data-theme",m);t.firstChild.textContent=m==="light"?"\\u263E":"\\u2600";if(v){try{localStorage.setItem("irisfile-theme",m)}catch(e){}}}` +
      `s(r.getAttribute("data-theme")==="light"?"light":"dark",false);t.addEventListener("click",function(){s(r.getAttribute("data-theme")==="light"?"dark":"light",true)});</script></body></html>`,
    {
      status,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'x-robots-tag': 'noindex, nofollow',
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'referrer-policy': 'same-origin',
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
        ...extraHeaders,
      },
    },
  );
}

// Same colours, type and components as the landing page (index.html), including the saved dark/light choice.
const CSS = `:root{--bg:#050a1f;--soft:#070e2b;--text:#E6ECFF;--muted:#8E9CC7;--line:#17234d;--p:#6FA3FF;--btn:#2F6BFF;--card:#0a1438;--err:#ff8a80;color-scheme:dark}
:root[data-theme="light"]{--bg:#fbfbfd;--soft:#f5f5f7;--text:#1d1d1f;--muted:#6e6e73;--line:#e5e5ea;--card:#fff;--p:#0b57d0;--btn:#0071e3;--err:#b3261e;color-scheme:light}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(70% 40% at 78% 0,rgba(47,107,255,.22),transparent 70%),var(--bg);color:var(--text);font:15px/1.55 -apple-system,BlinkMacSystemFont,"SF Pro Text","Inter","Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
:root[data-theme="light"] body{background:radial-gradient(60% 40% at 50% 0,rgba(0,113,227,.08),transparent 70%),var(--bg)}
a{color:var(--p);text-decoration:none}a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--p);outline-offset:3px;border-radius:4px}
.wrap{max-width:1500px;margin:0 auto;padding:0 24px}
header{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 85%,transparent);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.nav{display:flex;align-items:center;height:60px;gap:16px}
.logo{font-weight:700;font-size:20px;letter-spacing:-.03em;color:var(--text)}.logo:hover{text-decoration:none}.logo b{color:var(--p)}.logo i{font-style:normal;font-weight:500;color:var(--muted)}
.pill{font-size:12px;font-weight:600;color:var(--p);border:1px solid var(--line);background:var(--card);border-radius:980px;padding:2px 10px}
.navcta{display:flex;gap:8px;align-items:center;margin-left:auto}.navcta form{margin:0}
.btn{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 20px;border-radius:980px;font:500 15px inherit;font-family:inherit;border:1px solid transparent;cursor:pointer;transition:background .15s,box-shadow .15s}
.btn.p{background:var(--btn);color:#fff}.btn.p:hover{background:#4A80FF;box-shadow:0 0 24px rgba(79,140,255,.4);text-decoration:none}
:root[data-theme="light"] .btn.p:hover{background:#0077ed;box-shadow:none}
.btn.g{background:var(--card);color:var(--text);border-color:var(--line)}.btn.g:hover{background:var(--soft);text-decoration:none}
.tgl{min-width:40px;height:40px;border-radius:50%;border:1px solid var(--line);background:var(--card);color:var(--text);font-size:16px;cursor:pointer}
h1{font-size:clamp(26px,4vw,38px);font-weight:600;letter-spacing:-.04em;line-height:1.1;margin:36px 0 6px;background:linear-gradient(180deg,var(--text) 35%,var(--p));-webkit-background-clip:text;background-clip:text;color:transparent}
.muted{color:var(--muted)}.bar{display:flex;gap:18px;align-items:center;flex-wrap:wrap;margin:16px 0}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:9px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);white-space:nowrap}
td:nth-child(6),td:nth-child(7){white-space:normal;word-break:break-all;min-width:140px}
th{background:var(--soft);color:var(--muted);font-weight:600;position:sticky;top:0}tbody tr:last-child td{border-bottom:0}tbody tr:hover td{background:var(--soft)}
td:nth-child(2){font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.bot td{color:var(--muted)}
form.login{max-width:380px;margin:14vh auto 0;background:var(--card);padding:28px;border:1px solid var(--line);border-radius:16px}
form.login h1{margin-top:0}form.login input{width:100%;margin:10px 0 16px;min-height:44px;padding:0 14px;border-radius:12px;border:1px solid var(--line);background:var(--bg);color:var(--text);font:inherit}
form.login .btn{width:100%}.err{color:var(--err);margin:8px 0 0}
main{padding-bottom:48px}`;

async function visitorsPage(request, env, url) {
  const secret = env.VISITORS_PASSWORD;
  if (!secret) return page(503, '<p class="muted" style="margin:20vh auto;max-width:420px">The visitor log is not configured.</p>');
  if (request.method !== 'GET' && request.method !== 'POST') return page(405, '<p>Method not allowed.</p>', { allow: 'GET, POST' });

  if (request.method === 'POST') {
    // Browsers send Sec-Fetch-Site on every request; Origin can be "null" on same-site form posts, so it is only the fallback.
    const fetchSite = request.headers.get('sec-fetch-site');
    const origin = request.headers.get('origin');
    const crossSite = fetchSite ? fetchSite !== 'same-origin' && fetchSite !== 'none' : Boolean(origin) && origin !== url.origin;
    if (crossSite) return page(403, '<p>Cross-site request refused.</p>');
    const form = await request.formData().catch(() => null);
    if (form && form.get('action') === 'logout') {
      return new Response(null, { status: 303, headers: { location: '/visitors', 'set-cookie': cookie('', 0) } });
    }
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    const log = logStub(env);
    const state = await (await log.fetch(`https://log/locked?ip=${encodeURIComponent(ip)}`)).json();
    if (state.locked) return page(429, loginForm('Too many failed attempts. Try again in 15 minutes.'));
    const given = form ? String(form.get('password') || '') : '';
    if (given && (await passwordMatches(given, secret))) {
      await log.fetch(`https://log/clear?ip=${encodeURIComponent(ip)}`, { method: 'POST' });
      return new Response(null, { status: 303, headers: { location: '/visitors', 'set-cookie': cookie(await newSession(secret), SESSION_SECONDS) } });
    }
    await log.fetch(`https://log/fail?ip=${encodeURIComponent(ip)}`, { method: 'POST' });
    return page(401, loginForm('Wrong password.'));
  }

  if (!(await sessionValid(request, secret))) return page(401, loginForm(''));

  const pageNo = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10) || 1);
  const hideBots = url.searchParams.get('bots') === 'hide';
  const data = await (await logStub(env).fetch(`https://log/list?page=${pageNo}&size=${PAGE_SIZE}&bots=${hideBots ? 'hide' : 'show'}`)).json();
  return page(200, visitorsTable(data, pageNo, hideBots), {}, true);
}

const cookie = (value, maxAge) => `${SESSION_COOKIE}=${value}; Path=/visitors; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;

function loginForm(error) {
  return (
    `<form class="login" method="post" action="/visitors"><h1>Visitors</h1><p class="muted">Enter the password to view the visitor log.</p>` +
    `${error ? `<p class="err">${esc(error)}</p>` : ''}` +
    `<input type="password" name="password" autocomplete="current-password" autofocus required aria-label="Password"><button class="btn p" type="submit">Open</button></form>`
  );
}

function browserName(ua) {
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad|iOS/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  const b = /Edg\//.test(ua) ? 'Edge' : /OPR\/|Opera/.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : ua ? ua.split(/[\s/]/)[0] : '';
  return [b, os].filter(Boolean).join(' on ') || '-';
}

const when = (ts) => new Date(ts).toISOString().replace('T', ' ').slice(0, 19);

function visitorsTable(data, pageNo, hideBots) {
  const pages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
  const qs = (p, bots) => `?page=${p}${bots ? '&bots=hide' : ''}`;
  const rows = data.rows
    .map((r) => {
      const place = [r.city, r.region, r.country].filter(Boolean).join(', ') || '-';
      return (
        `<tr class="${r.bot ? 'bot' : ''}"><td>${esc(when(r.ts))}</td><td>${esc(r.ip || '-')}</td><td>${esc(place)}</td><td>${esc(r.timezone || '-')}</td>` +
        `<td>${esc(r.org || '-')}${r.asn ? ` (AS${esc(r.asn)})` : ''}</td><td>${esc(r.path)}</td><td>${esc(r.referrer || '-')}</td>` +
        `<td title="${esc(r.ua)}">${esc(browserName(r.ua))}</td><td>${r.bot ? 'Bot' : 'Visitor'}</td></tr>`
      );
    })
    .join('');
  return (
    `<h1>Visitors</h1><p class="muted">Times are UTC. Location is approximate (from the IP address). Entries are kept ${RETENTION_DAYS} days.</p>` +
    `<div class="bar"><span><b>${data.total}</b> page views shown, <b>${data.uniqueIps}</b> distinct IP addresses, <b>${data.last24h}</b> in the last 24 hours</span>` +
    `<a class="btn g" href="${qs(1, !hideBots)}">${hideBots ? 'Show bots' : 'Hide bots'}</a><a class="btn g" href="${qs(pageNo, hideBots)}">Refresh</a></div>` +
    `<div class="tablewrap"><table><thead><tr><th>Time (UTC)</th><th>IP address</th><th>Location</th><th>Time zone</th><th>Network</th><th>Page</th><th>Referrer</th><th>Browser</th><th>Type</th></tr></thead>` +
    `<tbody>${rows || '<tr><td colspan="9">No visits recorded yet.</td></tr>'}</tbody></table></div>` +
    `<div class="bar">${pageNo > 1 ? `<a class="btn g" href="${qs(pageNo - 1, hideBots)}">Newer</a>` : ''}<span class="muted">Page ${pageNo} of ${pages}</span>` +
    `${pageNo < pages ? `<a class="btn g" href="${qs(pageNo + 1, hideBots)}">Older</a>` : ''}</div>`
  );
}

/* ---------- storage ---------- */

export class VisitorLog {
  constructor(state) {
    this.sql = state.storage.sql;
    this.writes = 0;
    state.blockConcurrencyWhile(async () => {
      this.sql.exec(
        `CREATE TABLE IF NOT EXISTS visits (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, ip TEXT, country TEXT, region TEXT, city TEXT,
          timezone TEXT, org TEXT, asn INTEGER, path TEXT, referrer TEXT, ua TEXT, bot INTEGER, status INTEGER)`,
      );
      this.sql.exec('CREATE INDEX IF NOT EXISTS visits_ts ON visits (ts)');
      this.sql.exec('CREATE TABLE IF NOT EXISTS login_failures (ip TEXT NOT NULL, ts INTEGER NOT NULL)');
    });
  }

  async fetch(request) {
    const url = new URL(request.url);
    const ip = url.searchParams.get('ip') || '';
    switch (url.pathname) {
      case '/add': {
        const r = await request.json();
        this.sql.exec(
          'INSERT INTO visits (ts, ip, country, region, city, timezone, org, asn, path, referrer, ua, bot, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
          r.ts, r.ip, r.country, r.region, r.city, r.timezone, r.org, r.asn, r.path, r.referrer, r.ua, r.bot, r.status,
        );
        if (++this.writes % 50 === 0) this.prune();
        return new Response('ok');
      }
      case '/list': {
        const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10) || 1);
        const size = Math.min(500, Math.max(1, parseInt(url.searchParams.get('size') || '100', 10) || 100));
        const where = url.searchParams.get('bots') === 'hide' ? 'WHERE bot = 0' : '';
        const total = this.sql.exec(`SELECT COUNT(*) AS n FROM visits ${where}`).one().n;
        const uniqueIps = this.sql.exec(`SELECT COUNT(DISTINCT ip) AS n FROM visits ${where}`).one().n;
        const last24h = this.sql.exec(`SELECT COUNT(*) AS n FROM visits ${where ? where + ' AND' : 'WHERE'} ts > ?`, Date.now() - 86400000).one().n;
        const rows = this.sql.exec(`SELECT * FROM visits ${where} ORDER BY id DESC LIMIT ? OFFSET ?`, size, (page - 1) * size).toArray();
        return Response.json({ total, uniqueIps, last24h, rows });
      }
      case '/locked': {
        const n = this.sql.exec('SELECT COUNT(*) AS n FROM login_failures WHERE ip = ? AND ts > ?', ip, Date.now() - FAILURE_WINDOW_MS).one().n;
        return Response.json({ locked: n >= MAX_FAILURES });
      }
      case '/fail':
        this.sql.exec('INSERT INTO login_failures (ip, ts) VALUES (?, ?)', ip, Date.now());
        this.sql.exec('DELETE FROM login_failures WHERE ts < ?', Date.now() - FAILURE_WINDOW_MS);
        return new Response('ok');
      case '/clear':
        this.sql.exec('DELETE FROM login_failures WHERE ip = ?', ip);
        return new Response('ok');
      default:
        return new Response('not found', { status: 404 });
    }
  }

  prune() {
    this.sql.exec('DELETE FROM visits WHERE ts < ?', Date.now() - RETENTION_DAYS * 86400000);
    this.sql.exec('DELETE FROM visits WHERE id <= (SELECT MAX(id) FROM visits) - ?', MAX_ROWS);
  }
}
