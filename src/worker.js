import { EmailMessage } from 'cloudflare:email';

const ORIGINS = new Set(['https://iristaxfiling.com', 'https://www.iristaxfiling.com']);
const SENDER = 'noreply@iristaxfiling.com';
const MAX_PER_HOUR = 5;

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const clean = (v, max) => String(v ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim().slice(0, max);
const oneLine = (v, max) => clean(v, max).replace(/[\r\n]+/g, ' ');

async function sha256(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 24);
}

function b64(s) {
  let bin = '';
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/(.{76})/g, '$1\r\n');
}

async function notify(env, r) {
  if (!env.MAILER || !env.NOTIFY_TO) return;
  const subject = `[IrisTaxFiling] New registration: ${oneLine(r.name, 60)}`.replace(/[^\x20-\x7e]/g, '?');
  const body = [
    'New registration from the IrisTaxFiling homepage', '',
    `Name: ${r.name}`, `Email: ${r.email}`, `Company: ${r.company}`, `Role: ${r.role || '-'}`,
    `Forms: ${r.forms || '-'}`, `Filings per year: ${r.volume || '-'}`, `Country: ${r.country || '-'}`, `Received: ${r.receivedAt}`, '',
    'Message:', r.message || '-',
  ].join('\n');
  const raw = [
    `From: IrisTaxFiling <${SENDER}>`, `To: ${env.NOTIFY_TO}`, `Reply-To: ${r.email}`, `Subject: ${subject}`,
    `Message-ID: <${crypto.randomUUID()}@iristaxfiling.com>`, `Date: ${new Date().toUTCString()}`, 'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', b64(body),
  ].join('\r\n');
  await env.MAILER.send(new EmailMessage(SENDER, env.NOTIFY_TO, raw));
}

async function register(request, env, ctx) {
  if (request.method !== 'POST') return json(405, { error: 'Use POST.' });
  const origin = request.headers.get('origin');
  if (!origin || !ORIGINS.has(origin)) return json(403, { error: 'Not allowed.' });

  let d;
  try {
    d = await request.json();
  } catch {
    return json(400, { error: 'Please check the form and try again.' });
  }
  if (typeof d !== 'object' || d === null) return json(400, { error: 'Please check the form and try again.' });
  // Bots fill the hidden field; answer as if it worked so they do not retry.
  if (clean(d.website, 50)) return json(200, { ok: true });

  const r = {
    name: oneLine(d.name, 100), email: oneLine(d.email, 200), company: oneLine(d.company, 150), role: oneLine(d.role, 100),
    forms: oneLine(d.forms, 60), volume: oneLine(d.volume, 60), message: clean(d.message, 2000),
    country: request.cf?.country || '', receivedAt: new Date().toISOString(),
  };
  if (!r.name || !r.company || !/^[^\s@<>,;]+@[^\s@<>,;]+\.[^\s@<>,;]+$/.test(r.email)) {
    return json(422, { error: 'Please enter your name, company and a valid email address.' });
  }

  if (env.REGISTRATIONS) {
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    const key = `rl:${await sha256(ip)}:${Math.floor(Date.now() / 3_600_000)}`;
    const n = Number((await env.REGISTRATIONS.get(key)) || 0);
    if (n >= MAX_PER_HOUR) return json(429, { error: 'Too many submissions. Please try again later.' });
    await env.REGISTRATIONS.put(key, String(n + 1), { expirationTtl: 3600 });
    await env.REGISTRATIONS.put(`reg:${r.receivedAt}:${crypto.randomUUID()}`, JSON.stringify(r));
  }
  ctx.waitUntil(notify(env, r).catch((e) => console.error('registration email failed', e instanceof Error ? e.message : e)));
  return json(200, { ok: true });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/register') return register(request, env, ctx);
    return env.ASSETS.fetch(request);
  },
};
