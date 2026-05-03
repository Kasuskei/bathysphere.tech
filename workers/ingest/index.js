/**
 * bathysphere ingest Worker
 *
 * Bindings required (wrangler.toml):
 *   [[kv_namespaces]]  EVENTS
 *   [[d1_databases]]   DB
 * Secrets: BATHYSPHERE_SECRET, ABUSEIPDB_KEY, IPINFO_TOKEN
 */

import { classifyAttack, matchIocs } from '../lib/classify.js';

const MAX_EVENTS = 10_000;
const KV_KEY     = 'events';
const GEO_TTL    = 60 * 60 * 24 * 30;  // 30 days
const ABUSE_TTL  = 60 * 60 * 24 * 7;   // 7 days

const BLOCKLIST = ['192.168.', '127.', '10.', '172.16.', '::1'];

// ── Auth + body parsing ───────────────────────────────────────────────────────

async function parseAuthedBody(request, env) {
  const secret = request.headers.get('X-Bathysphere-Secret');
  if (!secret || secret !== env.BATHYSPHERE_SECRET)
    return { error: new Response('Unauthorized', { status: 401 }) };
  let body;
  try { body = await request.json(); }
  catch { return { error: new Response('Bad JSON', { status: 400 }) }; }
  if (!Array.isArray(body?.events))
    return { error: new Response('Expected { events: [...] }', { status: 400 }) };
  return { body };
}

// ── Enrichment ────────────────────────────────────────────────────────────────

async function abuseIpLookup(ip, env) {
  if (!env.ABUSEIPDB_KEY) return null;
  const cacheKey = `abuse:${ip}`;
  try {
    const cached = await env.EVENTS.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const resp = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: { 'Key': env.ABUSEIPDB_KEY, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(3000),
      }
    );
    if (!resp.ok) return null;

    const data = await resp.json();
    const d = data?.data;
    if (!d) return null;

    const result = {
      score:      d.abuseConfidenceScore ?? 0,
      reports:    d.totalReports ?? 0,
      categories: d.reports?.slice(0, 3).map(r => r.categories).flat().slice(0, 5) ?? [],
    };
    env.EVENTS.put(cacheKey, JSON.stringify(result), { expirationTtl: ABUSE_TTL });
    return result;
  } catch {
    return null;
  }
}

async function batchEnrich(rawIps, env) {
  const unique = [...new Set(rawIps.filter(ip => ip && !isBlocked(ip)))];
  const map = new Map();
  for (const ip of unique) {
    const [geo, abuse] = await Promise.all([geoLookup(ip, env), abuseIpLookup(ip, env)]);
    map.set(ip, { geo: geo ?? null, abuse: abuse ?? null });
  }
  return map;
}

const CLOUD_ASNS = new Set([
  14618, 16509,   // AWS
  15169, 396982,  // Google / GCP
  8075, 8069,     // Microsoft / Azure
  14061,          // DigitalOcean
  63949,          // Linode / Akamai
  20473,          // Vultr
  24940,          // Hetzner
  16276,          // OVH
  13335,          // Cloudflare
  398324,         // Shodan
  398705,         // Censys
]);

const CLOUD_PATTERNS = [
  { pattern: /amazon|aws/i,       name: 'AWS' },
  { pattern: /google|gcp/i,       name: 'GCP' },
  { pattern: /microsoft|azure/i,  name: 'Azure' },
  { pattern: /digitalocean/i,     name: 'DigitalOcean' },
  { pattern: /linode|akamai/i,    name: 'Linode' },
  { pattern: /vultr/i,            name: 'Vultr' },
  { pattern: /hetzner/i,          name: 'Hetzner' },
  { pattern: /ovh/i,              name: 'OVH' },
  { pattern: /cloudflare/i,       name: 'Cloudflare' },
  { pattern: /shodan/i,           name: 'Shodan' },
  { pattern: /censys/i,           name: 'Censys' },
  { pattern: /alibaba/i,          name: 'Alibaba Cloud' },
  { pattern: /tencent/i,          name: 'Tencent Cloud' },
  { pattern: /huawei/i,           name: 'Huawei Cloud' },
];

function detectCloud(asn, ispName) {
  if (asn && CLOUD_ASNS.has(asn)) {
    const match = CLOUD_PATTERNS.find(p => p.pattern.test(ispName ?? ''));
    return match?.name ?? 'Cloud/VPS';
  }
  for (const { pattern, name } of CLOUD_PATTERNS) {
    if (pattern.test(ispName ?? '')) return name;
  }
  return null;
}

async function geoLookup(ip, env) {
  const cacheKey = `geo:${ip}`;
  try {
    const cached = await env.EVENTS.get(cacheKey);
    if (cached) return JSON.parse(cached);

    let geo = await fetchIpApi(ip);
    if (!geo || (!geo.country && !geo.asn && !geo.isp)) {
      geo = await fetchIpInfo(ip, env);
    }
    if (!geo) return null;

    env.EVENTS.put(cacheKey, JSON.stringify(geo), { expirationTtl: GEO_TTL });
    return geo;
  } catch {
    return null;
  }
}

async function fetchIpApi(ip) {
  try {
    const resp = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,city,as,isp,reverse`,
      { signal: AbortSignal.timeout(2000) }
    );
    if (!resp.ok) return null;

    const data = await resp.json();
    if (data.status !== 'success') return null;

    const asnMatch = (data.as ?? '').match(/^AS(\d+)/);
    const asnNum   = asnMatch ? parseInt(asnMatch[1]) : null;
    const ispName  = data.isp ?? null;

    return {
      country: data.country ?? null,
      city:    data.city    ?? null,
      asn:     data.as      ?? null,
      isp:     ispName,
      rdns:    data.reverse && data.reverse !== '' ? data.reverse : null,
      cloud:   detectCloud(asnNum, ispName),
    };
  } catch {
    return null;
  }
}

async function fetchIpInfo(ip, env) {
  try {
    const token = env.IPINFO_TOKEN ? `?token=${env.IPINFO_TOKEN}` : '';
    const resp = await fetch(
      `https://ipinfo.io/${ip}/json${token}`,
      { signal: AbortSignal.timeout(2000) }
    );
    if (!resp.ok) return null;

    const data = await resp.json();
    if (data.bogon || !data.ip) return null;

    const asnMatch = (data.org ?? '').match(/^AS(\d+)/);
    const asnNum   = asnMatch ? parseInt(asnMatch[1]) : null;
    const ispName  = data.org ?? null;

    return {
      country: data.country ?? null,
      city:    data.city    ?? null,
      asn:     data.org     ?? null,
      isp:     ispName,
      rdns:    data.hostname && data.hostname !== '' ? data.hostname : null,
      cloud:   detectCloud(asnNum, ispName),
    };
  } catch {
    return null;
  }
}

// ── Normalization ─────────────────────────────────────────────────────────────

function anonymize(ip) {
  if (!ip) return null;
  if (ip.includes(':')) {
    const parts = ip.split(':');
    return parts[0] + ':x:x:x:x:x:x:x';
  }
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  return `${parts[0]}.${parts[1]}.x.x`;
}

function isBlocked(ip) {
  return BLOCKLIST.some(prefix => ip?.startsWith(prefix));
}

function normalize(raw, enrichment) {
  if (isBlocked(raw.src_ip)) return null;

  const anon_ip = anonymize(raw.src_ip);
  if (!anon_ip) return null;

  const base = {
    id:       raw.uuid ? `${raw.uuid}-${raw.eventid}-${raw.timestamp}` : crypto.randomUUID(),
    ts:       raw.timestamp,
    eventid:  raw.eventid,
    session:  raw.session,
    src_ip:   anon_ip,
    protocol: raw.protocol ?? 'ssh',
    sensor:   raw.sensor   ?? 'honeypot-pi',
    geo:      enrichment?.geo ?? null,
  };

  let event;
  switch (raw.eventid) {
    case 'cowrie.session.connect':
      event = { ...base, dst_port: raw.dst_port };
      break;
    case 'cowrie.session.closed':
      event = { ...base, duration: parseFloat(raw.duration) };
      break;
    case 'cowrie.client.version':
      event = { ...base, version: raw.version };
      break;
    case 'cowrie.login.success':
    case 'cowrie.login.failed':
      event = {
        ...base,
        username:      raw.username,
        password_hash: raw.password
          ? raw.password.slice(0, 2) + '***' + raw.password.slice(-1)
          : null,
        password_len: raw.password?.length ?? null,
      };
      break;
    case 'cowrie.command.input':
    case 'cowrie.command.failed':
      event = { ...base, input: raw.input };
      break;
    case 'cowrie.session.file_upload':
      event = { ...base, filename: raw.filename, shasum: raw.shasum };
      break;
    case 'cowrie.session.file_download':
      event = { ...base, url: raw.url, shasum: raw.shasum };
      break;
    default:
      event = base;
  }

  const technique = classifyAttack(event);
  if (technique) event.attack = technique;

  const iocs = matchIocs(event, enrichment?.abuse);
  if (iocs.length > 0) event.iocs = iocs;

  return event;
}

// ── Route handlers ────────────────────────────────────────────────────────────

async function handleIngest(request, env, { writeKV = true, requireDB = false } = {}) {
  const { body, error } = await parseAuthedBody(request, env);
  if (error) return error;

  if (requireDB && !env.DB) return new Response('D1 not configured', { status: 503 });

  const rawIps    = body.events.map(e => e.src_ip).filter(Boolean);
  const enrichMap = await batchEnrich(rawIps, env);

  const incoming = body.events
    .map(e => normalize(e, enrichMap.get(e.src_ip) ?? null))
    .filter(Boolean);

  if (incoming.length === 0)
    return new Response(JSON.stringify({ stored: 0 }), { headers: { 'Content-Type': 'application/json' } });

  let total;
  if (writeKV) {
    const existing = JSON.parse((await env.EVENTS.get(KV_KEY)) ?? '[]');
    const merged   = [...existing, ...incoming];
    const trimmed  = merged.length > MAX_EVENTS ? merged.slice(merged.length - MAX_EVENTS) : merged;
    await env.EVENTS.put(KV_KEY, JSON.stringify(trimmed));
    total = trimmed.length;
  }

  if (env.DB) await writeToD1(incoming, env.DB);

  return new Response(
    JSON.stringify({ stored: incoming.length, ...(total !== undefined && { total }) }),
    { headers: { 'Content-Type': 'application/json' } }
  );
}

async function handleBackfill(request, env) {
  const { body, error } = await parseAuthedBody(request, env);
  if (error) return error;
  if (!env.DB) return new Response('D1 not configured', { status: 503 });

  await writeToD1(body.events, env.DB);

  return new Response(
    JSON.stringify({ stored: body.events.length }),
    { headers: { 'Content-Type': 'application/json' } }
  );
}

// ── D1 persistence ────────────────────────────────────────────────────────────

/**
 * Accepts both live ingest format (nested e.geo / e.attack) and backfill
 * format (flat e.geo_country / e.attack_id). INSERT OR IGNORE on id.
 */
async function writeToD1(events, db) {
  const n = v => (v === undefined ? null : v ?? null);

  const stmts = events
    .filter(e => e.id && e.ts && e.eventid)
    .map(e =>
      db.prepare(`
        INSERT OR IGNORE INTO events (
          id, ts, eventid, session, src_ip, protocol, sensor,
          geo_country, geo_city, geo_asn, geo_isp, geo_rdns, geo_cloud,
          dst_port, duration, version,
          username, password_hash, password_len,
          input, filename, shasum, url,
          attack_id, attack_name, attack_tactic,
          iocs, abuse_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        n(e.id),
        n(e.ts),
        n(e.eventid),
        n(e.session),
        n(e.src_ip),
        n(e.protocol) ?? 'ssh',
        n(e.sensor)   ?? 'honeypot-pi',
        n(e.geo_country ?? e.geo?.country),
        n(e.geo_city    ?? e.geo?.city),
        n(e.geo_asn     ?? e.geo?.asn),
        n(e.geo_isp     ?? e.geo?.isp),
        n(e.geo_rdns    ?? e.geo?.rdns),
        n(e.geo_cloud   ?? e.geo?.cloud),
        n(e.dst_port),
        n(e.duration),
        n(e.version),
        n(e.username),
        n(e.password_hash),
        n(e.password_len),
        n(e.input),
        n(e.filename),
        n(e.shasum),
        n(e.url),
        n(e.attack_id    ?? e.attack?.id),
        n(e.attack_name  ?? e.attack?.name),
        n(e.attack_tactic ?? e.attack?.tactic),
        typeof e.iocs === 'string' ? e.iocs : (e.iocs?.length ? JSON.stringify(e.iocs) : null),
        n(e.abuse_score ?? e.iocs?.find?.(i => i.type === 'reputation')?.score)
      )
    );

  if (stmts.length === 0) return;

  try {
    for (let i = 0; i < stmts.length; i += 100) {
      await db.batch(stmts.slice(i, i + 100));
    }
  } catch (err) {
    console.error('D1 write failed:', err.message);
    throw err;
  }
}

// ── Router ────────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') return new Response('Not found', { status: 404 });
    const { pathname } = new URL(request.url);

    if (pathname === '/ingest')    return handleIngest(request, env);
    if (pathname === '/ingest-d1') return handleIngest(request, env, { writeKV: false, requireDB: true });
    if (pathname === '/backfill')  return handleBackfill(request, env);

    return new Response('Not found', { status: 404 });
  },
};
