/**
 * bathysphere — read Worker
 * Serves events from KV (live feed) and D1 (archive).
 *
 * Bindings required (wrangler.toml):
 *   [[kv_namespaces]]
 *   binding = "EVENTS"
 *   id = "<KV namespace ID>"
 *
 *   [[d1_databases]]
 *   binding = "DB"
 *   database_name = "bathysphere"
 *   database_id = "<D1 database ID>"
 *
 * Endpoints:
 *   GET /events      — live feed from KV
 *   GET /archive     — historical queries from D1
 *   GET /stats       — aggregate counts (D1 if available, KV fallback)
 */

const KV_KEY        = "events";
const DEFAULT_LIMIT = 100;
const MAX_KV_LIMIT  = 500;
const MAX_D1_LIMIT  = 1000;

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: CORS });
}

function rowToEvent(row) {
  const e = {
    id: row.id, ts: row.ts, eventid: row.eventid,
    session: row.session, src_ip: row.src_ip,
    protocol: row.protocol, sensor: row.sensor,
  };
  if (row.geo_country || row.geo_city) e.geo = { country: row.geo_country, city: row.geo_city };
  if (row.dst_port)      e.dst_port      = row.dst_port;
  if (row.duration)      e.duration      = row.duration;
  if (row.version)       e.version       = row.version;
  if (row.username)      e.username      = row.username;
  if (row.password_hash) e.password_hash = row.password_hash;
  if (row.password_len)  e.password_len  = row.password_len;
  if (row.input)         e.input         = row.input;
  if (row.filename)      e.filename      = row.filename;
  if (row.shasum)        e.shasum        = row.shasum;
  if (row.url)           e.url           = row.url;
  if (row.attack_id)     e.attack = { id: row.attack_id, name: row.attack_name, tactic: row.attack_tactic };
  if (row.iocs) { try { e.iocs = JSON.parse(row.iocs); } catch {} }
  return e;
}

async function handleEvents(url, env) {
  const p = url.searchParams;
  const limit = Math.min(parseInt(p.get("limit") ?? DEFAULT_LIMIT), MAX_KV_LIMIT);
  const since = p.get("since");
  const filterid = p.get("eventid");

  const raw = await env.EVENTS.get(KV_KEY);
  if (!raw) return json({ events: [], total: 0 });

  let events = JSON.parse(raw);
  if (since)    events = events.filter(e => e.ts > since);
  if (filterid) events = events.filter(e => e.eventid === filterid);
  const slice = events.slice(-limit);

  return json({ events: slice, total: events.length, oldest: events[0]?.ts ?? null, newest: events[events.length-1]?.ts ?? null });
}

async function handleArchive(url, env) {
  if (!env.DB) return json({ error: "D1 not configured" }, 503);

  const p      = url.searchParams;
  const limit  = Math.min(parseInt(p.get("limit") ?? DEFAULT_LIMIT), MAX_D1_LIMIT);
  const before = p.get("before");
  const since  = p.get("since");
  const eventid = p.get("eventid");
  const sensor  = p.get("sensor");
  const src_ip  = p.get("src_ip");
  const hasIoc  = p.get("has_ioc") === "1";
  const hasAtk  = p.get("has_attack") === "1";

  const where = []; const binds = [];
  if (before)  { where.push("ts < ?");             binds.push(before); }
  if (since)   { where.push("ts > ?");             binds.push(since); }
  if (eventid) { where.push("eventid = ?");        binds.push(eventid); }
  if (sensor)  { where.push("sensor = ?");         binds.push(sensor); }
  if (src_ip)  { where.push("src_ip = ?");         binds.push(src_ip); }
  if (hasIoc)  { where.push("iocs IS NOT NULL"); }
  if (hasAtk)  { where.push("attack_id IS NOT NULL"); }

  const wc = where.length ? `WHERE ${where.join(" AND ")}` : "";

  try {
    const [result, countResult] = await env.DB.batch([
      env.DB.prepare(`SELECT * FROM events ${wc} ORDER BY ts DESC LIMIT ?`).bind(...binds, limit),
      env.DB.prepare(`SELECT COUNT(*) as n FROM events ${wc}`).bind(...binds),
    ]);

    const events = (result.results ?? []).map(rowToEvent);
    return json({ events, total: countResult.results?.[0]?.n ?? 0, limit, oldest: events[events.length-1]?.ts ?? null, newest: events[0]?.ts ?? null });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

async function handleStats(env) {
  if (env.DB) {
    try {
      const [totals, ips] = await env.DB.batch([
        env.DB.prepare(`SELECT COUNT(*) as total_events, SUM(CASE WHEN eventid='cowrie.session.connect' THEN 1 ELSE 0 END) as sessions, SUM(CASE WHEN eventid='cowrie.login.success' THEN 1 ELSE 0 END) as logins_ok, SUM(CASE WHEN eventid='cowrie.login.failed' THEN 1 ELSE 0 END) as logins_fail, SUM(CASE WHEN eventid='cowrie.command.input' THEN 1 ELSE 0 END) as commands, SUM(CASE WHEN eventid='cowrie.session.file_upload' THEN 1 ELSE 0 END) as uploads, MIN(ts) as oldest, MAX(ts) as newest FROM events`),
        env.DB.prepare(`SELECT COUNT(DISTINCT src_ip) as unique_ips FROM events`),
      ]);
      const t = totals.results?.[0] ?? {};
      return json({ total_events: t.total_events ?? 0, unique_ips: ips.results?.[0]?.unique_ips ?? 0, sessions: t.sessions ?? 0, logins_ok: t.logins_ok ?? 0, logins_fail: t.logins_fail ?? 0, commands: t.commands ?? 0, uploads: t.uploads ?? 0, oldest: t.oldest ?? null, newest: t.newest ?? null, source: "d1" });
    } catch (err) {
      console.error("D1 stats failed, falling back to KV:", err.message);
    }
  }

  const raw = await env.EVENTS.get(KV_KEY);
  if (!raw) return json({ error: "no data" }, 404);
  const events = JSON.parse(raw);
  const counts = {}; let sessions=0,logins_ok=0,logins_fail=0,commands=0,uploads=0; const ips=new Set();
  for (const e of events) {
    counts[e.eventid]=(counts[e.eventid]??0)+1;
    if (e.src_ip) ips.add(e.src_ip);
    if (e.eventid==="cowrie.session.connect")     sessions++;
    if (e.eventid==="cowrie.login.success")       logins_ok++;
    if (e.eventid==="cowrie.login.failed")        logins_fail++;
    if (e.eventid==="cowrie.command.input")       commands++;
    if (e.eventid==="cowrie.session.file_upload") uploads++;
  }
  return json({ total_events: events.length, unique_ips: ips.size, sessions, logins_ok, logins_fail, commands, uploads, oldest: events[0]?.ts??null, newest: events[events.length-1]?.ts??null, by_eventid: counts, source: "kv" });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
    if (url.pathname === "/events")  return handleEvents(url, env);
    if (url.pathname === "/archive") return handleArchive(url, env);
    if (url.pathname === "/stats")   return handleStats(env);
    return json({ error: "not found" }, 404);
  },
};
