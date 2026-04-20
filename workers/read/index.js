/**
 * bathysphere — read Worker
 * Serves events from KV (live feed) and D1 (archive).
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
  if (row.geo_country || row.geo_city || row.geo_asn || row.geo_isp || row.geo_rdns || row.geo_cloud) {
    e.geo = {
      country: row.geo_country, city: row.geo_city,
      asn: row.geo_asn, isp: row.geo_isp,
      rdns: row.geo_rdns, cloud: row.geo_cloud,
    };
  }
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
  if (row.iocs)          { try { e.iocs = JSON.parse(row.iocs); } catch {} }
  return e;
}

async function handleEvents(url, env) {
  const p     = url.searchParams;
  const limit = Math.min(parseInt(p.get("limit") ?? DEFAULT_LIMIT), MAX_KV_LIMIT);
  const since = p.get("since");

  const raw = await env.EVENTS.get(KV_KEY);
  if (!raw) return json({ events: [], total: 0 });

  let events = JSON.parse(raw);
  if (since) events = events.filter(e => e.ts > since);
  const slice = events.slice(-limit);

  return json({ events: slice, total: events.length, oldest: events[0]?.ts ?? null, newest: events[events.length-1]?.ts ?? null });
}

async function handleArchive(url, env) {
  if (!env.DB) return json({ error: "D1 not configured" }, 503);

  const p         = url.searchParams;
  const limit     = Math.min(parseInt(p.get("limit") ?? DEFAULT_LIMIT), MAX_D1_LIMIT);
  const before    = p.get("before");
  const since     = p.get("since");
  const date_from = p.get("date_from");
  const date_to   = p.get("date_to");
  const eventid   = p.get("eventid");
  const sensor    = p.get("sensor");
  const src_ip    = p.get("src_ip");
  const search    = p.get("search")?.trim();
  const hasIoc    = p.get("has_ioc") === "1";
  const hasAtk    = p.get("has_attack") === "1";

  // If search is provided, use FTS to get matching IDs first
  // then filter the main events table by those IDs
  let ftsIds = null;
  if (search) {
    try {
      // Sanitize search term for FTS5 — escape special chars
      const safeTerm = search.replace(/["]/g, '""');
      const ftsResult = await env.DB.prepare(
        `SELECT id FROM events_fts WHERE events_fts MATCH ? ORDER BY rank LIMIT 500`
      ).bind(`"${safeTerm}"`).all();
      ftsIds = (ftsResult.results ?? []).map(r => r.id);
      // If no FTS results, return empty immediately
      if (ftsIds.length === 0) {
        return json({ events: [], total: 0, limit, oldest: null, newest: null });
      }
    } catch (err) {
      // FTS failed — fall back to LIKE search
      console.error('FTS search failed, falling back to LIKE:', err.message);
    }
  }

  const where = []; const binds = [];

  // Date range (takes priority over cursor-based pagination)
  if (date_from) { where.push("ts >= ?"); binds.push(date_from); }
  if (date_to)   { where.push("ts <= ?"); binds.push(date_to + 'T23:59:59Z'); }

  // Cursor pagination (only when no date range)
  if (!date_from && !date_to) {
    if (before) { where.push("ts < ?"); binds.push(before); }
    if (since)  { where.push("ts > ?"); binds.push(since); }
  }

  if (eventid) { where.push("eventid = ?");  binds.push(eventid); }
  if (sensor)  { where.push("sensor = ?");   binds.push(sensor); }
  if (src_ip)  { where.push("src_ip = ?");   binds.push(src_ip); }
  if (hasIoc)  { where.push("iocs IS NOT NULL"); }
  if (hasAtk)  { where.push("attack_id IS NOT NULL"); }

  // FTS ID filter
  if (ftsIds !== null) {
    const placeholders = ftsIds.map(() => '?').join(',');
    where.push(`id IN (${placeholders})`);
    binds.push(...ftsIds);
  } else if (search && !ftsIds) {
    // LIKE fallback if FTS failed
    const likeTerm = `%${search}%`;
    where.push("(input LIKE ? OR username LIKE ? OR version LIKE ?)");
    binds.push(likeTerm, likeTerm, likeTerm);
  }

  const wc = where.length ? `WHERE ${where.join(" AND ")}` : "";

  try {
    const [result, countResult, metaResult] = await env.DB.batch([
      env.DB.prepare(`SELECT * FROM events ${wc} ORDER BY ts DESC LIMIT ?`).bind(...binds, limit),
      env.DB.prepare(`SELECT COUNT(*) as n FROM events ${wc}`).bind(...binds),
      env.DB.prepare(`SELECT MIN(ts) as oldest, MAX(ts) as newest FROM events`),
    ]);

    const events = (result.results ?? []).map(rowToEvent);
    const total  = countResult.results?.[0]?.n ?? 0;
    const meta   = metaResult.results?.[0] ?? {};

    return json({
      events,
      total,
      limit,
      oldest: meta.oldest ?? null,
      newest: meta.newest ?? null,
      // Cursor for next page
      next_before: events.length === limit ? events[events.length - 1]?.ts : null,
    });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

async function handleStats(env) {
  if (env.DB) {
    try {
      const [totals, ips] = await env.DB.batch([
        env.DB.prepare(`SELECT
          COUNT(*) as total_events,
          SUM(CASE WHEN eventid='cowrie.session.connect' THEN 1 ELSE 0 END) as sessions,
          SUM(CASE WHEN eventid='cowrie.login.success' THEN 1 ELSE 0 END) as logins_ok,
          SUM(CASE WHEN eventid='cowrie.login.failed' THEN 1 ELSE 0 END) as logins_fail,
          SUM(CASE WHEN eventid='cowrie.command.input' THEN 1 ELSE 0 END) as commands,
          SUM(CASE WHEN eventid='cowrie.session.file_upload' THEN 1 ELSE 0 END) as uploads,
          MIN(ts) as oldest, MAX(ts) as newest
          FROM events`),
        env.DB.prepare(`SELECT COUNT(DISTINCT src_ip) as unique_ips FROM events`),
      ]);
      const t = totals.results?.[0] ?? {};
      if ((t.total_events ?? 0) >= 100) {
        return json({
          total_events: t.total_events ?? 0,
          unique_ips: ips.results?.[0]?.unique_ips ?? 0,
          sessions: t.sessions ?? 0,
          logins_ok: t.logins_ok ?? 0,
          logins_fail: t.logins_fail ?? 0,
          commands: t.commands ?? 0,
          uploads: t.uploads ?? 0,
          oldest: t.oldest ?? null,
          newest: t.newest ?? null,
          source: "d1"
        });
      }
    } catch (err) {
      console.error("D1 stats failed, falling back to KV:", err.message);
    }
  }

  const raw = await env.EVENTS.get(KV_KEY);
  if (!raw) return json({ error: "no data" }, 404);
  const events = JSON.parse(raw);
  let sessions=0, logins_ok=0, logins_fail=0, commands=0, uploads=0;
  const ips = new Set();
  for (const e of events) {
    if (e.src_ip) ips.add(e.src_ip);
    if (e.eventid === "cowrie.session.connect")      sessions++;
    if (e.eventid === "cowrie.login.success")        logins_ok++;
    if (e.eventid === "cowrie.login.failed")         logins_fail++;
    if (e.eventid === "cowrie.command.input")        commands++;
    if (e.eventid === "cowrie.session.file_upload")  uploads++;
  }
  return json({ total_events: events.length, unique_ips: ips.size, sessions, logins_ok, logins_fail, commands, uploads, oldest: events[0]?.ts ?? null, newest: events[events.length-1]?.ts ?? null, source: "kv" });
}


async function handleSignal(env) {
  if (!env.BLOG) return json({ posts: [], total: 0 });
  try {
    const result = await env.BLOG.prepare(
      `SELECT * FROM posts ORDER BY created_at DESC LIMIT 50`
    ).all();
    const posts = (result.results ?? []).map(row => ({
      id:       row.id,
      date:     row.date,
      sensor:   row.sensor,
      tags:     JSON.parse(row.tags ?? '[]'),
      title:    row.title,
      lede:     row.lede,
      findings: JSON.parse(row.findings ?? '{}'),
      body:     JSON.parse(row.body ?? '[]'),
    }));
    return json({ posts, total: posts.length });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

async function handleSignalStats(url, env) {
  if (!env.DB) return json({ error: 'D1 not configured' }, 503);

  const days = parseInt(url.searchParams.get('days') ?? '7');
  const since = days === 0
    ? null
    : new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  const where  = since ? `WHERE ts >= '${since}'` : '';
  const where2 = since ? `AND ts >= '${since}'`   : '';

  try {
    const [summary, volume, topIps, topCmds, topCreds, versions] = await env.DB.batch([

      // Summary counts
      env.DB.prepare(`
        SELECT
          COUNT(DISTINCT session) as sessions,
          COUNT(*) as events
        FROM events ${where}
      `),

      // Volume by day
      env.DB.prepare(`
        SELECT
          DATE(ts) as date,
          COUNT(DISTINCT session) as sessions,
          COUNT(*) as events
        FROM events ${where}
        GROUP BY DATE(ts)
        ORDER BY date ASC
        LIMIT 90
      `),

      // Top source IPs by session count
      env.DB.prepare(`
        SELECT
          src_ip,
          geo_country as country,
          COUNT(DISTINCT session) as sessions
        FROM events
        WHERE eventid = 'cowrie.session.connect' ${where2}
        GROUP BY src_ip
        ORDER BY sessions DESC
        LIMIT 10
      `),

      // Top commands
      env.DB.prepare(`
        SELECT
          input as cmd,
          COUNT(*) as count
        FROM events
        WHERE eventid = 'cowrie.command.input'
          AND input IS NOT NULL ${where2}
        GROUP BY input
        ORDER BY count DESC
        LIMIT 10
      `),

      // Top credentials
      env.DB.prepare(`
        SELECT
          username as user,
          password_hash as pass,
          COUNT(*) as count
        FROM events
        WHERE eventid = 'cowrie.login.success'
          AND username IS NOT NULL ${where2}
        GROUP BY username, password_hash
        ORDER BY count DESC
        LIMIT 12
      `),

      // Client version strings for bot classification
      env.DB.prepare(`
        SELECT
          version,
          COUNT(DISTINCT session) as sessions
        FROM events
        WHERE eventid = 'cowrie.client.version'
          AND version IS NOT NULL ${where2}
        GROUP BY version
        ORDER BY sessions DESC
        LIMIT 50
      `),

    ]);

    const s = summary.results?.[0] ?? {};
    const totalSessions = s.sessions ?? 0;

    // Bot/human classification from client version strings
let botSessions = 0, humanSessions = 0;
const botSignals = { libssh: 0, paramiko: 0, golang: 0, other_bot: 0 };

// Known legitimate human SSH clients - allowlist approach
const humanClientPatterns = [
  /^ssh-2\.0-openssh_[89]\.\d+/,
  /^ssh-2\.0-openssh_10\.\d+/,
  /^ssh-2\.0-openssh_for_windows_[89]\.\d+/,
  /^ssh-2\.0-openssh_for_windows_10\.\d+/,
  /^ssh-2\.0-putty_release_/,
];

for (const row of (versions.results ?? [])) {
  const v = (row.version ?? '').toLowerCase();
  const n = row.sessions ?? 0;

  if (v.includes('libssh')) {
    botSessions += n; botSignals.libssh += n;
  } else if (v.includes('paramiko')) {
    botSessions += n; botSignals.paramiko += n;
  } else if (v === 'ssh-2.0-go' || v.startsWith('ssh-2.0-go/')) {
    botSessions += n; botSignals.golang += n;
  } else if (humanClientPatterns.some(p => p.test(v))) {
    humanSessions += n;
  } else {
    // Everything else — unrecognized libraries, old OpenSSH, scanners, garbage strings
    botSessions += n; botSignals.other_bot += n;
  }
}

    // Remove zero-count bot signal keys
    Object.keys(botSignals).forEach(k => { if (botSignals[k] === 0) delete botSignals[k]; });

    return json({
      window_days: days === 0 ? 'all' : days,
      updated_at: new Date().toISOString(),
      summary: {
        sessions:       totalSessions,
        events:         s.events ?? 0,
        bot_sessions:   botSessions,
        human_sessions: humanSessions,
      },
      volume: volume.results ?? [],
      bot_vs_human: {
        bot:         botSessions,
        human:       humanSessions,
        bot_signals: botSignals,
      },
      top_ips:         (topIps.results  ?? []).map(r => ({
        ip:       r.src_ip,
        country:  r.country ?? '??',
        sessions: r.sessions,
      })),
      top_commands:    (topCmds.results  ?? []).map(r => ({
        cmd:   r.cmd,
        count: r.count,
      })),
      top_credentials: (topCreds.results ?? []).map(r => ({
        user:  r.user,
        pass:  r.pass ?? '',
        count: r.count,
      })),
    });

  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (request.method !== "GET")     return json({ error: "method not allowed" }, 405);
    if (url.pathname === "/events")   return handleEvents(url, env);
    if (url.pathname === "/archive")  return handleArchive(url, env);
    if (url.pathname === "/stats")    return handleStats(env);
    if (url.pathname === "/pings")   return handleSignal(env);
    if (url.pathname === "/signal-stats") return handleSignalStats(url, env);
    return json({ error: "not found" }, 404);
  },
};
