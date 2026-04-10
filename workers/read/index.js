/**
 * bathysphere — read Worker
 * Serves stored events to the feed frontend.
 *
 * Bindings required (wrangler.toml):
 *   [[kv_namespaces]]
 *   binding = "EVENTS"
 *   id = "<same KV namespace ID as ingest Worker>"
 *
 * Endpoints:
 *   GET /events
 *     ?limit=N        return the N most recent events (default 100, max 500)
 *     ?since=<ts>     return only events with ts > this ISO timestamp
 *     ?eventid=<id>   filter to a specific event type
 *
 *   GET /stats
 *     Returns aggregate counts over all stored events
 */

const KV_KEY      = "events";
const DEFAULT_LIMIT = 100;
const MAX_LIMIT     = 500;

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: CORS });
}

async function handleEvents(url, env) {
  const params  = url.searchParams;
  const limit   = Math.min(parseInt(params.get("limit") ?? DEFAULT_LIMIT), MAX_LIMIT);
  const since   = params.get("since");
  const filterid = params.get("eventid");

  const raw = await env.EVENTS.get(KV_KEY);
  if (!raw) return json({ events: [], total: 0 });

  let events = JSON.parse(raw);

  // Filter by timestamp if ?since= provided
  if (since) {
    events = events.filter(e => e.ts > since);
  }

  // Filter by event type if ?eventid= provided
  if (filterid) {
    events = events.filter(e => e.eventid === filterid);
  }

  // Return the N most recent
  const slice = events.slice(-limit);

  return json({
    events: slice,
    total:  events.length,
    oldest: events[0]?.ts ?? null,
    newest: events[events.length - 1]?.ts ?? null,
  });
}

async function handleStats(env) {
  const raw = await env.EVENTS.get(KV_KEY);
  if (!raw) return json({ error: "no data" }, 404);

  const events = JSON.parse(raw);

  const counts = {};
  let sessions = 0, logins_ok = 0, logins_fail = 0, commands = 0, uploads = 0;
  const ips = new Set();

  for (const e of events) {
    counts[e.eventid] = (counts[e.eventid] ?? 0) + 1;
    if (e.src_ip) ips.add(e.src_ip);
    if (e.eventid === "cowrie.session.connect")  sessions++;
    if (e.eventid === "cowrie.login.success")    logins_ok++;
    if (e.eventid === "cowrie.login.failed")     logins_fail++;
    if (e.eventid === "cowrie.command.input")    commands++;
    if (e.eventid === "cowrie.session.file_upload") uploads++;
  }

  return json({
    total_events:   events.length,
    unique_ips:     ips.size,
    sessions,
    logins_ok,
    logins_fail,
    commands,
    uploads,
    oldest: events[0]?.ts ?? null,
    newest: events[events.length - 1]?.ts ?? null,
    by_eventid: counts,
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (request.method !== "GET") {
      return json({ error: "method not allowed" }, 405);
    }

    if (url.pathname === "/events") return handleEvents(url, env);
    if (url.pathname === "/stats")  return handleStats(env);

    return json({ error: "not found" }, 404);
  },
};
