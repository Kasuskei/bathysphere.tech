/**
 * bathysphere — ingest Worker
 * Receives event batches from the Pi pusher and writes them to KV.
 *
 * Bindings required (wrangler.toml):
 *   [[kv_namespaces]]
 *   binding = "EVENTS"
 *   id = "<your KV namespace ID>"
 *
 * Secrets required (wrangler secret put):
 *   BATHYSPHERE_SECRET   — must match SHARED_SECRET on the Pi
 */

const MAX_EVENTS = 10_000;   // rolling window size kept in KV
const KV_KEY     = "events"; // single key storing the JSON array

// IPs we never want to appear in the feed even anonymized
// (RFC 5737 documentation ranges, loopback, your own Pi's LAN IP)
const BLOCKLIST  = ["192.168.", "127.", "10.", "172.16.", "::1"];

/**
 * Anonymize an IP address:
 *   IPv4  → keep first two octets, replace last two with x.x  (e.g. 165.154.x.x)
 *   IPv6  → keep first group only                              (e.g. 2001:x:x:x)
 */
function anonymize(ip) {
  if (!ip) return null;
  if (ip.includes(":")) {
    // IPv6
    const parts = ip.split(":");
    return parts[0] + ":x:x:x:x:x:x:x";
  }
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  return `${parts[0]}.${parts[1]}.x.x`;
}

function isBlocked(ip) {
  return BLOCKLIST.some(prefix => ip?.startsWith(prefix));
}

/**
 * Normalize a raw Cowrie event into what we store and serve.
 * Drops fields we don't need, anonymizes IPs.
 */
function normalize(raw) {
  if (isBlocked(raw.src_ip)) return null;

  const anon_ip = anonymize(raw.src_ip);
  if (!anon_ip) return null;

  const base = {
    id:        raw.uuid  ?? crypto.randomUUID(),
    ts:        raw.timestamp,
    eventid:   raw.eventid,
    session:   raw.session,
    src_ip:    anon_ip,
    protocol:  raw.protocol ?? "ssh",
    sensor:    raw.sensor ?? "honeypot-pi",
  };

  // Attach event-type-specific fields
  switch (raw.eventid) {
    case "cowrie.session.connect":
      return { ...base, dst_port: raw.dst_port };

    case "cowrie.session.closed":
      return { ...base, duration: parseFloat(raw.duration) };

    case "cowrie.client.version":
      return { ...base, version: raw.version };

    case "cowrie.login.success":
    case "cowrie.login.failed":
      return {
        ...base,
        username: raw.username,
        // Don't store passwords verbatim — hash them so patterns
        // are visible without leaking real credentials
        password_hash: raw.password
          ? raw.password.slice(0, 2) + "***" + raw.password.slice(-1)
          : null,
        password_len:  raw.password?.length ?? null,
      };

    case "cowrie.command.input":
    case "cowrie.command.failed":
      return { ...base, input: raw.input };

    case "cowrie.session.file_upload":
      return {
        ...base,
        filename: raw.filename,
        shasum:   raw.shasum,
      };

    case "cowrie.session.file_download":
      return {
        ...base,
        url:    raw.url,
        shasum: raw.shasum,
      };

    default:
      return base;
  }
}

async function handleIngest(request, env) {
  // ── Auth ──────────────────────────────────────────────────────────────────
  const secret = request.headers.get("X-Bathysphere-Secret");
  if (!secret || secret !== env.BATHYSPHERE_SECRET) {
    return new Response("Unauthorized", { status: 401 });
  }

  // ── Parse body ────────────────────────────────────────────────────────────
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response("Bad JSON", { status: 400 });
  }

  if (!Array.isArray(body?.events)) {
    return new Response("Expected { events: [...] }", { status: 400 });
  }

  // ── Normalize ─────────────────────────────────────────────────────────────
  const incoming = body.events
    .map(normalize)
    .filter(Boolean);

  if (incoming.length === 0) {
    return new Response(JSON.stringify({ stored: 0 }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // ── Read existing, append, trim ───────────────────────────────────────────
  const existing = JSON.parse(
    (await env.EVENTS.get(KV_KEY)) ?? "[]"
  );

  const merged = [...existing, ...incoming];
  const trimmed = merged.length > MAX_EVENTS
    ? merged.slice(merged.length - MAX_EVENTS)
    : merged;

  await env.EVENTS.put(KV_KEY, JSON.stringify(trimmed));

  return new Response(
    JSON.stringify({ stored: incoming.length, total: trimmed.length }),
    { headers: { "Content-Type": "application/json" } }
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ingest" && request.method === "POST") {
      return handleIngest(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
};
