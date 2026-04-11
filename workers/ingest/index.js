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

// ── MITRE ATT&CK mapping ───────────────────────────────────────────────────
//
// Each rule is evaluated in order. The first match wins.
// Rules can match on eventid, and optionally inspect the event payload
// for more specific classification (e.g. a specific command pattern).
//
// technique: { id, name, tactic } maps to ATT&CK Enterprise.

const ATTACK_RULES = [
  // ── Reconnaissance / Initial Access ───────────────────────────────────────
  {
    match: e => e.eventid === "cowrie.session.connect",
    technique: { id: "T1595.002", name: "Vulnerability Scanning", tactic: "Reconnaissance" },
  },
  {
    match: e => e.eventid === "cowrie.client.version",
    technique: { id: "T1595.001", name: "Scanning IP Blocks", tactic: "Reconnaissance" },
  },

  // ── Credential Access ──────────────────────────────────────────────────────
  {
    match: e => e.eventid === "cowrie.login.failed",
    technique: { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
  },
  {
    // Credential stuffing: same username and password (e.g. 345gs5662d34/345gs5662d34)
    match: e => e.eventid === "cowrie.login.failed" && e.username === e.password_hash?.slice(0,2),
    technique: { id: "T1110.004", name: "Credential Stuffing", tactic: "Credential Access" },
  },
  {
    match: e => e.eventid === "cowrie.login.success",
    technique: { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
  },

  // ── Discovery ─────────────────────────────────────────────────────────────
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /uname|\/proc\/version|\/etc\/os-release/.test(e.input),
    technique: { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /\/proc\/cpuinfo|lscpu|nproc/.test(e.input),
    technique: { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /ifconfig|ip addr|ip link|netstat|ss -/.test(e.input),
    technique: { id: "T1016", name: "System Network Configuration Discovery", tactic: "Discovery" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /\bps\b|\/proc\/[0-9]/.test(e.input),
    technique: { id: "T1057", name: "Process Discovery", tactic: "Discovery" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /whoami|id\b|groups\b|w\b|who\b/.test(e.input),
    technique: { id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /crontab|\/etc\/cron/.test(e.input),
    technique: { id: "T1053.003", name: "Cron", tactic: "Discovery" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /df\b|lsblk|fdisk|mount\b/.test(e.input),
    technique: { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /free\b|\/proc\/meminfo/.test(e.input),
    technique: { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  },

  // ── Persistence ───────────────────────────────────────────────────────────
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /authorized_keys/.test(e.input),
    technique: { id: "T1098.004", name: "SSH Authorized Keys", tactic: "Persistence" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /chattr|lockr/.test(e.input),
    technique: { id: "T1222.002", name: "Linux File/Directory Permissions Modification", tactic: "Defense Evasion" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /nohup|systemctl|service\b/.test(e.input),
    technique: { id: "T1543", name: "Create or Modify System Process", tactic: "Persistence" },
  },

  // ── Defense Evasion ───────────────────────────────────────────────────────
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /rm -rf|shred|unlink/.test(e.input),
    technique: { id: "T1070.004", name: "File Deletion", tactic: "Defense Evasion" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /pkill|kill -9/.test(e.input),
    technique: { id: "T1562.001", name: "Disable or Modify Tools", tactic: "Defense Evasion" },
  },
  {
    // Hidden directory dropper (e.g. ./.3264486628506439129/xinetd)
    match: e => e.eventid === "cowrie.command.input" &&
      /chmod\s+\+x\s+\.\/\.[^\/]+\//.test(e.input),
    technique: { id: "T1564.001", name: "Hidden Files and Directories", tactic: "Defense Evasion" },
  },

  // ── Collection / Exfiltration ─────────────────────────────────────────────
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /TelegramDesktop|tdata|ttyGSM|ttyUSB|smsd|qmuxd|modem/.test(e.input),
    technique: { id: "T1005", name: "Data from Local System", tactic: "Collection" },
  },
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /locate\s+[A-F0-9]{8,}/.test(e.input),
    technique: { id: "T1005", name: "Data from Local System", tactic: "Collection" },
  },

  // ── Command and Control ───────────────────────────────────────────────────
  {
    match: e => e.eventid === "cowrie.direct-tcpip.request",
    technique: { id: "T1572", name: "Protocol Tunneling", tactic: "Command and Control" },
  },

  // ── Impact ────────────────────────────────────────────────────────────────
  {
    match: e => e.eventid === "cowrie.command.input" &&
      /[Mm]iner|xmrig|xmr|monero|stratum\+/.test(e.input),
    technique: { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
  },
  {
    match: e => (e.eventid === "cowrie.session.file_upload" ||
                 e.eventid === "cowrie.session.file_download") &&
      /redtail|miner|xmrig/.test(e.filename ?? e.url ?? ""),
    technique: { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
  },

  // ── Execution ─────────────────────────────────────────────────────────────
  {
    // Generic shell command execution — catch-all for command events not
    // matched by a more specific rule above
    match: e => e.eventid === "cowrie.command.input",
    technique: { id: "T1059.004", name: "Unix Shell", tactic: "Execution" },
  },

  // ── Lateral Movement ─────────────────────────────────────────────────────
  {
    match: e => (e.eventid === "cowrie.session.file_upload" ||
                 e.eventid === "cowrie.session.file_download"),
    technique: { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement" },
  },
];

/**
 * Return the first matching ATT&CK technique for a normalized event,
 * or null if no rule matches.
 */
function classifyAttack(event) {
  for (const rule of ATTACK_RULES) {
    try {
      if (rule.match(event)) return rule.technique;
    } catch {
      // match function threw (e.g. regex on undefined field) — skip
    }
  }
  return null;
}

const MAX_EVENTS = 10_000;   // rolling window size kept in KV
const KV_KEY     = "events"; // single key storing the JSON array
const GEO_TTL    = 60 * 60 * 24 * 30; // cache geo results for 30 days

// IPs we never want to appear in the feed even anonymized
// (RFC 5737 documentation ranges, loopback, your own Pi's LAN IP)
const BLOCKLIST  = ["192.168.", "127.", "10.", "172.16.", "::1"];

/**
 * Look up geo data for a raw IP address.
 * Checks KV cache first — only calls ip-api.com on a cache miss.
 * Returns { country, city } or null on failure.
 * Raw IP is never stored — only the location result.
 */
async function geoLookup(ip, env) {
  const cacheKey = `geo:${ip}`;
  try {
    const cached = await env.EVENTS.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const resp = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,city`,
      { signal: AbortSignal.timeout(2000) }
    );
    if (!resp.ok) return null;

    const data = await resp.json();
    if (data.status !== 'success') return null;

    const geo = { country: data.country ?? null, city: data.city ?? null };
    // Cache the result — fire and forget, don't block ingest
    env.EVENTS.put(cacheKey, JSON.stringify(geo), { expirationTtl: GEO_TTL });
    return geo;
  } catch {
    return null;
  }
}

/**
 * Build a geo cache for all unique raw IPs in a batch.
 * Returns a Map of raw_ip -> { country, city }.
 */
async function batchGeoLookup(rawIps, env) {
  const unique = [...new Set(rawIps.filter(ip => ip && !isBlocked(ip)))];
  const results = await Promise.all(unique.map(ip => geoLookup(ip, env)));
  const map = new Map();
  unique.forEach((ip, i) => { if (results[i]) map.set(ip, results[i]); });
  return map;
}

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
 * Drops fields we don't need, anonymizes IPs, attaches geo.
 */
function normalize(raw, geo) {
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
    // Geo attached here — raw IP never stored
    geo:       geo ?? null,
  };

  // Attach event-type-specific fields
  let event;
  switch (raw.eventid) {
    case "cowrie.session.connect":
      event = { ...base, dst_port: raw.dst_port };
      break;

    case "cowrie.session.closed":
      event = { ...base, duration: parseFloat(raw.duration) };
      break;

    case "cowrie.client.version":
      event = { ...base, version: raw.version };
      break;

    case "cowrie.login.success":
    case "cowrie.login.failed":
      event = {
        ...base,
        username: raw.username,
        password_hash: raw.password
          ? raw.password.slice(0, 2) + "***" + raw.password.slice(-1)
          : null,
        password_len: raw.password?.length ?? null,
      };
      break;

    case "cowrie.command.input":
    case "cowrie.command.failed":
      event = { ...base, input: raw.input };
      break;

    case "cowrie.session.file_upload":
      event = { ...base, filename: raw.filename, shasum: raw.shasum };
      break;

    case "cowrie.session.file_download":
      event = { ...base, url: raw.url, shasum: raw.shasum };
      break;

    default:
      event = base;
  }

  // ── ATT&CK classification ─────────────────────────────────────────────────
  const technique = classifyAttack(event);
  if (technique) event.attack = technique;

  return event;
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

  // ── Geo lookup (batch, raw IPs, before anonymization) ─────────────────────
  const rawIps = body.events.map(e => e.src_ip).filter(Boolean);
  const geoMap = await batchGeoLookup(rawIps, env);

  // ── Normalize ─────────────────────────────────────────────────────────────
  const incoming = body.events
    .map(e => normalize(e, geoMap.get(e.src_ip) ?? null))
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
