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

const MAX_EVENTS   = 10_000;
const KV_KEY       = "events";
const GEO_TTL      = 60 * 60 * 24 * 30;  // 30 days
const ABUSE_TTL    = 60 * 60 * 24 * 7;   // 7 days — abuse scores change more often

// IPs we never want to appear in the feed even anonymized
const BLOCKLIST = ["192.168.", "127.", "10.", "172.16.", "::1"];

// ── Local IoC signatures ───────────────────────────────────────────────────
// Each rule checks a normalized event and returns an IoC object if matched.
// { type, label, severity }
//   severity: "critical" | "high" | "medium" | "low"

const IOC_SIGNATURES = [
  // Known Mirai credential pair
  {
    match: e => (e.eventid === 'cowrie.login.failed' || e.eventid === 'cowrie.login.success') &&
      e.username === '345gs5662d34',
    ioc: { type: 'credential', label: 'Mirai botnet credential', severity: 'high' },
  },
  // mdrfckr SSH backdoor key
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /mdrfckr/.test(e.input ?? ''),
    ioc: { type: 'persistence', label: 'mdrfckr SSH backdoor key', severity: 'critical' },
  },
  // Redtail cryptominer
  {
    match: e => (e.eventid === 'cowrie.session.file_upload' || e.eventid === 'cowrie.session.file_download') &&
      /redtail/i.test(e.filename ?? e.url ?? ''),
    ioc: { type: 'malware', label: 'Redtail cryptominer', severity: 'critical' },
  },
  // Generic cryptominer upload
  {
    match: e => e.eventid === 'cowrie.session.file_upload' &&
      /\.arm[0-9]|\.x86_64|\.i686|\.mips/.test(e.filename ?? ''),
    ioc: { type: 'malware', label: 'Multi-arch malware dropper', severity: 'critical' },
  },
  // Telegram credential exfiltration
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /TelegramDesktop|tdata/.test(e.input ?? ''),
    ioc: { type: 'exfiltration', label: 'Telegram session theft attempt', severity: 'high' },
  },
  // Hidden directory dropper
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /chmod\s+\+x\s+\.\/\.[^\/]+\//.test(e.input ?? ''),
    ioc: { type: 'malware', label: 'Hidden directory dropper', severity: 'high' },
  },
  // SSH authorized_keys injection
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /authorized_keys/.test(e.input ?? ''),
    ioc: { type: 'persistence', label: 'SSH key injection', severity: 'high' },
  },
  // Miner process check — attacker looking for existing miners
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /grep.*[Mm]iner/.test(e.input ?? ''),
    ioc: { type: 'recon', label: 'Cryptominer recon', severity: 'medium' },
  },
  // Solana node targeting
  {
    match: e => (e.eventid === 'cowrie.login.failed' || e.eventid === 'cowrie.login.success') &&
      /sol|solana/.test(e.username ?? ''),
    ioc: { type: 'credential', label: 'Solana node targeting', severity: 'medium' },
  },
  // TCP tunnel / proxy abuse
  {
    match: e => e.eventid === 'cowrie.direct-tcpip.request',
    ioc: { type: 'c2', label: 'TCP tunnel / proxy attempt', severity: 'medium' },
  },
  // ZGrab scanner
  {
    match: e => e.eventid === 'cowrie.client.version' &&
      /ZGrab/i.test(e.version ?? ''),
    ioc: { type: 'scanner', label: 'ZGrab internet scanner', severity: 'low' },
  },
  // clean.sh — typically used to remove competing malware
  {
    match: e => e.eventid === 'cowrie.session.file_upload' &&
      /clean\.sh/i.test(e.filename ?? ''),
    ioc: { type: 'malware', label: 'Competing malware cleanup script', severity: 'high' },
  },
];

/**
 * Run local signature matching against a normalized event.
 * Returns array of matched IoC objects (may be empty).
 */
function matchLocalIocs(event) {
  const matched = [];
  for (const sig of IOC_SIGNATURES) {
    try {
      if (sig.match(event)) matched.push(sig.ioc);
    } catch { /* skip */ }
  }
  return matched;
}

// ── AbuseIPDB lookup ───────────────────────────────────────────────────────

/**
 * Look up an IP's abuse confidence score from AbuseIPDB.
 * Caches results in KV for 7 days.
 * Returns { score, categories } or null on failure.
 * Raw IP is used for lookup but never stored.
 */
async function abuseIpLookup(ip, env) {
  if (!env.ABUSEIPDB_KEY) return null;
  const cacheKey = `abuse:${ip}`;
  try {
    const cached = await env.EVENTS.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const resp = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: {
          'Key': env.ABUSEIPDB_KEY,
          'Accept': 'application/json',
        },
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
      categories: d.reports?.slice(0,3).map(r => r.categories).flat().slice(0,5) ?? [],
    };
    env.EVENTS.put(cacheKey, JSON.stringify(result), { expirationTtl: ABUSE_TTL });
    return result;
  } catch {
    return null;
  }
}

/**
 * Batch AbuseIPDB + geo lookup for all unique IPs in a batch.
 * Returns Map of raw_ip -> { geo, abuse }
 */
async function batchEnrich(rawIps, env) {
  const unique = [...new Set(rawIps.filter(ip => ip && !isBlocked(ip)))];
  const [geoResults, abuseResults] = await Promise.all([
    Promise.all(unique.map(ip => geoLookup(ip, env))),
    Promise.all(unique.map(ip => abuseIpLookup(ip, env))),
  ]);
  const map = new Map();
  unique.forEach((ip, i) => {
    map.set(ip, {
      geo:   geoResults[i]   ?? null,
      abuse: abuseResults[i] ?? null,
    });
  });
  return map;
}

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
 * Drops fields we don't need, anonymizes IPs, attaches geo + IoCs.
 */
function normalize(raw, enrichment) {
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
    geo:       enrichment?.geo ?? null,
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

  // ── IoC enrichment ────────────────────────────────────────────────────────
  const localIocs = matchLocalIocs(event);

  // Add AbuseIPDB as an IoC if score is significant (>25)
  const abuse = enrichment?.abuse;
  if (abuse && abuse.score > 25) {
    localIocs.push({
      type:     'reputation',
      label:    `AbuseIPDB ${abuse.score}% confidence`,
      severity: abuse.score >= 75 ? 'critical' : abuse.score >= 50 ? 'high' : 'medium',
      reports:  abuse.reports,
    });
  }

  if (localIocs.length > 0) event.iocs = localIocs;

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

  // ── Enrichment (geo + AbuseIPDB, batch, raw IPs before anonymization) ──────
  const rawIps = body.events.map(e => e.src_ip).filter(Boolean);
  const enrichMap = await batchEnrich(rawIps, env);

  // ── Normalize ─────────────────────────────────────────────────────────────
  const incoming = body.events
    .map(e => normalize(e, enrichMap.get(e.src_ip) ?? null))
    .filter(Boolean);

  if (incoming.length === 0) {
    return new Response(JSON.stringify({ stored: 0 }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // ── Write to KV (rolling window for live feed) ───────────────────────────
  const existing = JSON.parse(
    (await env.EVENTS.get(KV_KEY)) ?? "[]"
  );

  const merged = [...existing, ...incoming];
  const trimmed = merged.length > MAX_EVENTS
    ? merged.slice(merged.length - MAX_EVENTS)
    : merged;

  await env.EVENTS.put(KV_KEY, JSON.stringify(trimmed));

  // ── Write to D1 (permanent archive) ──────────────────────────────────────
  if (env.DB) {
    await writeToD1(incoming, env.DB);
  }

  return new Response(
    JSON.stringify({ stored: incoming.length, total: trimmed.length }),
    { headers: { "Content-Type": "application/json" } }
  );
}

/**
 * Insert a batch of normalized events into D1.
 * Uses INSERT OR IGNORE to handle duplicate IDs gracefully.
 */
async function writeToD1(events, db) {
  // D1 batch API — execute multiple statements in one round trip
  const stmts = events.map(e =>
    db.prepare(`
      INSERT OR IGNORE INTO events (
        id, ts, eventid, session, src_ip, protocol, sensor,
        geo_country, geo_city,
        dst_port, duration, version,
        username, password_hash, password_len,
        input, filename, shasum, url,
        attack_id, attack_name, attack_tactic,
        iocs, abuse_score
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      e.id,
      e.ts,
      e.eventid,
      e.session ?? null,
      e.src_ip ?? null,
      e.protocol ?? 'ssh',
      e.sensor ?? 'honeypot-pi',
      e.geo?.country ?? null,
      e.geo?.city ?? null,
      e.dst_port ?? null,
      e.duration ?? null,
      e.version ?? null,
      e.username ?? null,
      e.password_hash ?? null,
      e.password_len ?? null,
      e.input ?? null,
      e.filename ?? null,
      e.shasum ?? null,
      e.url ?? null,
      e.attack?.id ?? null,
      e.attack?.name ?? null,
      e.attack?.tactic ?? null,
      e.iocs ? JSON.stringify(e.iocs) : null,
      e.iocs?.find(i => i.type === 'reputation')?.score ?? null
    )
  );

  try {
    await db.batch(stmts);
  } catch (err) {
    // Log but don't fail the ingest — KV write already succeeded
    console.error('D1 write failed:', err.message);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ingest" && request.method === "POST") {
      return handleIngest(request, env);
    }

    // ── Backfill endpoint — accepts pre-normalized events directly ────────────
    // Used by geo_backfill.js to replace KV contents with geo-enriched events
    if (url.pathname === "/backfill" && request.method === "POST") {
      const secret = request.headers.get("X-Bathysphere-Secret");
      if (!secret || secret !== env.BATHYSPHERE_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      let body;
      try { body = await request.json(); } catch {
        return new Response("Bad JSON", { status: 400 });
      }
      if (!Array.isArray(body?.events)) {
        return new Response("Expected { events: [...] }", { status: 400 });
      }
      await env.EVENTS.put(KV_KEY, JSON.stringify(body.events));
      return new Response(
        JSON.stringify({ stored: body.events.length }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    return new Response("Not found", { status: 404 });
  },
};
