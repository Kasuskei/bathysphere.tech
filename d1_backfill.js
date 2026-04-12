#!/usr/bin/env node
/**
 * d1_backfill.js
 * Reads the full Cowrie log, enriches with geo + AbuseIPDB,
 * and bulk inserts into D1 via the ingest Worker.
 *
 * Usage:
 *   $env:SHARED_SECRET="your_secret"
 *   $env:ABUSEIPDB_KEY="your_key"
 *   node d1_backfill.js
 *
 * The script is resumable — it tracks progress in d1_backfill_state.json
 * and skips events already in D1 (INSERT OR IGNORE handles duplicates).
 */

const fs       = require('fs');
const readline = require('readline');
const path     = require('path');
const crypto   = require('crypto');

// ── Config ────────────────────────────────────────────────────────────────────
const LOG_FILE      = path.join(__dirname, 'logs', 'cowrie_full.json');
const STATE_FILE    = path.join(__dirname, 'd1_backfill_state.json');
const INGEST_URL    = 'https://bathysphere-ingest.kasuskei.workers.dev/backfill';
const SHARED_SECRET = process.env.SHARED_SECRET;
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY;
const BATCH_SIZE    = 50;    // events per POST to ingest Worker
const GEO_DELAY_MS  = 1100; // ip-api.com: 45 req/min free tier
const ABUSE_DELAY_MS= 1100; // AbuseIPDB: 1000/day, space them out
// ─────────────────────────────────────────────────────────────────────────────

const BLOCKLIST = ['192.168.', '127.', '10.', '172.16.', '::1'];

function isBlocked(ip) {
  return !ip || BLOCKLIST.some(p => ip.startsWith(p));
}

function anonymize(ip) {
  if (!ip) return null;
  if (ip.includes(':')) return ip.split(':')[0] + ':x:x:x:x:x:x:x';
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  return `${parts[0]}.${parts[1]}.x.x`;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); }
  catch { return { offset: 0, processed: 0, inserted: 0 }; }
}

function saveState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

// ── Persistent cache files ────────────────────────────────────────────────────
const GEO_CACHE_FILE   = path.join(__dirname, 'd1_backfill_geo_cache.json');
const ABUSE_CACHE_FILE = path.join(__dirname, 'd1_backfill_abuse_cache.json');

function loadCache(file) {
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    return new Map(Object.entries(data));
  } catch { return new Map(); }
}

function saveCache(file, map) {
  fs.writeFileSync(file, JSON.stringify(Object.fromEntries(map), null, 2));
}

// ── Geo lookup with persistent cache ─────────────────────────────────────────
const geoCache = loadCache(GEO_CACHE_FILE);
let geoRequests = 0;

async function geoLookup(ip) {
  if (geoCache.has(ip)) return geoCache.get(ip);
  try {
    if (geoRequests > 0) await sleep(GEO_DELAY_MS);
    geoRequests++;
    const resp = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city`, { signal: AbortSignal.timeout(3000) });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (data.status !== 'success') { geoCache.set(ip, null); return null; }
    const geo = { country: data.country ?? null, city: data.city ?? null };
    geoCache.set(ip, geo);
    // Persist every 50 new lookups
    if (geoRequests % 50 === 0) saveCache(GEO_CACHE_FILE, geoCache);
    return geo;
  } catch {
    return null;
  }
}

// ── AbuseIPDB lookup with persistent cache ────────────────────────────────────
const abuseCache = loadCache(ABUSE_CACHE_FILE);
let abuseRequests = 0;

async function abuseLookup(ip) {
  if (!ABUSEIPDB_KEY) return null;
  if (abuseCache.has(ip)) return abuseCache.get(ip);
  try {
    if (abuseRequests > 0) await sleep(ABUSE_DELAY_MS);
    abuseRequests++;
    const resp = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { headers: { 'Key': ABUSEIPDB_KEY, 'Accept': 'application/json' }, signal: AbortSignal.timeout(5000) }
    );
    if (!resp.ok) return null;
    const data = await resp.json();
    const d = data?.data;
    if (!d) return null;
    const result = { score: d.abuseConfidenceScore ?? 0, reports: d.totalReports ?? 0 };
    abuseCache.set(ip, result);
    // Persist every 50 new lookups
    if (abuseRequests % 50 === 0) saveCache(ABUSE_CACHE_FILE, abuseCache);
    return result;
  } catch {
    return null;
  }
}

// ── Local IoC signatures (mirrors ingest Worker) ──────────────────────────────
const IOC_SIGNATURES = [
  { match: e => /mdrfckr/.test(e.input ?? ''),                           ioc: { type: 'persistence',  label: 'mdrfckr SSH backdoor key',           severity: 'critical' } },
  { match: e => /redtail/i.test(e.filename ?? e.url ?? ''),              ioc: { type: 'malware',      label: 'Redtail cryptominer',                 severity: 'critical' } },
  { match: e => /\.arm[0-9]|\.x86_64|\.i686|\.mips/.test(e.filename ?? ''), ioc: { type: 'malware', label: 'Multi-arch malware dropper',           severity: 'critical' } },
  { match: e => /TelegramDesktop|tdata/.test(e.input ?? ''),             ioc: { type: 'exfiltration', label: 'Telegram session theft attempt',      severity: 'high' } },
  { match: e => /chmod\s+\+x\s+\.\/\.[^\/]+\//.test(e.input ?? ''),     ioc: { type: 'malware',      label: 'Hidden directory dropper',            severity: 'high' } },
  { match: e => /authorized_keys/.test(e.input ?? ''),                   ioc: { type: 'persistence',  label: 'SSH key injection',                   severity: 'high' } },
  { match: e => /grep.*[Mm]iner/.test(e.input ?? ''),                    ioc: { type: 'recon',        label: 'Cryptominer recon',                   severity: 'medium' } },
  { match: e => /sol|solana/.test(e.username ?? ''),                     ioc: { type: 'credential',   label: 'Solana node targeting',               severity: 'medium' } },
  { match: e => e.username === '345gs5662d34',                           ioc: { type: 'credential',   label: 'Mirai botnet credential',             severity: 'high' } },
  { match: e => e.eventid === 'cowrie.direct-tcpip.request',             ioc: { type: 'c2',           label: 'TCP tunnel / proxy attempt',          severity: 'medium' } },
  { match: e => /ZGrab/i.test(e.version ?? ''),                          ioc: { type: 'scanner',      label: 'ZGrab internet scanner',              severity: 'low' } },
  { match: e => /clean\.sh/i.test(e.filename ?? ''),                     ioc: { type: 'malware',      label: 'Competing malware cleanup script',    severity: 'high' } },
];

const ATTACK_RULES = [
  { match: e => e.eventid === 'cowrie.session.connect',                                                    technique: { id: 'T1595.002', name: 'Vulnerability Scanning',                     tactic: 'Reconnaissance' } },
  { match: e => e.eventid === 'cowrie.client.version',                                                     technique: { id: 'T1595.001', name: 'Scanning IP Blocks',                         tactic: 'Reconnaissance' } },
  { match: e => e.eventid === 'cowrie.login.failed',                                                       technique: { id: 'T1110.001', name: 'Password Guessing',                          tactic: 'Credential Access' } },
  { match: e => e.eventid === 'cowrie.login.success',                                                      technique: { id: 'T1078',     name: 'Valid Accounts',                            tactic: 'Initial Access' } },
  { match: e => e.eventid === 'cowrie.command.input' && /uname|\/proc\/version/.test(e.input ?? ''),       technique: { id: 'T1082',     name: 'System Information Discovery',              tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /\/proc\/cpuinfo|lscpu/.test(e.input ?? ''),       technique: { id: 'T1082',     name: 'System Information Discovery',              tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /ifconfig|ip addr/.test(e.input ?? ''),            technique: { id: 'T1016',     name: 'System Network Configuration Discovery',    tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /\bps\b/.test(e.input ?? ''),                      technique: { id: 'T1057',     name: 'Process Discovery',                         tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /whoami|id\b|groups\b|w\b/.test(e.input ?? ''),    technique: { id: 'T1033',     name: 'System Owner/User Discovery',               tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /crontab/.test(e.input ?? ''),                     technique: { id: 'T1053.003', name: 'Cron',                                      tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /authorized_keys/.test(e.input ?? ''),             technique: { id: 'T1098.004', name: 'SSH Authorized Keys',                       tactic: 'Persistence' } },
  { match: e => e.eventid === 'cowrie.command.input' && /chattr|lockr/.test(e.input ?? ''),                technique: { id: 'T1222.002', name: 'Linux File/Directory Permissions Modification', tactic: 'Defense Evasion' } },
  { match: e => e.eventid === 'cowrie.command.input' && /nohup|systemctl/.test(e.input ?? ''),             technique: { id: 'T1543',     name: 'Create or Modify System Process',           tactic: 'Persistence' } },
  { match: e => e.eventid === 'cowrie.command.input' && /rm -rf|shred/.test(e.input ?? ''),                technique: { id: 'T1070.004', name: 'File Deletion',                             tactic: 'Defense Evasion' } },
  { match: e => e.eventid === 'cowrie.command.input' && /pkill|kill -9/.test(e.input ?? ''),               technique: { id: 'T1562.001', name: 'Disable or Modify Tools',                   tactic: 'Defense Evasion' } },
  { match: e => e.eventid === 'cowrie.command.input' && /chmod\s+\+x\s+\.\/\.[^\/]+\//.test(e.input ?? ''), technique: { id: 'T1564.001', name: 'Hidden Files and Directories',            tactic: 'Defense Evasion' } },
  { match: e => e.eventid === 'cowrie.command.input' && /TelegramDesktop|tdata/.test(e.input ?? ''),       technique: { id: 'T1005',     name: 'Data from Local System',                   tactic: 'Collection' } },
  { match: e => e.eventid === 'cowrie.direct-tcpip.request',                                               technique: { id: 'T1572',     name: 'Protocol Tunneling',                       tactic: 'Command and Control' } },
  { match: e => e.eventid === 'cowrie.command.input' && /[Mm]iner|xmrig/.test(e.input ?? ''),              technique: { id: 'T1496',     name: 'Resource Hijacking',                       tactic: 'Impact' } },
  { match: e => (e.eventid === 'cowrie.session.file_upload' || e.eventid === 'cowrie.session.file_download') && /redtail|miner/.test(e.filename ?? e.url ?? ''), technique: { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' } },
  { match: e => e.eventid === 'cowrie.command.input',                                                      technique: { id: 'T1059.004', name: 'Unix Shell',                                tactic: 'Execution' } },
  { match: e => e.eventid === 'cowrie.session.file_upload' || e.eventid === 'cowrie.session.file_download', technique: { id: 'T1570',   name: 'Lateral Tool Transfer',                    tactic: 'Lateral Movement' } },
];

function classifyAttack(e) {
  for (const r of ATTACK_RULES) { try { if (r.match(e)) return r.technique; } catch {} }
  return null;
}

function matchIocs(e, abuse) {
  const iocs = [];
  for (const s of IOC_SIGNATURES) { try { if (s.match(e)) iocs.push(s.ioc); } catch {} }
  if (abuse && abuse.score > 25) {
    iocs.push({ type: 'reputation', label: `AbuseIPDB ${abuse.score}% confidence`, severity: abuse.score >= 75 ? 'critical' : abuse.score >= 50 ? 'high' : 'medium', reports: abuse.reports });
  }
  return iocs.length ? iocs : null;
}

// ── Normalize a raw Cowrie event ──────────────────────────────────────────────
function normalize(raw, geo, abuse) {
  if (isBlocked(raw.src_ip)) return null;
  const anon_ip = anonymize(raw.src_ip);
  if (!anon_ip) return null;

  const base = {
    id:       raw.uuid ?? crypto.randomUUID(),
    ts:       raw.timestamp,
    eventid:  raw.eventid,
    session:  raw.session ?? null,
    src_ip:   anon_ip,
    protocol: raw.protocol ?? 'ssh',
    sensor:   raw.sensor ?? 'honeypot-pi',
    geo:      geo ?? null,
  };

  let event;
  switch (raw.eventid) {
    case 'cowrie.session.connect':    event = { ...base, dst_port: raw.dst_port }; break;
    case 'cowrie.session.closed':     event = { ...base, duration: parseFloat(raw.duration) }; break;
    case 'cowrie.client.version':     event = { ...base, version: raw.version }; break;
    case 'cowrie.login.success':
    case 'cowrie.login.failed':
      event = { ...base, username: raw.username,
        password_hash: raw.password ? raw.password.slice(0,2)+'***'+raw.password.slice(-1) : null,
        password_len: raw.password?.length ?? null }; break;
    case 'cowrie.command.input':
    case 'cowrie.command.failed':     event = { ...base, input: raw.input }; break;
    case 'cowrie.session.file_upload': event = { ...base, filename: raw.filename, shasum: raw.shasum }; break;
    case 'cowrie.session.file_download': event = { ...base, url: raw.url, shasum: raw.shasum }; break;
    default: event = base;
  }

  const attack = classifyAttack(event);
  if (attack) event.attack = attack;

  const iocs = matchIocs(event, abuse);
  if (iocs) event.iocs = iocs;

  return event;
}

// ── POST a batch to the ingest Worker ────────────────────────────────────────
async function postBatch(events) {
  const resp = await fetch(INGEST_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Bathysphere-Secret': SHARED_SECRET },
    body: JSON.stringify({ events }),
  });
  if (!resp.ok) throw new Error(`Ingest returned ${resp.status}: ${await resp.text()}`);
  return resp.json();
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  if (!SHARED_SECRET) { console.error('Set $env:SHARED_SECRET before running.'); process.exit(1); }

  const state = loadState();
  console.log(`Resuming from line offset ${state.offset}. Previously processed: ${state.processed}, inserted: ${state.inserted}`);

  // First pass: collect all unique raw IPs for batch geo lookup
  console.log('Pass 1: collecting unique IPs...');
  const uniqueIps = new Set();
  let lineCount = 0;
  {
    const rl = readline.createInterface({ input: fs.createReadStream(LOG_FILE), crlfDelay: Infinity });
    for await (const line of rl) {
      lineCount++;
      try {
        const e = JSON.parse(line.trim());
        if (e.src_ip && !isBlocked(e.src_ip)) uniqueIps.add(e.src_ip);
      } catch {}
    }
  }
  console.log(`Total lines: ${lineCount}. Unique external IPs: ${uniqueIps.size}`);

  // Geo lookup for all unique IPs
  console.log('Pass 1a: geo lookups...');
  let geoCount = 0;
  for (const ip of uniqueIps) {
    await geoLookup(ip);
    geoCount++;
    if (geoCount % 50 === 0) console.log(`  Geo: ${geoCount}/${uniqueIps.size}`);
  }
  console.log(`Geo lookups complete. Cache size: ${geoCache.size}`);

  // AbuseIPDB lookup for all unique IPs
  if (ABUSEIPDB_KEY) {
    console.log('Pass 1b: AbuseIPDB lookups...');
    let abuseCount = 0;
    for (const ip of uniqueIps) {
      await abuseLookup(ip);
      abuseCount++;
      if (abuseCount % 50 === 0) console.log(`  Abuse: ${abuseCount}/${uniqueIps.size}`);
    }
    console.log(`AbuseIPDB lookups complete. Cache size: ${abuseCache.size}`);
  }

  // Second pass: normalize and push events
  console.log('Pass 2: normalizing and pushing events...');
  let currentLine = 0;
  let batch = [];
  let processed = 0;
  let inserted = 0;

  const rl2 = readline.createInterface({ input: fs.createReadStream(LOG_FILE), crlfDelay: Infinity });

  for await (const line of rl2) {
    currentLine++;
    if (currentLine <= state.offset) continue;

    try {
      const raw = JSON.parse(line.trim());
      const geo   = raw.src_ip ? geoCache.get(raw.src_ip) ?? null : null;
      const abuse = raw.src_ip ? abuseCache.get(raw.src_ip) ?? null : null;
      const event = normalize(raw, geo, abuse);
      if (event) batch.push(event);
    } catch {}

    processed++;

    if (batch.length >= BATCH_SIZE) {
      try {
        const result = await postBatch(batch);
        inserted += result.stored ?? batch.length;
        state.offset    = currentLine;
        state.processed = (state.processed ?? 0) + processed;
        state.inserted  = (state.inserted  ?? 0) + inserted;
        saveState(state);
        if (Math.floor(currentLine / BATCH_SIZE) % 10 === 0) {
          console.log(`  Line ${currentLine}/${lineCount} — pushed ${inserted} events so far`);
        }
        batch = [];
        processed = 0;
        inserted = 0;
      } catch (err) {
        console.error(`Batch failed at line ${currentLine}: ${err.message}. Retrying in 5s...`);
        await sleep(5000);
      }
    }
  }

  // Push remaining events
  if (batch.length > 0) {
    const result = await postBatch(batch);
    inserted += result.stored ?? batch.length;
    console.log(`Final batch: pushed ${inserted} events.`);
  }

  state.offset = lineCount;
  saveState(state);
  saveCache(GEO_CACHE_FILE, geoCache);
  saveCache(ABUSE_CACHE_FILE, abuseCache);
  console.log(`\nBackfill complete. Total lines: ${lineCount}. Check D1 row count with:`);
  console.log(`wrangler d1 execute bathysphere --remote --command="SELECT COUNT(*) FROM events"`);
}

main().catch(err => { console.error(err); process.exit(1); });
