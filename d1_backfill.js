#!/usr/bin/env node
/**
 * d1_backfill.js — fixed
 *
 * Fixes:
 *  1. Flattens geo into geo_country/geo_city to match D1 schema + Worker expectations
 *  2. Skips Pass 1 geo/abuse collection if all IPs already cached (fast resume)
 *  3. Added MAX_LINES limit for test runs (set to 0 to disable)
 *  4. Better per-batch logging so you can see stored counts immediately
 *
 * Usage:
 *   $env:SHARED_SECRET="your_secret"
 *   $env:ABUSEIPDB_KEY="your_key"
 *   node d1_backfill.js
 *
 * For a 50-event test run:
 *   $env:MAX_LINES="500"   <- reads only first 500 log lines (yields ~50 events)
 *   node d1_backfill.js
 */

const fs       = require('fs');
const readline = require('readline');
const path     = require('path');
const crypto   = require('crypto');

// ── Config ──────────────────────────────────────────────────────────────────
// Override log file with: node d1_backfill.js --file=logs/cowrie_april11.json
const fileArg       = process.argv.find(a => a.startsWith('--file='))?.split('=')[1];
const LOG_FILE      = fileArg ? path.resolve(__dirname, fileArg) : path.join(__dirname, 'logs', 'cowrie_full.json');
// State file is per-log so resuming works correctly for each file
const stateBase     = fileArg ? path.basename(fileArg, '.json') : 'cowrie_full';
const STATE_FILE    = path.join(__dirname, `d1_backfill_state_${stateBase}.json`);
const INGEST_URL    = 'https://bathysphere-ingest.kasuskei.workers.dev/backfill';
const SHARED_SECRET = process.env.SHARED_SECRET;
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY;
const BATCH_SIZE    = 50;
const GEO_DELAY_MS  = 1100;
const ABUSE_DELAY_MS= 1100;
// Set MAX_LINES > 0 to cap how many log lines are read (for test runs).
// e.g. MAX_LINES=500 will read only the first 500 lines of the log.
const MAX_LINES     = parseInt(process.env.MAX_LINES ?? '0', 10);
// ────────────────────────────────────────────────────────────────────────────

const BLOCKLIST = ['192.168.', '127.', '10.', '172.16.', '::1'];
function isBlocked(ip) { return !ip || BLOCKLIST.some(p => ip.startsWith(p)); }

function anonymize(ip) {
  if (!ip) return null;
  if (ip.includes(':')) return ip.split(':')[0] + ':x:x:x:x:x:x:x';
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  return `${parts[0]}.${parts[1]}.x.x`;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); }
  catch { return { offset: 0, processed: 0, inserted: 0 }; }
}
function saveState(state) { fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2)); }

// ── Persistent cache files ──────────────────────────────────────────────────
const GEO_CACHE_FILE   = path.join(__dirname, 'd1_backfill_geo_cache.json');
const ABUSE_CACHE_FILE = path.join(__dirname, 'd1_backfill_abuse_cache.json');

function loadCache(file) {
  try { return new Map(Object.entries(JSON.parse(fs.readFileSync(file, 'utf8')))); }
  catch { return new Map(); }
}
function saveCache(file, map) {
  fs.writeFileSync(file, JSON.stringify(Object.fromEntries(map), null, 2));
}

// ── Geo lookup ──────────────────────────────────────────────────────────────
const geoCache = loadCache(GEO_CACHE_FILE);
let geoRequests = 0;

async function geoLookup(ip) {
  if (geoCache.has(ip)) return geoCache.get(ip);
  try {
    if (geoRequests > 0) await sleep(GEO_DELAY_MS);
    geoRequests++;
    const resp = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,city,as,isp,reverse,hosting`,
      { signal: AbortSignal.timeout(3000) }
    );
    if (!resp.ok) return null;
    const data = await resp.json();
    if (data.status !== 'success') { geoCache.set(ip, null); return null; }
    const geo = {
      country: data.country ?? null,
      city:    data.city    ?? null,
      asn:     data.as      ?? null,
      isp:     data.isp     ?? null,
      rdns:    data.reverse ?? null,
      cloud:   data.hosting ? 'hosting' : null,
    };
    geoCache.set(ip, geo);
    if (geoRequests % 50 === 0) saveCache(GEO_CACHE_FILE, geoCache);
    return geo;
  } catch { return null; }
}

// ── AbuseIPDB lookup ────────────────────────────────────────────────────────
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
    if (abuseRequests % 50 === 0) saveCache(ABUSE_CACHE_FILE, abuseCache);
    return result;
  } catch { return null; }
}

// ── IoC + ATT&CK (unchanged from original) ─────────────────────────────────
const IOC_SIGNATURES = [
  { match: e => /mdrfckr/.test(e.input ?? ''),                               ioc: { type: 'persistence',  label: 'mdrfckr SSH backdoor key',            severity: 'critical' } },
  { match: e => /redtail/i.test(e.filename ?? e.url ?? ''),                  ioc: { type: 'malware',      label: 'Redtail cryptominer',                  severity: 'critical' } },
  { match: e => /\.arm[0-9]|\.x86_64|\.i686|\.mips/.test(e.filename ?? ''), ioc: { type: 'malware',      label: 'Multi-arch malware dropper',            severity: 'critical' } },
  { match: e => /TelegramDesktop|tdata/.test(e.input ?? ''),                 ioc: { type: 'exfiltration', label: 'Telegram session theft attempt',        severity: 'high' } },
  { match: e => /chmod\s+\+x\s+\.\/\.[^\/]+\//.test(e.input ?? ''),         ioc: { type: 'malware',      label: 'Hidden directory dropper',              severity: 'high' } },
  { match: e => /authorized_keys/.test(e.input ?? ''),                       ioc: { type: 'persistence',  label: 'SSH key injection',                     severity: 'high' } },
  { match: e => /grep.*[Mm]iner/.test(e.input ?? ''),                        ioc: { type: 'recon',        label: 'Cryptominer recon',                     severity: 'medium' } },
  { match: e => /sol|solana/.test(e.username ?? ''),                         ioc: { type: 'credential',   label: 'Solana node targeting',                 severity: 'medium' } },
  { match: e => e.username === '345gs5662d34',                               ioc: { type: 'credential',   label: 'Mirai botnet credential',               severity: 'high' } },
  { match: e => e.eventid === 'cowrie.direct-tcpip.request',                 ioc: { type: 'c2',           label: 'TCP tunnel / proxy attempt',            severity: 'medium' } },
  { match: e => /ZGrab/i.test(e.version ?? ''),                              ioc: { type: 'scanner',      label: 'ZGrab internet scanner',                severity: 'low' } },
  { match: e => /clean\.sh/i.test(e.filename ?? ''),                         ioc: { type: 'malware',      label: 'Competing malware cleanup script',      severity: 'high' } },
];

const ATTACK_RULES = [
  { match: e => e.eventid === 'cowrie.session.connect',                                                        technique: { id: 'T1595.002', name: 'Vulnerability Scanning',                        tactic: 'Reconnaissance' } },
  { match: e => e.eventid === 'cowrie.client.version',                                                         technique: { id: 'T1595.001', name: 'Scanning IP Blocks',                            tactic: 'Reconnaissance' } },
  { match: e => e.eventid === 'cowrie.login.failed',                                                           technique: { id: 'T1110.001', name: 'Password Guessing',                             tactic: 'Credential Access' } },
  { match: e => e.eventid === 'cowrie.login.success',                                                          technique: { id: 'T1078',     name: 'Valid Accounts',                               tactic: 'Initial Access' } },
  { match: e => e.eventid === 'cowrie.command.input' && /uname|\/proc\/version/.test(e.input ?? ''),           technique: { id: 'T1082',     name: 'System Information Discovery',                 tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /\/proc\/cpuinfo|lscpu/.test(e.input ?? ''),           technique: { id: 'T1082',     name: 'System Information Discovery',                 tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /ifconfig|ip addr/.test(e.input ?? ''),               technique: { id: 'T1016',     name: 'System Network Configuration Discovery',       tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /\bps\b/.test(e.input ?? ''),                         technique: { id: 'T1057',     name: 'Process Discovery',                            tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /whoami|id\b|groups\b|w\b/.test(e.input ?? ''),       technique: { id: 'T1033',     name: 'System Owner/User Discovery',                  tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /crontab/.test(e.input ?? ''),                        technique: { id: 'T1053.003', name: 'Cron',                                         tactic: 'Discovery' } },
  { match: e => e.eventid === 'cowrie.command.input' && /authorized_keys/.test(e.input ?? ''),                technique: { id: 'T1098.004', name: 'SSH Authorized Keys',                          tactic: 'Persistence' } },
  { match: e => e.eventid === 'cowrie.command.input' && /chattr|lockr/.test(e.input ?? ''),                   technique: { id: 'T1222.002', name: 'Linux File/Directory Permissions Modification', tactic: 'Defense Evasion' } },
  { match: e => e.eventid === 'cowrie.command.input' && /nohup|systemctl/.test(e.input ?? ''),                technique: { id: 'T1543',     name: 'Create or Modify System Process',              tactic: 'Persistence' } },
  { match: e => e.eventid === 'cowrie.command.input' && /rm -rf|shred/.test(e.input ?? ''),                   technique: { id: 'T1070.004', name: 'File Deletion',                                tactic: 'Defense Evasion' } },
  { match: e => e.eventid === 'cowrie.command.input' && /pkill|kill -9/.test(e.input ?? ''),                  technique: { id: 'T1562.001', name: 'Disable or Modify Tools',                      tactic: 'Defense Evasion' } },
  { match: e => e.eventid === 'cowrie.command.input' && /chmod\s+\+x\s+\.\/\.[^\/]+\//.test(e.input ?? ''),  technique: { id: 'T1564.001', name: 'Hidden Files and Directories',                  tactic: 'Defense Evasion' } },
  { match: e => e.eventid === 'cowrie.command.input' && /TelegramDesktop|tdata/.test(e.input ?? ''),          technique: { id: 'T1005',     name: 'Data from Local System',                      tactic: 'Collection' } },
  { match: e => e.eventid === 'cowrie.direct-tcpip.request',                                                   technique: { id: 'T1572',     name: 'Protocol Tunneling',                           tactic: 'Command and Control' } },
  { match: e => e.eventid === 'cowrie.command.input' && /[Mm]iner|xmrig/.test(e.input ?? ''),                 technique: { id: 'T1496',     name: 'Resource Hijacking',                           tactic: 'Impact' } },
  { match: e => (e.eventid === 'cowrie.session.file_upload' || e.eventid === 'cowrie.session.file_download') && /redtail|miner/.test(e.filename ?? e.url ?? ''), technique: { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' } },
  { match: e => e.eventid === 'cowrie.command.input',                                                          technique: { id: 'T1059.004', name: 'Unix Shell',                                   tactic: 'Execution' } },
  { match: e => e.eventid === 'cowrie.session.file_upload' || e.eventid === 'cowrie.session.file_download',   technique: { id: 'T1570',     name: 'Lateral Tool Transfer',                       tactic: 'Lateral Movement' } },
];

function classifyAttack(e) {
  for (const r of ATTACK_RULES) { try { if (r.match(e)) return r.technique; } catch {} }
  return null;
}
function matchIocs(e, abuse) {
  const iocs = [];
  for (const s of IOC_SIGNATURES) { try { if (s.match(e)) iocs.push(s.ioc); } catch {} }
  if (abuse && abuse.score > 25)
    iocs.push({ type: 'reputation', label: `AbuseIPDB ${abuse.score}% confidence`, severity: abuse.score >= 75 ? 'critical' : abuse.score >= 50 ? 'high' : 'medium', reports: abuse.reports });
  return iocs.length ? iocs : null;
}

// ── Normalize — FIX: flatten geo into geo_* columns ─────────────────────────
function normalize(raw, geo, abuse) {
  if (isBlocked(raw.src_ip)) return null;
  const anon_ip = anonymize(raw.src_ip);
  if (!anon_ip) return null;

  const base = {
    id:          raw.uuid ? `${raw.uuid}-${raw.eventid}-${raw.timestamp}` : crypto.randomUUID(),
    ts:          raw.timestamp,           // Cowrie field is `timestamp`
    eventid:     raw.eventid,
    session:     raw.session    ?? null,
    src_ip:      anon_ip,
    protocol:    raw.protocol   ?? 'ssh',
    sensor:      raw.sensor     ?? 'honeypot-pi',
    // ✅ FIX: flat geo columns instead of nested object
    geo_country: geo?.country   ?? null,
    geo_city:    geo?.city      ?? null,
    geo_asn:     geo?.asn       ?? null,
    geo_isp:     geo?.isp       ?? null,
    geo_rdns:    geo?.rdns      ?? null,
    geo_cloud:   geo?.cloud     ?? null,
  };

  let event;
  switch (raw.eventid) {
    case 'cowrie.session.connect':
      event = { ...base, dst_port: raw.dst_port ?? null }; break;
    case 'cowrie.session.closed':
      event = { ...base, duration: raw.duration != null ? parseFloat(raw.duration) : null }; break;
    case 'cowrie.client.version':
      event = { ...base, version: raw.version ?? null }; break;
    case 'cowrie.login.success':
    case 'cowrie.login.failed':
      event = { ...base,
        username:      raw.username ?? null,
        password_hash: raw.password ? raw.password.slice(0,2)+'***'+raw.password.slice(-1) : null,
        password_len:  raw.password?.length ?? null,
      }; break;
    case 'cowrie.command.input':
    case 'cowrie.command.failed':
      event = { ...base, input: raw.input ?? null }; break;
    case 'cowrie.session.file_upload':
      event = { ...base, filename: raw.filename ?? null, shasum: raw.shasum ?? null }; break;
    case 'cowrie.session.file_download':
      event = { ...base, url: raw.url ?? null, shasum: raw.shasum ?? null }; break;
    default:
      event = { ...base };
  }

  const attack = classifyAttack(event);
  if (attack) {
    event.attack_id     = attack.id;
    event.attack_name   = attack.name;
    event.attack_tactic = attack.tactic;
  }

  const iocs = matchIocs(event, abuse);
  if (iocs) event.iocs = JSON.stringify(iocs);   // D1 stores as JSON text

  // Attach abuse score directly
  if (abuse) {
    event.abuse_score = abuse.score;
  }

  return event;
}

// ── POST batch ──────────────────────────────────────────────────────────────
async function postBatch(events) {
  const resp = await fetch(INGEST_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Bathysphere-Secret': SHARED_SECRET },
    body: JSON.stringify({ events }),
  });
  if (!resp.ok) throw new Error(`Ingest returned ${resp.status}: ${await resp.text()}`);
  return resp.json();
}

// ── Main ────────────────────────────────────────────────────────────────────
async function main() {
  if (!SHARED_SECRET) { console.error('Set $env:SHARED_SECRET before running.'); process.exit(1); }

  const state = loadState();
  console.log(`Resuming from line offset ${state.offset}. Previously processed: ${state.processed}, inserted: ${state.inserted}`);
  if (MAX_LINES > 0) console.log(`⚠️  TEST MODE: capped at ${MAX_LINES} lines`);

  // ── Pass 1: collect unique IPs ─────────────────────────────────────────
  // Skip the full scan if both caches are already warm.
  const geoWarm   = geoCache.size > 0;
  const abuseWarm = abuseCache.size > 0 || !ABUSEIPDB_KEY;

  let lineCount = 0;
  let uniqueIps = new Set();

  if (!geoWarm || !abuseWarm) {
    console.log('Pass 1: collecting unique IPs (caches cold)...');
    const rl = readline.createInterface({ input: fs.createReadStream(LOG_FILE), crlfDelay: Infinity });
    for await (const line of rl) {
      lineCount++;
      if (MAX_LINES > 0 && lineCount > MAX_LINES) break;
      try {
        const e = JSON.parse(line.trim());
        if (e.src_ip && !isBlocked(e.src_ip)) uniqueIps.add(e.src_ip);
      } catch {}
    }
    console.log(`Scanned ${lineCount} lines. Unique external IPs: ${uniqueIps.size}`);
  } else {
    console.log(`Caches warm (geo: ${geoCache.size}, abuse: ${abuseCache.size} IPs). Skipping Pass 1 scan.`);
    // Still need lineCount for progress display — do a fast count
    if (MAX_LINES === 0) {
      const rl = readline.createInterface({ input: fs.createReadStream(LOG_FILE), crlfDelay: Infinity });
      for await (const _ of rl) lineCount++;
    } else {
      lineCount = MAX_LINES;
    }
    // Populate uniqueIps from cache keys so we can fill any gaps
    uniqueIps = new Set([...geoCache.keys(), ...abuseCache.keys()]);
  }

  // ── Pass 1a: geo lookups (only uncached IPs) ───────────────────────────
  const ipsNeedingGeo = [...uniqueIps].filter(ip => !geoCache.has(ip));
  if (ipsNeedingGeo.length > 0) {
    console.log(`Pass 1a: geo lookups for ${ipsNeedingGeo.length} uncached IPs...`);
    let n = 0;
    for (const ip of ipsNeedingGeo) {
      await geoLookup(ip);
      if (++n % 50 === 0) console.log(`  Geo: ${n}/${ipsNeedingGeo.length}`);
    }
    saveCache(GEO_CACHE_FILE, geoCache);
    console.log(`Geo complete. Cache size: ${geoCache.size}`);
  } else {
    console.log(`Pass 1a: all IPs geo-cached (${geoCache.size}). Skipping.`);
  }

  // ── Pass 1b: AbuseIPDB lookups (only uncached IPs) ────────────────────
  if (ABUSEIPDB_KEY) {
    const ipsNeedingAbuse = [...uniqueIps].filter(ip => !abuseCache.has(ip));
    if (ipsNeedingAbuse.length > 0) {
      console.log(`Pass 1b: AbuseIPDB lookups for ${ipsNeedingAbuse.length} uncached IPs...`);
      let n = 0;
      for (const ip of ipsNeedingAbuse) {
        await abuseLookup(ip);
        if (++n % 50 === 0) console.log(`  Abuse: ${n}/${ipsNeedingAbuse.length}`);
      }
      saveCache(ABUSE_CACHE_FILE, abuseCache);
      console.log(`AbuseIPDB complete. Cache size: ${abuseCache.size}`);
    } else {
      console.log(`Pass 1b: all IPs abuse-cached (${abuseCache.size}). Skipping.`);
    }
  }

  // ── Pass 2: normalize and push ─────────────────────────────────────────
  console.log('Pass 2: normalizing and pushing events...');
  let currentLine = 0;
  let batch = [];
  let totalInserted = 0;

  const rl2 = readline.createInterface({ input: fs.createReadStream(LOG_FILE), crlfDelay: Infinity });

  for await (const line of rl2) {
    currentLine++;
    if (MAX_LINES > 0 && currentLine > MAX_LINES) break;
    if (currentLine <= state.offset) continue;

    try {
      const raw   = JSON.parse(line.trim());
      const geo   = raw.src_ip ? (geoCache.get(raw.src_ip) ?? null)   : null;
      const abuse = raw.src_ip ? (abuseCache.get(raw.src_ip) ?? null) : null;
      const event = normalize(raw, geo, abuse);
      if (event) batch.push(event);
    } catch {}

    if (batch.length >= BATCH_SIZE) {
      try {
        const result = await postBatch(batch);
        const stored = result.stored ?? batch.length;
        totalInserted += stored;
        state.offset   = currentLine;
        state.inserted = (state.inserted ?? 0) + stored;
        saveState(state);
        console.log(`  Line ${currentLine}/${lineCount} — batch stored: ${stored}/${batch.length} | total inserted: ${totalInserted}`);
        batch = [];
      } catch (err) {
        console.error(`Batch failed at line ${currentLine}: ${err.message}. Retrying in 5s...`);
        await sleep(5000);
      }
    }
  }

  // Push remaining
  if (batch.length > 0) {
    try {
      const result = await postBatch(batch);
      const stored = result.stored ?? batch.length;
      totalInserted += stored;
      console.log(`Final batch: stored ${stored}/${batch.length}`);
    } catch (err) {
      console.error(`Final batch failed: ${err.message}`);
    }
  }

  state.offset = MAX_LINES > 0 ? state.offset : lineCount;
  saveState(state);
  saveCache(GEO_CACHE_FILE, geoCache);
  saveCache(ABUSE_CACHE_FILE, abuseCache);
  console.log(`\nDone. Lines read: ${currentLine}. Events inserted this run: ${totalInserted}`);
  console.log(`Check D1: wrangler d1 execute bathysphere --remote --command="SELECT COUNT(*) FROM events"`);
}

main().catch(err => { console.error(err); process.exit(1); });
