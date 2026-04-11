/**
 * geo_backfill.js
 * One-time script to backfill geo data for existing KV events.
 *
 * Run from your PC:
 *   node geo_backfill.js
 *
 * Reads all events from the read Worker, looks up missing geo data
 * via ip-api.com batch endpoint (100 IPs per request, free tier),
 * then POSTs enriched events back via a special backfill endpoint
 * on the ingest Worker.
 *
 * ip-api.com batch endpoint: http://ip-api.com/batch
 * - Free tier: 100 IPs per request, 15 requests per minute
 * - No API key needed
 *
 * NOTE: This script uses the real IPs stored in KV events.
 * Wait — our KV events only store anonymized IPs (165.154.x.x).
 * We can't reverse those to look up geo. Instead this script
 * re-reads the original Cowrie log file on the Pi and builds
 * a raw_ip -> anon_ip -> geo mapping, then patches KV events
 * that are missing geo data.
 *
 * USAGE:
 *   1. Copy cowrie.json from the Pi to your PC
 *   2. Set the variables below
 *   3. node geo_backfill.js
 */

const fs = require('fs');
const readline = require('readline');

// ── Config ────────────────────────────────────────────────────────────────────
const COWRIE_LOG    = './cowrie.json';
const READ_URL      = 'https://bathysphere-read.kasuskei.workers.dev';
const BACKFILL_URL  = 'https://bathysphere-ingest.kasuskei.workers.dev/backfill';
const SHARED_SECRET = process.env.SHARED_SECRET;
const BATCH_SIZE    = 100;  // ip-api.com free tier max
const RATE_LIMIT_MS = 4100; // 15 req/min = 1 per 4s, add buffer
// ─────────────────────────────────────────────────────────────────────────────

function anonymize(ip) {
  if (!ip) return null;
  if (ip.includes(':')) {
    return ip.split(':')[0] + ':x:x:x:x:x:x:x';
  }
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  return `${parts[0]}.${parts[1]}.x.x`;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function geoLookupBatch(ips) {
  const resp = await fetch('http://ip-api.com/batch?fields=status,query,country,city', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(ips.map(ip => ({ query: ip }))),
  });
  if (!resp.ok) throw new Error(`ip-api batch failed: ${resp.status}`);
  const data = await resp.json();
  const map = new Map();
  data.forEach(r => {
    if (r.status === 'success') {
      map.set(r.query, { country: r.country, city: r.city });
    }
  });
  return map;
}

async function main() {
  if (!SHARED_SECRET) {
    console.error('Set SHARED_SECRET env var before running.');
    process.exit(1);
  }

  console.log('Reading Cowrie log to build raw IP → anon IP map...');

  // Build map of anon_ip -> raw_ip from the log file
  // (we need raw IPs for the geo lookup)
  const anonToRaw = new Map();
  const rl = readline.createInterface({
    input: fs.createReadStream(COWRIE_LOG),
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    try {
      const e = JSON.parse(line.trim());
      if (e.src_ip && !e.src_ip.startsWith('192.168.')) {
        const anon = anonymize(e.src_ip);
        if (anon && !anonToRaw.has(anon)) {
          anonToRaw.set(anon, e.src_ip);
        }
      }
    } catch { /* skip malformed lines */ }
  }

  console.log(`Found ${anonToRaw.size} unique anonymized IPs in log.`);

  // Fetch all current KV events
  console.log('Fetching current events from KV...');
  const resp = await fetch(`${READ_URL}/events?limit=10000`);
  const { events } = await resp.json();
  console.log(`Fetched ${events.length} events.`);

  // Find events missing geo
  const missing = events.filter(e => !e.geo && e.src_ip && anonToRaw.has(e.src_ip));
  console.log(`${missing.length} events missing geo data.`);

  if (missing.length === 0) {
    console.log('Nothing to backfill.');
    return;
  }

  // Get unique raw IPs that need lookup
  const rawIpsNeeded = [...new Set(missing.map(e => anonToRaw.get(e.src_ip)))];
  console.log(`Looking up ${rawIpsNeeded.length} unique IPs...`);

  // Batch geo lookup with rate limiting
  const geoMap = new Map();
  for (let i = 0; i < rawIpsNeeded.length; i += BATCH_SIZE) {
    const batch = rawIpsNeeded.slice(i, i + BATCH_SIZE);
    console.log(`  Batch ${Math.floor(i/BATCH_SIZE)+1}/${Math.ceil(rawIpsNeeded.length/BATCH_SIZE)}...`);
    const results = await geoLookupBatch(batch);
    results.forEach((geo, ip) => geoMap.set(ip, geo));
    if (i + BATCH_SIZE < rawIpsNeeded.length) await sleep(RATE_LIMIT_MS);
  }

  console.log(`Got geo for ${geoMap.size} IPs.`);

  // Patch events with geo data — rebuild anon_ip -> geo map
  const anonGeoMap = new Map();
  anonToRaw.forEach((rawIp, anonIp) => {
    const geo = geoMap.get(rawIp);
    if (geo) anonGeoMap.set(anonIp, geo);
  });

  // Patch all events (not just missing ones — update entire set)
  const patched = events.map(e => {
    if (!e.geo && anonGeoMap.has(e.src_ip)) {
      return { ...e, geo: anonGeoMap.get(e.src_ip) };
    }
    return e;
  });

  const patchedCount = patched.filter((e, i) => e !== events[i]).length;
  console.log(`Patched ${patchedCount} events. Pushing back to KV...`);

  // Push entire patched set to /backfill in one call
  console.log(`Pushing ${patched.length} events to /backfill...`);
  const pushResp = await fetch(BACKFILL_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bathysphere-Secret': SHARED_SECRET,
    },
    body: JSON.stringify({ events: patched }),
  });

  if (!pushResp.ok) {
    console.error(`Backfill push failed: ${pushResp.status} ${await pushResp.text()}`);
    return;
  }

  const result = await pushResp.json();
  console.log(`Backfill complete. ${result.stored} events written to KV.`);
}

main().catch(console.error);
