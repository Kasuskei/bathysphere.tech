#!/usr/bin/env node
/**
 * Inserts a manually written signal post into bathysphere-blog D1.
 * 
 * Usage:
 *   $env:SHARED_SECRET="your_secret"
 *   node insert_signal_post.js
 */

const INGEST_URL = 'https://bathysphere-signal.kasuskei.workers.dev/post';
const SHARED_SECRET = process.env.SHARED_SECRET;

// We'll insert directly via the blog D1 using a fetch to a new /post endpoint
// on the signal Worker. But the simpler approach is to just use the Cloudflare
// REST API directly.

// Actually simplest: write to blog D1 via a small HTTP endpoint we add to the
// read Worker, OR just run wrangler d1 execute with a JS file.

// Instead, let's POST the post data to the signal Worker's manual endpoint
// with the full post payload, and have it write to D1.

const post = {
  "date": "2026-04-08",
  "sensor": "honeypot-pi",
  "tags": ["campaign"],
  "title": "13,365 sessions in 8 hours from a single IP",
  "lede": "Something from 220.190.x.x connected to the honeypot 13,365 times over 8 hours and 18 minutes, authenticated as root on nearly every attempt, ran a single command, and disconnected. Then it stopped and never came back. It wasn't attacking. It was checking.",
  "findings": {
    "source_ip": "220.190.x.x",
    "session_id": "13,365 sessions",
    "duration": "8h 18m",
    "events": "106,912 events · 2026-04-08 18:09 UTC to 2026-04-09 02:27 UTC"
  },
  "body": [
    {
      "type": "text",
      "content": "At <code>18:09 UTC</code> on <code>2026-04-08</code>, a host at <code>220.190.x.x</code> — a Chinese cloud/hosting block — began connecting to the honeypot at a rate of approximately 27 sessions per minute. It ran at that rate, essentially flat, for over 8 hours. By the time it stopped at <code>02:27 UTC</code> on <code>2026-04-09</code>, it had opened <strong>13,365 sessions</strong> and generated <strong>106,912 events</strong>. It has not been seen since."
    },
    {
      "type": "section",
      "title": "Session volume by hour"
    },
    {
      "type": "commands",
      "lines": [
        { "cmd": "2026-04-08 18:00  1,553 sessions", "comment": "" },
        { "cmd": "2026-04-08 19:00  1,759 sessions", "comment": "// peak hour" },
        { "cmd": "2026-04-08 20:00  1,744 sessions", "comment": "" },
        { "cmd": "2026-04-08 21:00  1,550 sessions", "comment": "" },
        { "cmd": "2026-04-08 22:00  1,435 sessions", "comment": "" },
        { "cmd": "2026-04-08 23:00  1,468 sessions", "comment": "" },
        { "cmd": "2026-04-09 00:00  1,453 sessions", "comment": "" },
        { "cmd": "2026-04-09 01:00  1,612 sessions", "comment": "" },
        { "cmd": "2026-04-09 02:00    798 sessions", "comment": "// partial hour — stopped at 02:27" }
      ]
    },
    {
      "type": "section",
      "title": "What it did"
    },
    {
      "type": "text",
      "content": "Every session followed the same pattern without exception. Connect, authenticate as <code>root</code>, run one command, disconnect. The command was identical across all 13,363 successful sessions: <code>echo -e \"\\x6F\\x6B\"</code> — a hex-encoded print of the string <code>ok</code>. Not <code>echo ok</code>. The hex encoding indicates the command was generated programmatically, not hardcoded as a string. Something built this command rather than wrote it."
    },
    {
      "type": "text",
      "content": "Authentication succeeded on 13,363 of 13,365 attempts — a 99.99% success rate explained entirely by Cowrie accepting all credentials. The actor cycled through 10 passwords in rotation, all under the <code>root</code> username, with hashes in the <code>19***0</code> through <code>19***9</code> pattern — consistent with a sequential numeric password list. No credential variation, no username variation, no deviation of any kind across the entire 8-hour window."
    },
    {
      "type": "section",
      "title": "What it wasn't"
    },
    {
      "type": "text",
      "content": "This is not a credential spray — an actor spraying passwords tries many credentials hoping some work, then executes a payload on success. This actor already had a working credential set and wasn't interested in what happened after login. It is not a scanner — scanners move across IP ranges looking for open ports. This IP hit only this host, repeatedly, for hours. It is not a typical bot — the 63-event Diicot sessions elsewhere in the dataset follow a structured playbook with persistence and hardware survey. This actor ran one command and left, every time."
    },
    {
      "type": "text",
      "content": "The most consistent explanation is infrastructure verification: something deployed on <code>220.190.x.x</code> believed this SSH endpoint was part of its own infrastructure and was confirming it was alive and responding. The flat session rate — a fixed ~27 connections per minute sustained without acceleration or decay — points to a thread pool or rate-limited worker running at a configured concurrency ceiling, not organic traffic. The complete stop at <code>02:27 UTC</code> with no return suggests a job that ran to completion or a configuration that was changed, not a network failure or block."
    },
    {
      "type": "attacks",
      "attacks": [
        { "id": "T1110", "name": "Brute Force", "tactic": "Credential Access" },
        { "id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery" },
        { "id": "T1497", "name": "Virtualization/Sandbox Evasion", "tactic": "Defense Evasion" }
      ]
    },
    {
      "type": "defender",
      "content": "A single IP generating thousands of short sessions in a flat rate pattern is a strong indicator of automated infrastructure tooling rather than a human actor. Rate-limit or block after 10 failed sessions from a single IP within a 60-second window — this actor would have been cut off in the first minute. The hex-encoded command <code>\\x6F\\x6B</code> is a fingerprint worth alerting on in shell logs; legitimate administrators don't encode <code>echo ok</code> in hex."
    }
  ],
  "session_ids": "220.190.x.x — 13365 sessions"
};

async function main() {
  if (!SHARED_SECRET) { console.error('Set $env:SHARED_SECRET'); process.exit(1); }

  const resp = await fetch('https://bathysphere-signal.kasuskei.workers.dev/insert', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bathysphere-Secret': SHARED_SECRET,
    },
    body: JSON.stringify({ post }),
  });

  const text = await resp.text();
  console.log(`Status: ${resp.status}`);
  console.log(text);
}

main().catch(err => { console.error(err); process.exit(1); });
