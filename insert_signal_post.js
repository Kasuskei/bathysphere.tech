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
  date: '2026-04-13',
  sensor: 'honeypot-pi',
  tags: ['campaign', 'lateral'],
  title: 'Container-aware Monero miner with privilege escalation deployed as sshd',
  lede: 'A session from 115.190.x.x authenticated as root/ubuntu, sat idle for five minutes, then uploaded a binary named sshd via SFTP. VirusTotal classifies the payload as an XMRig-based Monero miner with container escape capability — it manipulates Linux user namespaces via /proc/self/ to escape restricted environments before mining with full host privileges. First submitted in December 2022 and undetected by major EDRs, the binary continues to circulate unchanged.',
  findings: {
    source_ip: '115.190.x.x',
    session_id: '499a9c54',
    duration: '5m 3s',
    events: 'Auth as root/ubuntu + 5min staging + SFTP upload of sshd'
  },
  body: [
    {
      type: 'text',
      content: 'The session authenticated as <strong>root</strong> using credential <code>ubuntu/ubuntu</code> at 22:40 UTC. No commands were executed after login. The session remained open for five minutes and two seconds before the actor transferred a single file named <code>sshd</code> via SFTP — a deliberate masquerade of the legitimate SSH daemon process name. The actor disconnected immediately after the upload completed. The absence of any shell commands suggests a fully automated deployment script with a fixed staging delay, or manual operation with payload preparation occurring outside the session.'
    },
    {
      type: 'section',
      title: 'Attack sequence'
    },
    {
      type: 'commands',
      lines: [
        { cmd: '[login: root / ubuntu]', comment: 'Authentication at 22:40 UTC' },
        { cmd: '[idle: 5 minutes 2 seconds]', comment: 'No commands executed — staging delay or manual preparation' },
        { cmd: '[SFTP upload: sshd]', comment: 'SHA256: 9ecbeee2c88e701fe3d39e868c0a102cc77c033775f8fa9625ae83e9150a2a50' }
      ]
    },
    {
      type: 'text',
      content: 'VirusTotal classifies the binary under the <strong>MALXMR family</strong> — TrendMicro designation for XMRig-based Monero miners that use evasion and privilege escalation to maximize mining yield. The binary uses <code>rdtsc</code> and <code>rdtscp</code> CPU timing instructions to detect sandbox analysis environments. Its most significant capability is Linux user namespace manipulation: reads and writes to <code>/proc/self/uid_map</code>, <code>/proc/self/gid_map</code>, and <code>/proc/self/setgroups</code> in function <code>sub_4944c0</code> allow it to remap its own UID/GID — escaping containerized environments and acquiring elevated host privileges before launching mining operations. This dual capability explains the masquerade name: a miner running as <code>sshd</code> with root-equivalent privileges, escaped from any container boundary, is both harder to kill and harder to attribute. First submitted to VirusTotal in December 2022 and last seen April 2026, the binary has not changed in over three years. Despite this, CrowdStrike Falcon, ESET, and Malwarebytes currently return no detection.'
    },
    {
      type: 'attacks',
      attacks: [
        { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access' },
        { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'Lateral Movement' },
        { id: 'T1611', name: 'Escape to Host', tactic: 'Privilege Escalation' },
        { id: 'T1036.005', name: 'Match Legitimate Name or Location', tactic: 'Defense Evasion' },
        { id: 'T1497.003', name: 'Time Based Evasion', tactic: 'Defense Evasion' },
        { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' }
      ]
    },
    {
      type: 'defender',
      content: 'Alert on any process named <code>sshd</code> running from a non-standard path such as <code>/tmp</code> — the legitimate sshd binary runs from <code>/usr/sbin/sshd</code>. Add an auditd rule to detect writes to <code>/proc/self/uid_map</code>: <code>-w /proc/self/uid_map -p wa -k ns_escape</code>. Rotate or disable default credentials — <code>ubuntu/ubuntu</code> authenticated successfully here. The SHA256 hash <code>9ecbeee2...</code> is a stable indicator given the binary has not changed since 2022.'
    }
  ],
  session_ids: '499a9c54ef72'
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
