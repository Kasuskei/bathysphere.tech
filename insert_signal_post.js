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

const post = {
  date: '2026-04-27',
  sensor: 'honeypot-pi',
  tags: ['mirai', 'post-quantum', 'campaign'],
  title: 'Post-quantum cryptography in commodity malware: Mirai variant observed running ML-KEM',
  lede: 'A HASSH clustering pass against honeypot telemetry surfaced a Mirai variant running post-quantum key exchange algorithms across 312 coordinated nodes. ML-KEM was standardized by NIST in August 2024. It is already in the wild.',
  findings: {
    source_ip: 'distributed — 312 unique IPs',
    session_id: '7,423 sessions',
    duration: 'ongoing',
    events: '39,129 events · first seen 2026-04-21 · active as of 2026-04-27'
  },
  body: [
    {
      type: 'text',
      content: 'The find came out of HASSH clustering against a dedicated PostgreSQL research database built on top of Cowrie SSH honeypot telemetry. Querying for post-quantum key exchange algorithms in the kexalgs field returned 392 IPs. Grouping those by HASSH fingerprint revealed that 312 shared an identical fingerprint — <code>af8223ac9914f509afdadfaf5f7ee94e</code> — pointing to a single tool and a single coordinated campaign. First observed <code>2026-04-21 02:35 UTC</code>. Still active.'
    },
    {
      type: 'section',
      title: 'The tooling'
    },
    {
      type: 'text',
      content: 'The client string <code>SSH-2.0-libssh_0.12.0</code> identifies a custom scanner built on the libssh library rather than standard OpenSSH. libssh 0.12.0 introduced ML-KEM support, and whoever built this tool compiled against it. The key exchange suite advertised is current:'
    },
    {
      type: 'commands',
      lines: [
        { cmd: 'mlkem768x25519-sha256', comment: '// ML-KEM · NIST standard · August 2024' },
        { cmd: 'mlkem768nistp256-sha256', comment: '' },
        { cmd: 'sntrup761x25519-sha512', comment: '// Streamlined NTRU Prime hybrid' },
        { cmd: 'sntrup761x25519-sha512@openssh.com', comment: '' },
        { cmd: 'curve25519-sha256', comment: '' },
        { cmd: 'kex-strict-c-v00@openssh.com', comment: '// Terrapin mitigation · OpenSSH 9.6' },
      ]
    },
    {
      type: 'text',
      content: 'The presence of <code>kex-strict-c-v00@openssh.com</code> across all sessions confirms the tooling is patched against the Terrapin attack disclosed in December 2023. This is not abandoned or stale infrastructure. The operator is maintaining it.'
    },
    {
      type: 'section',
      title: 'The credentials'
    },
    {
      type: 'text',
      content: 'Despite the modern cryptography stack, the credential list is pure Mirai. <code>345gs5662d34</code> — a default credential hardcoded into Mirai\'s original source code — leads the auth attempts at 1,626 hits, followed by <code>3245gs5662d34</code> at 1,616. The full list mixes Mirai defaults with credentials associated with known Mirai variants including Moobot. Average session duration is 3.47 seconds. Post-auth activity confirms this is a deployment campaign, not reconnaissance.'
    },
    {
      type: 'section',
      title: 'Infrastructure'
    },
    {
      type: 'text',
      content: '312 nodes across 20+ countries. Indonesia is the heaviest source at 856 sessions across both consumer and cloud ISPs — PT Telekomunikasi Indonesia, PT Cloud Hosting Indonesia, Cloud Host Pte Ltd, and Byteplus. The remaining distribution spans Hong Kong, the United States, South Korea, Vietnam, Brazil, India, France, Germany, and Mexico. Cloud providers represented include UCLOUD, Tencent, OVH, Contabo, and Microsoft Azure. The geographic and provider spread is consistent with a takedown-resistant architecture.'
    },
    {
      type: 'section',
      title: 'Why this matters'
    },
    {
      type: 'text',
      content: 'ML-KEM was standardized by NIST in August 2024. It shipped in libssh 0.12.0 shortly after. The timeline from standardization to deployment in mass-scanning commodity malware is measured in months. Post-quantum cryptography appearing not in targeted nation-state tooling but in a Mirai variant — one of the most widely distributed botnet families on the internet — suggests the adoption curve is steeper than most would have anticipated. The credential list hasn\'t changed. The infrastructure is being maintained. The crypto stack is being updated.'
    },
    {
      type: 'attacks',
      attacks: [
        { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access' },
        { id: 'T1071.002', name: 'Application Layer Protocol: SSH', tactic: 'Command and Control' },
        { id: 'T1584', name: 'Compromise Infrastructure', tactic: 'Resource Development' },
      ]
    },
    {
      type: 'defender',
      content: 'HASSH <code>af8223ac9914f509afdadfaf5f7ee94e</code> is a reliable fingerprint for this campaign. The credential pair <code>345gs5662d34:345gs5662d34</code> is a stable Mirai IOC and should be present in existing detection rules. The presence of <code>mlkem</code> in SSH kexalgs is not inherently malicious — modern OpenSSH clients advertise it by default — but combined with <code>libssh_0.12.0</code> and the Mirai credential list it is a high-confidence cluster signal.'
    }
  ],
  session_ids: 'distributed — 312 unique IPs · HASSH af8223ac9914f509afdadfaf5f7ee94e'
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
