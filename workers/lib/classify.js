// MITRE ATT&CK mapping — rules evaluated in order, first match wins.
export const ATTACK_RULES = [
  // Reconnaissance
  {
    match: e => e.eventid === 'cowrie.session.connect',
    technique: { id: 'T1595.002', name: 'Vulnerability Scanning', tactic: 'Reconnaissance' },
  },
  {
    match: e => e.eventid === 'cowrie.client.version',
    technique: { id: 'T1595.001', name: 'Scanning IP Blocks', tactic: 'Reconnaissance' },
  },

  // Credential Access
  {
    // Must precede the generic login.failed rule below.
    // NOTE: password_hash is already redacted ("xx***x") by normalize() before classification runs,
    // so this comparison will almost never match. Real stuffing detection needs the raw password,
    // which is only available before normalization. Left as a best-effort signal.
    match: e => e.eventid === 'cowrie.login.failed' && e.username === e.password_hash?.slice(0, 2),
    technique: { id: 'T1110.004', name: 'Credential Stuffing', tactic: 'Credential Access' },
  },
  {
    match: e => e.eventid === 'cowrie.login.failed',
    technique: { id: 'T1110.001', name: 'Password Guessing', tactic: 'Credential Access' },
  },
  {
    match: e => e.eventid === 'cowrie.login.success',
    technique: { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access' },
  },

  // Discovery
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /uname|\/proc\/version|\/etc\/os-release/.test(e.input),
    technique: { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /\/proc\/cpuinfo|lscpu|nproc/.test(e.input),
    technique: { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /ifconfig|ip addr|ip link|netstat|ss -/.test(e.input),
    technique: { id: 'T1016', name: 'System Network Configuration Discovery', tactic: 'Discovery' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /\bps\b|\/proc\/[0-9]/.test(e.input),
    technique: { id: 'T1057', name: 'Process Discovery', tactic: 'Discovery' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /whoami|id\b|groups\b|w\b|who\b/.test(e.input),
    technique: { id: 'T1033', name: 'System Owner/User Discovery', tactic: 'Discovery' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /crontab|\/etc\/cron/.test(e.input),
    technique: { id: 'T1053.003', name: 'Cron', tactic: 'Discovery' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /df\b|lsblk|fdisk|mount\b/.test(e.input),
    technique: { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /free\b|\/proc\/meminfo/.test(e.input),
    technique: { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery' },
  },

  // Persistence
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /authorized_keys/.test(e.input),
    technique: { id: 'T1098.004', name: 'SSH Authorized Keys', tactic: 'Persistence' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /nohup|systemctl|service\b/.test(e.input),
    technique: { id: 'T1543', name: 'Create or Modify System Process', tactic: 'Persistence' },
  },

  // Defense Evasion
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /chattr|lockr/.test(e.input),
    technique: { id: 'T1222.002', name: 'Linux File/Directory Permissions Modification', tactic: 'Defense Evasion' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /rm -rf|shred|unlink/.test(e.input),
    technique: { id: 'T1070.004', name: 'File Deletion', tactic: 'Defense Evasion' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /pkill|kill -9/.test(e.input),
    technique: { id: 'T1562.001', name: 'Disable or Modify Tools', tactic: 'Defense Evasion' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /chmod\s+\+x\s+\.\/\.[^\/]+\//.test(e.input),
    technique: { id: 'T1564.001', name: 'Hidden Files and Directories', tactic: 'Defense Evasion' },
  },

  // Collection
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /TelegramDesktop|tdata|ttyGSM|ttyUSB|smsd|qmuxd|modem/.test(e.input),
    technique: { id: 'T1005', name: 'Data from Local System', tactic: 'Collection' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /locate\s+[A-F0-9]{8,}/.test(e.input),
    technique: { id: 'T1005', name: 'Data from Local System', tactic: 'Collection' },
  },

  // Command and Control
  {
    match: e => e.eventid === 'cowrie.direct-tcpip.request',
    technique: { id: 'T1572', name: 'Protocol Tunneling', tactic: 'Command and Control' },
  },

  // Impact
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /[Mm]iner|xmrig|xmr|monero|stratum\+/.test(e.input),
    technique: { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' },
  },
  {
    match: e => (e.eventid === 'cowrie.session.file_upload' || e.eventid === 'cowrie.session.file_download') &&
      /redtail|miner|xmrig/.test(e.filename ?? e.url ?? ''),
    technique: { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' },
  },

  // Execution — catch-all for command events not matched above
  {
    match: e => e.eventid === 'cowrie.command.input',
    technique: { id: 'T1059.004', name: 'Unix Shell', tactic: 'Execution' },
  },

  // Lateral Movement
  {
    match: e => e.eventid === 'cowrie.session.file_upload' || e.eventid === 'cowrie.session.file_download',
    technique: { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'Lateral Movement' },
  },
];

export function classifyAttack(event) {
  for (const rule of ATTACK_RULES) {
    try { if (rule.match(event)) return rule.technique; } catch {}
  }
  return null;
}

export const IOC_SIGNATURES = [
  {
    match: e => (e.eventid === 'cowrie.login.failed' || e.eventid === 'cowrie.login.success') &&
      e.username === '345gs5662d34',
    ioc: { type: 'credential', label: 'Mirai botnet credential', severity: 'high' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' && /mdrfckr/.test(e.input ?? ''),
    ioc: { type: 'persistence', label: 'mdrfckr SSH backdoor key', severity: 'critical' },
  },
  {
    match: e => (e.eventid === 'cowrie.session.file_upload' || e.eventid === 'cowrie.session.file_download') &&
      /redtail/i.test(e.filename ?? e.url ?? ''),
    ioc: { type: 'malware', label: 'Redtail cryptominer', severity: 'critical' },
  },
  {
    match: e => e.eventid === 'cowrie.session.file_upload' &&
      /\.arm[0-9]|\.x86_64|\.i686|\.mips/.test(e.filename ?? ''),
    ioc: { type: 'malware', label: 'Multi-arch malware dropper', severity: 'critical' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /TelegramDesktop|tdata/.test(e.input ?? ''),
    ioc: { type: 'exfiltration', label: 'Telegram session theft attempt', severity: 'high' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' &&
      /chmod\s+\+x\s+\.\/\.[^\/]+\//.test(e.input ?? ''),
    ioc: { type: 'malware', label: 'Hidden directory dropper', severity: 'high' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' && /authorized_keys/.test(e.input ?? ''),
    ioc: { type: 'persistence', label: 'SSH key injection', severity: 'high' },
  },
  {
    match: e => e.eventid === 'cowrie.command.input' && /grep.*[Mm]iner/.test(e.input ?? ''),
    ioc: { type: 'recon', label: 'Cryptominer recon', severity: 'medium' },
  },
  {
    match: e => (e.eventid === 'cowrie.login.failed' || e.eventid === 'cowrie.login.success') &&
      /sol|solana/.test(e.username ?? ''),
    ioc: { type: 'credential', label: 'Solana node targeting', severity: 'medium' },
  },
  {
    match: e => e.eventid === 'cowrie.direct-tcpip.request',
    ioc: { type: 'c2', label: 'TCP tunnel / proxy attempt', severity: 'medium' },
  },
  {
    match: e => e.eventid === 'cowrie.client.version' && /ZGrab/i.test(e.version ?? ''),
    ioc: { type: 'scanner', label: 'ZGrab internet scanner', severity: 'low' },
  },
  {
    match: e => e.eventid === 'cowrie.session.file_upload' && /clean\.sh/i.test(e.filename ?? ''),
    ioc: { type: 'malware', label: 'Competing malware cleanup script', severity: 'high' },
  },
];

// Returns all matched IoC objects. Appends an AbuseIPDB reputation entry if score > 25.
export function matchIocs(event, abuse = null) {
  const matched = [];
  for (const sig of IOC_SIGNATURES) {
    try { if (sig.match(event)) matched.push(sig.ioc); } catch {}
  }
  if (abuse?.score > 25) {
    matched.push({
      type:     'reputation',
      label:    `AbuseIPDB ${abuse.score}% confidence`,
      severity: abuse.score >= 75 ? 'critical' : abuse.score >= 50 ? 'high' : 'medium',
      reports:  abuse.reports,
    });
  }
  return matched;
}
