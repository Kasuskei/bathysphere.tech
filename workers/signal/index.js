/**
 * bathysphere — signal generator Worker
 *
 * Runs on a cron schedule. Queries the events D1 database for notable
 * sessions from the past 7 days, selects the most interesting one,
 * calls the Claude API to generate a clinical research note, and writes
 * the result to the blog D1 database.
 *
 * Cron: every Monday at 09:00 UTC ("0 9 * * 1")
 *
 * Bindings required (wrangler.toml):
 *   [[d1_databases]] binding = "DB"        — events database
 *   [[d1_databases]] binding = "BLOG"      — blog database
 *   [vars] ANTHROPIC_API_KEY               — set via wrangler secret put
 */

// ── Qualification thresholds ──────────────────────────────────────────────────
// A session must meet at least one of these to be considered notable
const MIN_COMMANDS        = 3;    // at least 3 commands executed
const MIN_IOC_SEVERITY    = 2;    // 1=low, 2=medium, 3=high, 4=critical
const REQUIRE_POST_RECON  = true; // must have gone beyond Recon/Credential Access

// Tactics that indicate meaningful post-access behavior
const INTERESTING_TACTICS = new Set([
  'Execution', 'Persistence', 'Defense Evasion', 'Discovery',
  'Collection', 'Command and Control', 'Lateral Movement', 'Impact',
]);

const IOC_SEV = { low: 1, medium: 2, high: 3, critical: 4 };

// ── Score a session — higher = more interesting ───────────────────────────────
function scoreSession(session) {
  let score = 0;
  const tactics = new Set();

  for (const e of session.events) {
    if (e.attack_tactic) tactics.add(e.attack_tactic);
    if (e.eventid === 'cowrie.command.input') score += 1;
    if (e.eventid === 'cowrie.session.file_upload' || e.eventid === 'cowrie.session.file_download') score += 5;
    if (e.eventid === 'cowrie.login.success') score += 3;
    if (e.eventid === 'cowrie.direct-tcpip.request') score += 4;

    // IoC scoring
    if (e.iocs) {
      try {
        const iocs = typeof e.iocs === 'string' ? JSON.parse(e.iocs) : e.iocs;
        for (const ioc of iocs) {
          score += (IOC_SEV[ioc.severity] ?? 1) * 3;
        }
      } catch {}
    }
  }

  // Bonus for interesting tactics
  for (const t of tactics) {
    if (INTERESTING_TACTICS.has(t)) score += 4;
  }

  // Bonus for tactic diversity
  score += tactics.size * 2;

  return { score, tactics };
}

// ── Fetch and group sessions from the past 7 days ─────────────────────────────
async function fetchNotableSessions(db) {
  const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

  const result = await db.prepare(`
    SELECT id, ts, eventid, session, src_ip, protocol, sensor,
           geo_country, geo_city, geo_asn, geo_isp,
           username, password_hash, password_len,
           input, filename, url, shasum,
           attack_id, attack_name, attack_tactic,
           iocs, abuse_score
    FROM events
    WHERE ts > ?
    ORDER BY ts ASC
  `).bind(since).all();

  const rows = result.results ?? [];

  // Group by session
  const sessionMap = new Map();
  for (const row of rows) {
    const key = row.session ?? row.id;
    if (!sessionMap.has(key)) {
      sessionMap.set(key, {
        session_id: key,
        src_ip: row.src_ip,
        geo_country: row.geo_country,
        geo_city: row.geo_city,
        geo_asn: row.geo_asn,
        geo_isp: row.geo_isp,
        sensor: row.sensor,
        protocol: row.protocol,
        events: [],
      });
    }
    sessionMap.get(key).events.push(row);
  }

  // Score and filter
  const candidates = [];
  for (const [, session] of sessionMap) {
    const { score, tactics } = scoreSession(session);
    const commandCount = session.events.filter(e => e.eventid === 'cowrie.command.input').length;
    const hasInterestingTactic = [...tactics].some(t => INTERESTING_TACTICS.has(t));

    if (commandCount >= MIN_COMMANDS && hasInterestingTactic) {
      candidates.push({ ...session, score, tactics: [...tactics] });
    }
  }

  // Sort by score descending, return top 5 for Claude to pick from
  return candidates.sort((a, b) => b.score - a.score).slice(0, 5);
}

// ── Check if we already wrote a post for this session ─────────────────────────
async function sessionAlreadyWritten(blog, sessionId) {
  const result = await blog.prepare(
    `SELECT id FROM posts WHERE session_ids LIKE ?`
  ).bind(`%${sessionId}%`).first();
  return !!result;
}

// ── Call Claude API ───────────────────────────────────────────────────────────
async function generatePost(sessions, apiKey) {
  // Build a concise summary of each candidate session for Claude
  const sessionSummaries = sessions.map((s, i) => {
    const commands = s.events
      .filter(e => e.eventid === 'cowrie.command.input' && e.input)
      .map(e => e.input);
    const iocs = s.events.flatMap(e => {
      try { return e.iocs ? (typeof e.iocs === 'string' ? JSON.parse(e.iocs) : e.iocs) : []; }
      catch { return []; }
    });
    const uploads = s.events.filter(e => e.eventid === 'cowrie.session.file_upload').map(e => e.filename);
    const downloads = s.events.filter(e => e.eventid === 'cowrie.session.file_download').map(e => e.url);
    const authEvents = s.events.filter(e => e.eventid === 'cowrie.login.failed' || e.eventid === 'cowrie.login.success');
    const duration = (() => {
      const times = s.events.map(e => new Date(e.ts).getTime()).filter(Boolean);
      if (times.length < 2) return null;
      return Math.round((Math.max(...times) - Math.min(...times)) / 1000);
    })();

    return {
      index: i + 1,
      session_id: s.session_id,
      src_ip: s.src_ip,
      location: [s.geo_city, s.geo_country].filter(Boolean).join(', ') || null,
      asn: s.geo_asn ?? null,
      isp: s.geo_isp ?? null,
      sensor: s.sensor,
      score: s.score,
      tactics: s.tactics,
      duration_seconds: duration,
      event_count: s.events.length,
      command_count: commands.length,
      commands: commands.slice(0, 20),
      credentials_tried: authEvents.slice(0, 6).map(e => ({ user: e.username, pass: e.password_hash })),
      uploads,
      downloads,
      iocs: [...new Map(iocs.map(i => [i.label, i])).values()].slice(0, 8),
    };
  });

  const prompt = `You are a threat intelligence analyst writing for bathysphere.tech, a personal honeypot research journal.

You will receive ${sessionSummaries.length} candidate sessions from the past 7 days. Select the single most analytically interesting one and write a research note about it.

SELECTION CRITERIA (in order of priority):
1. Novel or unusual behavior — something a researcher would genuinely find interesting
2. Specific malware, tooling, or campaign indicators
3. Multi-stage attack chains that show intent beyond automated scanning
4. Targeting of specific infrastructure (crypto, cloud, IoT)
5. Avoid: pure credential sprays with no follow-on, generic uname/whoami recon with nothing distinctive

SESSIONS:
${JSON.stringify(sessionSummaries, null, 2)}

OUTPUT FORMAT — respond with a single JSON object exactly matching this structure:
{
  "selected_session_id": "the session_id you chose",
  "date": "YYYY-MM-DD",
  "sensor": "honeypot-pi",
  "tags": ["one or more of: campaign, commands, credentials, iot, lateral"],
  "title": "A short, specific, factual title — no hype, no metaphor. Describe what actually happened.",
  "lede": "2-3 sentences. Clinical tone. What happened, what made it notable. No filler phrases like 'in an interesting finding' or 'this session demonstrates'. Just state the facts.",
  "findings": {
    "source_ip": "anonymized IP from the session",
    "session_id": "first 8 chars of session id",
    "duration": "Xs or 'N sessions'",
    "events": "brief description e.g. '14 commands' or 'credential sweep + 3 uploads'"
  },
  "body": [
    {
      "type": "text",
      "content": "Opening paragraph. 2-4 sentences. State what happened and the most significant indicator. Use <strong>tags</strong> for key terms. Use <code>tags</code> for commands, filenames, hashes."
    },
    {
      "type": "section",
      "title": "section name e.g. 'Command sequence' or 'Credential sequence'"
    },
    {
      "type": "commands",
      "lines": [
        { "cmd": "the exact command", "comment": "brief analyst comment or empty string" }
      ]
    },
    {
      "type": "text",
      "content": "Follow-up analysis. What does the behavior indicate? What is the actor's likely objective? Be specific — cite the commands or IoCs that support your conclusion."
    },
    {
      "type": "attacks",
      "attacks": [
        { "id": "T1234", "name": "Technique name", "tactic": "Tactic name" }
      ]
    },
    {
      "type": "defender",
      "content": "One specific, actionable detection or mitigation recommendation. Be concrete — name the indicator, the log source, or the rule. Avoid generic advice."
    }
  ]
}

TONE REQUIREMENTS:
- Clinical and precise. No editorializing, no dramatic language.
- Third person. "The session authenticated with..." not "I observed..."
- Short sentences. State facts. Let the commands speak.
- The defender takeaway must be specific and actionable, not generic security advice.
- If nothing in the candidate sessions is genuinely notable, return null instead of the JSON object.

Respond with only the JSON object or null. No preamble, no explanation.`;

  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 2000,
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!resp.ok) {
    throw new Error(`Claude API error ${resp.status}: ${await resp.text()}`);
  }

  const data = await resp.json();
  const text = data.content?.[0]?.text?.trim();
  if (!text || text === 'null') return null;

  // Strip any accidental markdown fences
  const clean = text.replace(/^```json\s*/i, '').replace(/\s*```$/, '').trim();
  return JSON.parse(clean);
}

// ── Write post to blog D1 ─────────────────────────────────────────────────────
async function writePost(blog, post, sessionId) {
  const id = `sig-${Date.now()}-${Math.random().toString(36).slice(2,7)}`;
  await blog.prepare(`
    INSERT INTO posts (id, created_at, date, sensor, tags, title, lede, findings, body, session_ids)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    new Date().toISOString(),
    post.date,
    post.sensor,
    JSON.stringify(post.tags),
    post.title,
    post.lede,
    JSON.stringify(post.findings),
    JSON.stringify(post.body),
    sessionId,
  ).run();
  return id;
}

// ── Main cron handler ─────────────────────────────────────────────────────────
export default {
  async scheduled(event, env, ctx) {
    const apiKey = env.ANTHROPIC_API_KEY;
    if (!apiKey) { console.error('ANTHROPIC_API_KEY not set'); return; }
    if (!env.DB)   { console.error('DB binding missing'); return; }
    if (!env.BLOG) { console.error('BLOG binding missing'); return; }

    console.log('Signal generator running...');

    try {
      const candidates = await fetchNotableSessions(env.DB);
      console.log(`Found ${candidates.length} candidate sessions`);

      if (candidates.length === 0) {
        console.log('No notable sessions this week — skipping');
        return;
      }

      // Filter out sessions we've already written about
      const fresh = [];
      for (const s of candidates) {
        const already = await sessionAlreadyWritten(env.BLOG, s.session_id);
        if (!already) fresh.push(s);
      }

      if (fresh.length === 0) {
        console.log('All candidate sessions already have posts — skipping');
        return;
      }

      console.log(`Calling Claude API with ${fresh.length} fresh candidates...`);
      const post = await generatePost(fresh, apiKey);

      if (!post) {
        console.log('Claude found nothing notable this week — skipping');
        return;
      }

      const id = await writePost(env.BLOG, post, post.selected_session_id);
      console.log(`Post written: ${id} — "${post.title}"`);

    } catch (err) {
      console.error('Signal generator failed:', err.message);
    }
  },

  // Also allow manual trigger via HTTP for testing
  async fetch(request, env) {
    if (request.method !== 'POST') return new Response('POST to trigger', { status: 405 });
    const secret = request.headers.get('X-Bathysphere-Secret');
    if (!secret || secret !== env.BATHYSPHERE_SECRET) return new Response('Unauthorized', { status: 401 });

    try {
      await this.scheduled(null, env, null);
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  },
};
