# bathysphere.tech — deployment guide

## Prerequisites
- Cloudflare account with Workers Paid plan ($5/mo)
- `wrangler` CLI installed and authenticated
  ```
  npm i -g wrangler && wrangler login
  ```
- Python 3 and `requests` on the Pi
  ```
  pip3 install requests
  ```
- An AbuseIPDB account (free tier) — https://www.abuseipdb.com
- An Anthropic API account with credits — https://console.anthropic.com

---

## Step 1 — Create the KV namespace

Run once. Both the ingest and read Workers share this namespace.

```
wrangler kv:namespace create "EVENTS"
```

Copy the returned `id` and paste it into:
- `workers/ingest/wrangler.toml` → `[[kv_namespaces]] id = "..."`
- `workers/read/wrangler.toml`   → `[[kv_namespaces]] id = "..."`

---

## Step 2 — Create the D1 databases

Two databases: one for events, one for signal posts.

```
wrangler d1 create bathysphere
wrangler d1 create bathysphere-blog
```

Copy the returned `database_id` values and paste them into:
- `workers/ingest/wrangler.toml` → `[[d1_databases]]` binding `DB`
- `workers/read/wrangler.toml`   → `[[d1_databases]]` bindings `DB` and `BLOG`
- `workers/signal/wrangler.toml` → `[[d1_databases]]` bindings `DB` and `BLOG`

Then create the events schema:

```
wrangler d1 execute bathysphere --remote --command="
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  eventid TEXT NOT NULL,
  session TEXT,
  src_ip TEXT,
  protocol TEXT,
  sensor TEXT,
  geo_country TEXT,
  geo_city TEXT,
  geo_asn TEXT,
  geo_isp TEXT,
  geo_rdns TEXT,
  geo_cloud TEXT,
  dst_port INTEGER,
  duration REAL,
  version TEXT,
  username TEXT,
  password_hash TEXT,
  password_len INTEGER,
  input TEXT,
  filename TEXT,
  shasum TEXT,
  url TEXT,
  attack_id TEXT,
  attack_name TEXT,
  attack_tactic TEXT,
  iocs TEXT,
  abuse_score INTEGER
)"
```

Add indexes for query performance:

```
wrangler d1 execute bathysphere --remote --command="CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(ts DESC)"
wrangler d1 execute bathysphere --remote --command="CREATE INDEX IF NOT EXISTS idx_events_type ON events(eventid)"
wrangler d1 execute bathysphere --remote --command="CREATE INDEX IF NOT EXISTS idx_events_sensor ON events(sensor)"
wrangler d1 execute bathysphere --remote --command="CREATE INDEX IF NOT EXISTS idx_events_attack ON events(attack_id)"
wrangler d1 execute bathysphere --remote --command="CREATE INDEX IF NOT EXISTS idx_events_has_ioc ON events(iocs IS NOT NULL)"
wrangler d1 execute bathysphere --remote --command="CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(src_ip)"
```

Add FTS5 full-text search on commands, usernames, and client versions:

```
wrangler d1 execute bathysphere --remote --command="CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(id UNINDEXED, input, username, version, content='events', content_rowid='rowid')"
wrangler d1 execute bathysphere --remote --command="INSERT INTO events_fts(events_fts) VALUES('rebuild')"
wrangler d1 execute bathysphere --remote --command="CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events BEGIN INSERT INTO events_fts(rowid, id, input, username, version) VALUES (new.rowid, new.id, new.input, new.username, new.version); END"
wrangler d1 execute bathysphere --remote --command="CREATE TRIGGER IF NOT EXISTS events_fts_delete AFTER DELETE ON events BEGIN INSERT INTO events_fts(events_fts, rowid, id, input, username, version) VALUES('delete', old.rowid, old.id, old.input, old.username, old.version); END"
```

Create the blog schema:

```
wrangler d1 execute bathysphere-blog --remote --command="
CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  date TEXT NOT NULL,
  sensor TEXT NOT NULL,
  tags TEXT NOT NULL,
  title TEXT NOT NULL,
  lede TEXT NOT NULL,
  findings TEXT NOT NULL,
  body TEXT NOT NULL,
  session_ids TEXT
)"
```

---

## Step 3 — Generate secrets

**Shared secret** (authenticates Pi pusher → ingest Worker):
```
python3 -c "import secrets; print(secrets.token_hex(32))"
```

You'll need:
- This shared secret
- An AbuseIPDB API key (from https://www.abuseipdb.com/account/api)
- An Anthropic API key (from https://console.anthropic.com/api-keys)

---

## Step 4 — Deploy the ingest Worker

```
cd workers/ingest
wrangler deploy
wrangler secret put BATHYSPHERE_SECRET   # paste shared secret
wrangler secret put ABUSEIPDB_KEY        # paste AbuseIPDB key
```

---

## Step 5 — Deploy the read Worker

```
cd workers/read
wrangler deploy
```

No additional secrets needed — it reads from bindings only.

---

## Step 6 — Deploy the signal generator Worker

```
cd workers/signal
wrangler deploy
wrangler secret put BATHYSPHERE_SECRET   # same shared secret
wrangler secret put ANTHROPIC_API_KEY    # paste Anthropic key
```

The signal generator runs automatically every Monday at 09:00 UTC.
To trigger it manually for testing:

```
curl -X POST https://bathysphere-signal.kasuskei.workers.dev \
  -H "X-Bathysphere-Secret: <your_secret>"
```

---

## Step 7 — Install the Pi pusher

On the honeypot Pi (as root):

```
pip3 install requests
mkdir -p /opt/cowrie-pusher /var/lib/cowrie-pusher /etc/cowrie-pusher

cp cowrie_pusher.py /opt/cowrie-pusher/
cp cowrie-pusher.service /etc/systemd/system/

# Write config
cat > /etc/cowrie-pusher/env << EOF
SHARED_SECRET=<your_shared_secret>
INGEST_URL=https://bathysphere-ingest.kasuskei.workers.dev/ingest
COWRIE_LOG=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
STATE_FILE=/var/lib/cowrie-pusher/state.json
POLL_INTERVAL=30
BATCH_SIZE=200
EOF

chown cowrie:cowrie /etc/cowrie-pusher/env
chmod 600 /etc/cowrie-pusher/env
chown -R cowrie:cowrie /opt/cowrie-pusher /var/lib/cowrie-pusher

systemctl daemon-reload
systemctl enable cowrie-pusher
systemctl start cowrie-pusher
```

Verify it's running:

```
journalctl -u cowrie-pusher -f
```

You should see:
```
[pusher] INFO Read 14 new event(s).
[pusher] INFO Pushed batch of 14 event(s).
```

---

## Step 8 — Backfill historical logs (optional)

If you have existing Cowrie logs to import, use the backfill script.
Set environment variables and run from the repo root:

```
$env:SHARED_SECRET="<your_secret>"
$env:ABUSEIPDB_KEY="<your_abuseipdb_key>"
node d1_backfill.js
```

For a test run capped at 500 log lines:
```
$env:MAX_LINES="500"
node d1_backfill.js
```

For a specific log file (e.g. archived daily logs):
```
node d1_backfill.js --file=logs/cowrie_april11.json
```

State is saved to `d1_backfill_state_<filename>.json` — the script is resumable.

---

## Step 9 — Deploy the site

```
# From the repo root
wrangler pages deploy site --project-name=bathysphere
```

Or connect your GitHub repo in the Cloudflare Pages dashboard for auto-deploy
on push. The site has no build step — just static HTML.

---

## Ongoing operations

**View pusher logs:**
```
journalctl -u cowrie-pusher -f
```

**Restart pusher after config change:**
```
systemctl restart cowrie-pusher
```

**Check D1 event count:**
```
wrangler d1 execute bathysphere --remote --command="SELECT COUNT(*) FROM events"
```

**Check most recent events:**
```
wrangler d1 execute bathysphere --remote --command="SELECT ts, eventid, src_ip FROM events ORDER BY ts DESC LIMIT 5"
```

**Manually trigger signal post generation:**
```
curl -X POST https://bathysphere-signal.kasuskei.workers.dev \
  -H "X-Bathysphere-Secret: <your_secret>"
```

**Check signal posts:**
```
wrangler d1 execute bathysphere-blog --remote --command="SELECT id, date, title FROM posts"
```

**Rotate the shared secret:**
1. Generate a new secret (Step 3)
2. `wrangler secret put BATHYSPHERE_SECRET` in `workers/ingest`
3. `wrangler secret put BATHYSPHERE_SECRET` in `workers/signal`
4. Update `/etc/cowrie-pusher/env` on the Pi
5. `systemctl restart cowrie-pusher`
