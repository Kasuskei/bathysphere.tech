# bathysphere.tech — deployment guide

## Prerequisites
- Cloudflare account with bathysphere.tech added as a zone
- `wrangler` CLI installed and authenticated (`npm i -g wrangler && wrangler login`)
- Python 3 and `requests` on the Pi (`pip3 install requests`)

---

## Step 1 — Create the KV namespace

Run once. Both Workers share the same namespace.

    wrangler kv:namespace create "EVENTS"

Copy the returned `id` value. Paste it into:
- `workers/ingest/wrangler.toml`  → `[[kv_namespaces]] id = "..."`
- `workers/read/wrangler.toml`    → `[[kv_namespaces]] id = "..."`

---

## Step 2 — Generate the shared secret

    python3 -c "import secrets; print(secrets.token_hex(32))"

You'll use this value in two places:
- On the Pi: `/etc/cowrie-pusher/env` → `SHARED_SECRET=<value>`
- In Cloudflare: as a Worker secret (next step)

---

## Step 3 — Deploy the ingest Worker

    cd workers/ingest
    wrangler deploy
    wrangler secret put BATHYSPHERE_SECRET
    # paste your generated secret when prompted

Then in the Cloudflare dashboard:
  Workers & Pages → bathysphere-ingest → Settings → Triggers
  Add route: bathysphere.tech/ingest

---

## Step 4 — Deploy the read Worker

    cd workers/read
    wrangler deploy

Then in the Cloudflare dashboard:
  Workers & Pages → bathysphere-read → Settings → Triggers
  Add routes:
    bathysphere.tech/events
    bathysphere.tech/stats

---

## Step 5 — Install the Pi pusher

On the honeypot Pi (as root):

    pip3 install requests
    mkdir -p /opt/cowrie-pusher /var/lib/cowrie-pusher /etc/cowrie-pusher

    cp cowrie_pusher.py /opt/cowrie-pusher/
    cp cowrie-pusher.service /etc/systemd/system/

    # Write secrets file
    cp env.template /etc/cowrie-pusher/env
    nano /etc/cowrie-pusher/env          # paste your SHARED_SECRET

    chown cowrie:cowrie /etc/cowrie-pusher/env
    chmod 600 /etc/cowrie-pusher/env
    chown -R cowrie:cowrie /opt/cowrie-pusher /var/lib/cowrie-pusher

    systemctl daemon-reload
    systemctl enable cowrie-pusher
    systemctl start cowrie-pusher

Verify it's running and pushing:

    journalctl -u cowrie-pusher -f

You should see lines like:
    [pusher] INFO Read 14 new event(s).
    [pusher] INFO Pushed batch of 14 event(s).

---

## Step 6 — Verify end to end

Check the read Worker is serving data:

    curl https://bathysphere.tech/stats | jq
    curl "https://bathysphere.tech/events?limit=5" | jq

If /stats returns { total_events: 0 }, wait one poll cycle (30s) and retry.

---

## Step 7 — Deploy the site to Cloudflare Pages

    # From the repo root
    wrangler pages deploy ./site --project-name=bathysphere

Or connect your GitHub repo in the Cloudflare Pages dashboard for auto-deploy
on push. The site has no build step — just static HTML.

---

## Ongoing operations

View pusher logs:
    journalctl -u cowrie-pusher -f

Restart pusher after config change:
    systemctl restart cowrie-pusher

Check KV event count:
    curl https://bathysphere.tech/stats | jq .total_events

Watch live events from the terminal:
    watch -n 30 'curl -s "https://bathysphere.tech/events?limit=10" | jq "[.events[] | {ts, eventid, src_ip}]"'

Rotate the shared secret:
    1. Generate a new secret (Step 2)
    2. wrangler secret put BATHYSPHERE_SECRET  (in workers/ingest)
    3. Update /etc/cowrie-pusher/env on the Pi
    4. systemctl restart cowrie-pusher
