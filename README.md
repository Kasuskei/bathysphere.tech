# bathysphere.tech

A honeypot threat intelligence feed. A Raspberry Pi 4 running Cowrie sits exposed
on the internet and logs everything that connects to it — credential attempts,
commands run in the captured shell, files uploaded, tunneling attempts. This repo
is the full stack that collects, stores, and displays that data.

Live at [bathysphere.tech](https://bathysphere.tech)

---

## What's in here

```
site/             Landing page and feed UI — deployed via Cloudflare Pages
workers/ingest/   Cloudflare Worker that receives events from the Pi
workers/read/     Cloudflare Worker that serves events to the frontend
pusher/           Python service that runs on the Pi and ships logs to the cloud
DEPLOY.md         Step-by-step deployment guide
```

## How it works

```
Raspberry Pi 4
└── Cowrie SSH honeypot (port 2222)
    └── cowrie_pusher.py (systemd service)
        └── POST /ingest every 30s
            └── Cloudflare Worker (ingest)
                └── Cloudflare KV  ←→  Cloudflare Worker (read)
                                            └── GET /events
                                                └── bathysphere.tech feed
```

1. **Cowrie** runs on a Raspberry Pi 4 and presents a convincing SSH shell to anyone
   who connects. It logs every session, credential attempt, and command in JSON.

2. **cowrie_pusher.py** tails the Cowrie log file and POSTs new events to the ingest
   Worker every 30 seconds. Runs as a systemd service so it survives reboots.

3. **The ingest Worker** validates the request, anonymizes IP addresses, and appends
   events to a Cloudflare KV store. Keeps a rolling window of the 10,000 most recent
   events.

4. **The read Worker** serves stored events as JSON to the frontend. Supports filtering
   by timestamp and event type.

5. **The site** is a static HTML page served by Cloudflare Pages that polls `/events`
   every 30 seconds and updates the feed.

## Hardware

- Raspberry Pi 4 (4GB) — honeypot sensor
- HP ProDesk mini PC — OPNsense firewall/router
- Netgear GS308E — managed switch, VLAN segmentation

## Stack

- [Cowrie](https://github.com/cowrie/cowrie) — SSH/Telnet honeypot
- [Cloudflare Workers](https://workers.cloudflare.com/) — ingest and read API
- [Cloudflare KV](https://developers.cloudflare.com/kv/) — event storage
- [Cloudflare Pages](https://pages.cloudflare.com/) — static site hosting
- Python 3 — Pi-side log pusher

## Deployment

See [DEPLOY.md](./DEPLOY.md) for the full step-by-step guide.

## Notes on privacy

- All IP addresses in the feed are anonymized (last two octets replaced with `x.x`)
- Passwords are never stored — only a masked hint and character length
- No visitor tracking on the site

## License

MIT
