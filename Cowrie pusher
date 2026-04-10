#!/usr/bin/env python3
"""
cowrie_pusher.py
Tails cowrie.json and POSTs new events to the bathysphere ingest Worker.
Runs as a systemd service on the honeypot Pi.
"""

import json
import os
import time
import logging
import requests
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
LOG_FILE     = Path(os.getenv("COWRIE_LOG", "/home/cowrie/var/log/cowrie/cowrie.json"))
STATE_FILE   = Path(os.getenv("STATE_FILE",  "/var/lib/cowrie-pusher/state.json"))
INGEST_URL   = os.getenv("INGEST_URL",   "https://bathysphere.tech/ingest")
SHARED_SECRET = os.getenv("SHARED_SECRET", "")   # set in systemd EnvironmentFile
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))   # seconds
BATCH_SIZE    = int(os.getenv("BATCH_SIZE",    "200"))   # max events per POST
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [pusher] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def load_state() -> dict:
    """Load the last byte offset we successfully pushed."""
    try:
        return json.loads(STATE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"offset": 0}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))


def read_new_events(offset: int) -> tuple[list[dict], int]:
    """
    Read new JSON lines from cowrie.json starting at byte offset.
    Returns (events, new_offset).
    Handles log rotation gracefully: if the file is shorter than our
    stored offset, we assume rotation and start from 0.
    """
    events = []
    try:
        size = LOG_FILE.stat().st_size
        if size < offset:
            log.info("Log file shrank — assuming rotation, resetting offset.")
            offset = 0

        with LOG_FILE.open("rb") as f:
            f.seek(offset)
            for raw in f:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    log.warning("Skipping malformed line: %s", line[:80])
            new_offset = f.tell()

    except FileNotFoundError:
        log.warning("Log file not found: %s — waiting.", LOG_FILE)
        return [], offset

    return events, new_offset


def post_batch(events: list[dict]) -> bool:
    """POST a batch of events to the ingest Worker. Returns True on success."""
    if not SHARED_SECRET:
        log.error("SHARED_SECRET is not set — refusing to send.")
        return False

    try:
        resp = requests.post(
            INGEST_URL,
            json={"events": events},
            headers={
                "Content-Type": "application/json",
                "X-Bathysphere-Secret": SHARED_SECRET,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            return True
        log.error("Ingest Worker returned %d: %s", resp.status_code, resp.text[:200])
        return False

    except requests.exceptions.Timeout:
        log.error("POST timed out after 15s.")
        return False
    except requests.exceptions.ConnectionError as e:
        log.error("Connection error: %s", e)
        return False


def run() -> None:
    log.info("Starting. Log: %s  Endpoint: %s  Interval: %ds",
             LOG_FILE, INGEST_URL, POLL_INTERVAL)

    state = load_state()
    log.info("Resuming from byte offset %d.", state["offset"])

    while True:
        events, new_offset = read_new_events(state["offset"])

        if events:
            log.info("Read %d new event(s).", len(events))
            # Send in batches so a single huge burst doesn't time out
            for i in range(0, len(events), BATCH_SIZE):
                batch = events[i : i + BATCH_SIZE]
                if post_batch(batch):
                    log.info("Pushed batch of %d event(s).", len(batch))
                else:
                    # Don't advance offset — retry next cycle
                    log.warning("Batch failed — will retry next cycle.")
                    new_offset = state["offset"]
                    break
            else:
                state["offset"] = new_offset
                save_state(state)
        else:
            log.debug("No new events.")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
