-- bathysphere D1 schema
-- Run with: wrangler d1 execute bathysphere --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS events (
  id          TEXT PRIMARY KEY,
  ts          TEXT NOT NULL,
  eventid     TEXT NOT NULL,
  session     TEXT,
  src_ip      TEXT,
  protocol    TEXT DEFAULT 'ssh',
  sensor      TEXT DEFAULT 'honeypot-pi',

  -- Geo
  geo_country TEXT,
  geo_city    TEXT,

  -- Network enrichment
  geo_asn     TEXT,
  geo_isp     TEXT,
  geo_rdns    TEXT,
  geo_cloud   TEXT,

  -- Event-specific fields
  dst_port    INTEGER,
  duration    REAL,
  version     TEXT,
  username    TEXT,
  password_hash TEXT,
  password_len  INTEGER,
  input       TEXT,
  filename    TEXT,
  shasum      TEXT,
  url         TEXT,

  -- ATT&CK
  attack_id   TEXT,
  attack_name TEXT,
  attack_tactic TEXT,

  -- IoCs stored as JSON array
  iocs        TEXT,

  -- AbuseIPDB score stored separately for easy querying
  abuse_score INTEGER
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_ts        ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_eventid   ON events(eventid);
CREATE INDEX IF NOT EXISTS idx_src_ip    ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_sensor    ON events(sensor);
CREATE INDEX IF NOT EXISTS idx_session   ON events(session);
CREATE INDEX IF NOT EXISTS idx_attack_id ON events(attack_id);
CREATE INDEX IF NOT EXISTS idx_username  ON events(username);
CREATE INDEX IF NOT EXISTS idx_cloud     ON events(geo_cloud);
CREATE INDEX IF NOT EXISTS idx_asn       ON events(geo_asn);
