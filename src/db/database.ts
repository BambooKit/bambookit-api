import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { env } from '../config/env.js';

// Schema is applied idempotently on startup. Each statement is safe to re-run.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,               -- Supabase auth user id (JWT sub)
  email TEXT,
  name TEXT,
  avatar_url TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL CHECK (kind IN ('desktop','mobile')),
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  app_version TEXT,
  public_key TEXT,                   -- Ed25519 SPKI PEM (desktop only)
  push_token TEXT,                   -- FCM token (mobile only)
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id);

CREATE TABLE IF NOT EXISTS device_links (
  desktop_id TEXT NOT NULL REFERENCES devices(id),
  mobile_id TEXT NOT NULL REFERENCES devices(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  PRIMARY KEY (desktop_id, mobile_id)
);

CREATE TABLE IF NOT EXISTS pairing_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id),
  desktop_id TEXT NOT NULL REFERENCES devices(id),
  expires_at TEXT NOT NULL,
  used_at TEXT,
  used_by_device_id TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  opencode_project_id TEXT NOT NULL,
  name TEXT NOT NULL,
  directory TEXT NOT NULL,
  branch TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (device_id, opencode_project_id)
);
CREATE INDEX IF NOT EXISTS projects_user ON projects(user_id);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  project_id TEXT REFERENCES projects(id),
  opencode_session_id TEXT NOT NULL,
  parent_opencode_session_id TEXT,
  directory TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL,              -- idle | busy | retry | error
  status_message TEXT,
  agent TEXT,
  model TEXT,
  additions INTEGER NOT NULL DEFAULT 0,
  deletions INTEGER NOT NULL DEFAULT 0,
  files INTEGER NOT NULL DEFAULT 0,
  current_action TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (device_id, opencode_session_id)
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id, updated_at);

CREATE TABLE IF NOT EXISTS session_parts (
  id TEXT PRIMARY KEY,               -- opencode part id, scoped by session
  session_id TEXT NOT NULL REFERENCES sessions(id),
  message_id TEXT NOT NULL,
  role TEXT NOT NULL,                -- user | assistant
  type TEXT NOT NULL,                -- text | reasoning | tool
  text TEXT,
  tool TEXT,
  tool_status TEXT,
  tool_title TEXT,
  sort_key TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS parts_session ON session_parts(session_id, sort_key);

CREATE TABLE IF NOT EXISTS session_diffs (
  session_id TEXT NOT NULL REFERENCES sessions(id),
  file TEXT NOT NULL,
  status TEXT,
  additions INTEGER NOT NULL DEFAULT 0,
  deletions INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (session_id, file)
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  session_id TEXT NOT NULL REFERENCES sessions(id),
  opencode_request_id TEXT NOT NULL,
  permission TEXT NOT NULL,
  title TEXT,
  patterns TEXT NOT NULL,            -- JSON array
  status TEXT NOT NULL,              -- PENDING | RESPONDING | APPROVED | REJECTED | EXPIRED
  reply TEXT,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  UNIQUE (device_id, opencode_request_id)
);
CREATE INDEX IF NOT EXISTS approvals_user ON approvals(user_id, status);

CREATE TABLE IF NOT EXISTS commands (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  session_id TEXT REFERENCES sessions(id),
  issued_by_device_id TEXT,
  type TEXT NOT NULL,
  payload TEXT NOT NULL,             -- JSON
  status TEXT NOT NULL,              -- PENDING | SUCCEEDED | FAILED
  result TEXT,                       -- JSON
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS commands_device ON commands(device_id, status);

CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  device_id TEXT,
  project_id TEXT,
  session_id TEXT,
  type TEXT NOT NULL,
  payload TEXT NOT NULL,             -- JSON
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_user ON events(user_id, seq);

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  data TEXT NOT NULL,                -- JSON (ids only, never content or secrets)
  read_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS notifications_user ON notifications(user_id, created_at);
`;

function open(): DatabaseSync {
  if (env.DATABASE_PATH !== ':memory:') mkdirSync(dirname(env.DATABASE_PATH), { recursive: true });
  const db = new DatabaseSync(env.DATABASE_PATH);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  db.exec(SCHEMA);
  return db;
}

export const db = open();

export function now(): string {
  return new Date().toISOString();
}

/** Run fn inside a transaction. */
export function tx<T>(fn: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

export function parseJson<T>(value: unknown, fallback: T): T {
  if (typeof value !== 'string') return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}
