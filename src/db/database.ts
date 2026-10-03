import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { env } from '../config/env.js';

/**
 * Storage for bambookit-api.
 * - POSTGRES_URL set  → Postgres (e.g. Supabase). Use this on hosts with ephemeral disks (Render free tier).
 * - otherwise         → SQLite file at DATABASE_PATH (local development).
 * Queries are written once with `?` placeholders and portable SQL; the Postgres driver rewrites
 * placeholders to $1..$n.
 */
export interface Queryable {
  get<T = any>(sql: string, ...params: unknown[]): Promise<T | undefined>;
  all<T = any>(sql: string, ...params: unknown[]): Promise<T[]>;
  run(sql: string, ...params: unknown[]): Promise<{ changes: number }>;
}

export interface Database extends Queryable {
  dialect: 'sqlite' | 'postgres';
  tx<T>(fn: (q: Queryable) => Promise<T>): Promise<T>;
  ping(): Promise<void>;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
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
  public_key TEXT,
  push_token TEXT,
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
  status TEXT NOT NULL,
  status_message TEXT,
  agent TEXT,
  model TEXT,
  additions INTEGER NOT NULL DEFAULT 0,
  deletions INTEGER NOT NULL DEFAULT 0,
  files INTEGER NOT NULL DEFAULT 0,
  current_action TEXT,
  remote INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (device_id, opencode_session_id)
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id, updated_at);
CREATE TABLE IF NOT EXISTS session_parts (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  message_id TEXT NOT NULL,
  role TEXT NOT NULL,
  type TEXT NOT NULL,
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
  patterns TEXT NOT NULL,
  status TEXT NOT NULL,
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
  payload TEXT NOT NULL,
  status TEXT NOT NULL,
  result TEXT,
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
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_user ON events(user_id, seq);
CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  data TEXT NOT NULL,
  read_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS notifications_user ON notifications(user_id, created_at);
CREATE TABLE IF NOT EXISTS device_state (
  device_id TEXT PRIMARY KEY REFERENCES devices(id),
  user_id TEXT NOT NULL,
  state TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL,
  opencode_session_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS share_items (
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  type TEXT NOT NULL,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (share_id, key)
);
`;

function statements(dialect: 'sqlite' | 'postgres'): string[] {
  const sql = dialect === 'postgres' ? SCHEMA.replace('seq INTEGER PRIMARY KEY AUTOINCREMENT', 'seq BIGSERIAL PRIMARY KEY') : SCHEMA;
  return sql.split(';').map((s) => s.trim()).filter(Boolean);
}

/** Rewrite `?` placeholders as $1..$n (no `?` appears inside string literals in our SQL). */
function toPg(sql: string): string {
  let n = 0;
  return sql.replace(/\?/g, () => `$${++n}`);
}

// ---------------------------------------------------------------- SQLite

async function openSqlite(path: string): Promise<Database> {
  const { DatabaseSync } = await import('node:sqlite');
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const sqlite = new DatabaseSync(path);
  sqlite.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  for (const s of statements('sqlite')) sqlite.exec(s);

  const cache = new Map<string, any>();
  const stmt = (sql: string) => {
    let s = cache.get(sql);
    if (!s) cache.set(sql, (s = sqlite.prepare(sql)));
    return s;
  };
  const q: Queryable = {
    async get(sql, ...p) {
      return stmt(sql).get(...p);
    },
    async all(sql, ...p) {
      return stmt(sql).all(...p);
    },
    async run(sql, ...p) {
      return { changes: Number(stmt(sql).run(...p).changes) };
    },
  };
  // One connection: serialize transactions so concurrent requests never share one.
  let chain: Promise<unknown> = Promise.resolve();
  return {
    ...q,
    dialect: 'sqlite',
    async ping() {
      sqlite.prepare('SELECT 1').get();
    },
    tx<T>(fn: (q: Queryable) => Promise<T>): Promise<T> {
      const run = chain.then(async () => {
        sqlite.exec('BEGIN IMMEDIATE');
        try {
          const result = await fn(q);
          sqlite.exec('COMMIT');
          return result;
        } catch (err) {
          sqlite.exec('ROLLBACK');
          throw err;
        }
      });
      chain = run.catch(() => undefined);
      return run;
    },
  };
}

// ---------------------------------------------------------------- Postgres

interface PgLike {
  query(sql: string, params?: unknown[]): Promise<{ rows: any[]; rowCount?: number | null; affectedRows?: number }>;
}

function pgQueryable(client: PgLike): Queryable {
  return {
    async get(sql, ...p) {
      return (await client.query(toPg(sql), p)).rows[0];
    },
    async all(sql, ...p) {
      return (await client.query(toPg(sql), p)).rows;
    },
    async run(sql, ...p) {
      const r = await client.query(toPg(sql), p);
      return { changes: Number(r.rowCount ?? r.affectedRows ?? 0) };
    },
  };
}

async function openPostgres(url: string): Promise<Database> {
  // In-process Postgres (WASM) for tests: POSTGRES_URL=pglite://memory
  if (url.startsWith('pglite://')) {
    // Test-only dependency; resolved at runtime so production builds do not need it installed.
    const { PGlite } = (await import('@electric-sql/pglite' as string)) as any;
    const lite = new PGlite();
    const client: PgLike = { query: async (sql, params) => lite.query(sql, params as any[]) as any };
    for (const s of statements('postgres')) await lite.exec(s);
    let chain: Promise<unknown> = Promise.resolve();
    const q = pgQueryable(client);
    return {
      ...q,
      dialect: 'postgres',
      async ping() {
        await lite.query('SELECT 1');
      },
      tx<T>(fn: (q: Queryable) => Promise<T>) {
        const run = chain.then(() => lite.transaction(async (t: any) => fn(pgQueryable({ query: async (sql, params) => t.query(sql, params as any[]) as any }))));
        chain = run.catch(() => undefined);
        return run as Promise<T>;
      },
    };
  }

  const pg = (await import('pg')).default;
  pg.types.setTypeParser(20, (v: string) => Number(v)); // int8 (seq, COUNT) as number
  const pool = new pg.Pool({
    connectionString: url,
    max: 10,
    ssl: /sslmode=disable/.test(url) || /@(localhost|127\.0\.0\.1)/.test(url) ? undefined : { rejectUnauthorized: false },
  });
  for (const s of statements('postgres')) await pool.query(s);
  const q = pgQueryable(pool);
  return {
    ...q,
    dialect: 'postgres',
    async ping() {
      await pool.query('SELECT 1');
    },
    async tx<T>(fn: (q: Queryable) => Promise<T>) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn(pgQueryable(client));
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw err;
      } finally {
        client.release();
      }
    },
  };
}

export const db: Database = env.POSTGRES_URL ? await openPostgres(env.POSTGRES_URL) : await openSqlite(env.DATABASE_PATH);

/** Upgrades for databases created by earlier versions. Safe to run on every start. */
async function migrate(d: Database) {
  await d.run('ALTER TABLE sessions ADD COLUMN remote INTEGER NOT NULL DEFAULT 0').catch(() => undefined);
  // Profile: sign-in method, email verification (from the identity provider) and an uploaded photo in R2.
  await d.run('ALTER TABLE users ADD COLUMN provider TEXT').catch(() => undefined);
  await d.run('ALTER TABLE users ADD COLUMN email_verified INTEGER').catch(() => undefined);
  await d.run('ALTER TABLE users ADD COLUMN avatar_key TEXT').catch(() => undefined);
  // Nickname chosen in BambooKit; kept apart from the identity provider's name, which is refreshed on sign-in.
  await d.run('ALTER TABLE users ADD COLUMN nickname TEXT').catch(() => undefined);
  // Liked (starred) sessions: a BambooKit-only flag, never sent to the PC.
  await d.run('ALTER TABLE sessions ADD COLUMN starred INTEGER NOT NULL DEFAULT 0').catch(() => undefined);
  // Questions the agent asks (kind = 'question') travel through approvals with their options and answers.
  await d.run("ALTER TABLE approvals ADD COLUMN kind TEXT NOT NULL DEFAULT 'permission'").catch(() => undefined);
  await d.run('ALTER TABLE approvals ADD COLUMN questions TEXT').catch(() => undefined);
  await d.run('ALTER TABLE approvals ADD COLUMN answers TEXT').catch(() => undefined);
  // Session chats, diffs and activity now live only on the PC; remove copies stored by earlier versions.
  await d.run('DELETE FROM session_parts');
  await d.run('DELETE FROM session_diffs');
  await d.run("DELETE FROM events WHERE type IN ('session.part', 'session.transcript', 'session.diff', 'activity')");
}
await migrate(db);

export function now(): string {
  return new Date().toISOString();
}

export function parseJson<T>(value: unknown, fallback: T): T {
  if (typeof value !== 'string') return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}
