import { Hono } from 'hono';
import { z } from 'zod';
import { env, VERSION } from '../config/env.js';
import { db } from '../db/database.js';
import { requireUser, type AppEnv } from '../middleware/auth.js';
import { HttpError } from '../lib/http.js';
import { health } from '../lib/monitor.js';
import { connectionTotals } from '../realtime/bus.js';
import { storage } from '../services/storage.js';

/**
 * Admin panel data. Only accounts whose email is listed in ADMIN_EMAILS (and verified when the sign-in
 * provider says so) may read it. Aggregates and account metadata only — never session content, files,
 * tokens or keys.
 */
const adminEmails = new Set((env.ADMIN_EMAILS ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));

export function isAdmin(user: { email: string | null; emailVerified: boolean | null }) {
  return !!user.email && adminEmails.has(user.email.toLowerCase()) && user.emailVerified !== false;
}

const n = async (sql: string, ...args: unknown[]) => Number((await db.get<{ n: number }>(sql, ...args))?.n ?? 0);
const since = (ms: number) => new Date(Date.now() - ms).toISOString();
const DAY = 24 * 3600_000;

export async function adminSnapshot() {
  const live = connectionTotals();
  const desktops = await db.all<{ id: string; app_version: string | null }>("SELECT id, app_version FROM devices WHERE kind = 'desktop' AND revoked_at IS NULL");
  const online = new Set(live.connectedDeviceIds);
  const versions: Record<string, number> = {};
  for (const d of desktops) versions[d.app_version ?? 'unknown'] = (versions[d.app_version ?? 'unknown'] ?? 0) + 1;
  const providers = await db.all<{ provider: string | null; n: number }>('SELECT provider, COUNT(*) AS n FROM users GROUP BY provider');
  return {
    service: { version: VERSION, commit: process.env.RENDER_GIT_COMMIT?.slice(0, 7) ?? null, database: db.dialect, storage: !!storage, telegram: !!env.TELEGRAM_BOT_TOKEN },
    health: health(),
    realtime: { streams: live.devices + live.web, devices: live.devices, web: live.web },
    users: {
      total: await n('SELECT COUNT(*) AS n FROM users'),
      new24h: await n('SELECT COUNT(*) AS n FROM users WHERE created_at >= ?', since(DAY)),
      new7d: await n('SELECT COUNT(*) AS n FROM users WHERE created_at >= ?', since(7 * DAY)),
      active24h: await n('SELECT COUNT(*) AS n FROM users WHERE last_seen_at >= ?', since(DAY)),
      byProvider: Object.fromEntries(providers.map((p) => [p.provider ?? 'unknown', Number(p.n)])),
    },
    devices: {
      desktops: desktops.length,
      desktopsOnline: desktops.filter((d) => online.has(d.id)).length,
      phones: await n("SELECT COUNT(*) AS n FROM devices WHERE kind = 'mobile' AND revoked_at IS NULL"),
      revoked: await n('SELECT COUNT(*) AS n FROM devices WHERE revoked_at IS NOT NULL'),
      desktopVersions: versions,
    },
    projects: { total: await n('SELECT COUNT(*) AS n FROM projects') },
    sessions: {
      total: await n('SELECT COUNT(*) AS n FROM sessions WHERE parent_opencode_session_id IS NULL'),
      working: await n("SELECT COUNT(*) AS n FROM sessions WHERE status IN ('busy','retry')"),
      updated24h: await n('SELECT COUNT(*) AS n FROM sessions WHERE updated_at >= ?', since(DAY)),
    },
    approvals: { pending: await n("SELECT COUNT(*) AS n FROM approvals WHERE status IN ('PENDING','RESPONDING')") },
    work: {
      last7dMs: await n('SELECT COALESCE(SUM(duration_ms), 0) AS n FROM work_intervals WHERE started_at >= ?', since(7 * DAY)),
      tasks7d: await n('SELECT COUNT(*) AS n FROM work_intervals WHERE started_at >= ?', since(7 * DAY)),
      failed7d: await n("SELECT COUNT(*) AS n FROM work_intervals WHERE started_at >= ? AND outcome = 'failed'", since(7 * DAY)),
    },
  };
}

export async function recentUsers(limit: number, offset = 0) {
  const rows = await db.all<any>(
    `SELECT u.id, u.email, u.name, u.nickname, u.provider, u.email_verified, u.created_at, u.last_seen_at,
       (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL) AS devices,
       (SELECT COUNT(*) FROM projects p WHERE p.user_id = u.id) AS projects,
       (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS sessions
     FROM users u ORDER BY u.created_at DESC LIMIT ? OFFSET ?`,
    limit,
    offset,
  );
  return rows.map((r) => ({
    id: r.id,
    email: r.email ?? null,
    name: r.nickname ?? r.name ?? null,
    provider: r.provider ?? null,
    emailVerified: r.email_verified === null || r.email_verified === undefined ? null : !!Number(r.email_verified),
    createdAt: r.created_at,
    lastSeenAt: r.last_seen_at ?? null,
    devices: Number(r.devices),
    projects: Number(r.projects),
    sessions: Number(r.sessions),
  }));
}

export const adminRouter = new Hono<AppEnv>();
adminRouter.use('*', requireUser, async (c, next) => {
  if (!isAdmin(c.get('user'))) throw new HttpError(403, 'NOT_ADMIN', 'This account is not a BambooKit administrator.');
  await next();
});

// GET /v1/admin/me — lets clients show the admin panel entry only to administrators
adminRouter.get('/me', (c) => c.json({ data: { admin: true } }));

// GET /v1/admin/overview — service health, users, devices, sessions and recent server errors
adminRouter.get('/overview', async (c) => c.json({ data: await adminSnapshot() }));

// GET /v1/admin/users?limit=&offset=
adminRouter.get('/users', async (c) => {
  const limit = z.coerce.number().int().min(1).max(200).default(50).parse(c.req.query('limit') ?? undefined);
  const offset = z.coerce.number().int().min(0).default(0).parse(c.req.query('offset') ?? undefined);
  return c.json({ data: await recentUsers(limit, offset), total: await n('SELECT COUNT(*) AS n FROM users') });
});
