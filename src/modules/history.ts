import { gunzipSync } from 'node:zlib';
import { Hono } from 'hono';
import { z } from 'zod';
import { env } from '../config/env.js';
import { db } from '../db/database.js';
import { HttpError, badRequest, forbidden, notFound } from '../lib/http.js';
import { logger } from '../lib/logger.js';
import { requireDevice, requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { isConnected } from '../realtime/bus.js';
import { SIGNED_URL_SECONDS, keys, storage } from '../services/storage.js';
import { relay } from './relay.js';
import { serializeApproval } from './serializers.js';
import { requireStorage } from './profile.js';
import { assertSessionAccess } from './collaborators.js';

/**
 * Session history: prompts, timeline, changed files with per-edit patches, tests and summary.
 * The PC is the source (OpenCode's local database). While it is online the history is read live;
 * the PC also saves a copy to Cloudflare R2 that phones and the website can read for
 * SESSION_SNAPSHOT_DAYS (7) days while the PC is off. Full before/after file contents are only read
 * live from the PC and never stored.
 */
export const historyRouter = new Hono<AppEnv>();
historyRouter.use('*', requireUser);

const MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024;
const maxAgeMs = () => env.SESSION_SNAPSHOT_DAYS * 86_400_000;

async function ownedSession(userId: string, id: string) {
  const row = await db.get('SELECT * FROM sessions WHERE id = ? AND user_id = ?', id, userId);
  if (!row) throw notFound('Session');
  return row;
}

async function approvalsFor(sessionId: string) {
  const rows = await db.all(
    `SELECT a.*, s.title AS session_title, p.name AS project_name FROM approvals a
     JOIN sessions s ON s.id = a.session_id LEFT JOIN projects p ON p.id = s.project_id
     WHERE a.session_id = ? ORDER BY a.created_at ASC LIMIT 500`,
    sessionId,
  );
  return rows.map(serializeApproval);
}

// GET /v1/sessions/:id/history
historyRouter.get('/:id/history', async (c) => {
  const user = c.get('user');
  const { session } = await assertSessionAccess(user.id, c.req.param('id'), 'read');
  const desktop = await db.get<DeviceRow>('SELECT * FROM devices WHERE id = ?', session.device_id);
  const approvals = await approvalsFor(session.id);

  if (desktop && !desktop.revoked_at && isConnected(desktop.id)) {
    const history = (await relay(session.user_id, desktop, 'history', { opencodeSessionId: session.opencode_session_id })) as Record<string, unknown>;
    return c.json({ data: { source: 'pc', savedAt: null, history: { ...history, sessionId: session.id }, approvals } });
  }

  if (storage) {
    const obj = await storage.get(keys.sessionSnapshot(user.id, session.id));
    if (obj && Date.now() - obj.lastModified.getTime() <= maxAgeMs()) {
      const history = JSON.parse(gunzipSync(obj.body).toString('utf8'));
      return c.json({ data: { source: 'cloud', savedAt: obj.lastModified.toISOString(), history: { ...history, sessionId: session.id }, approvals } });
    }
  }
  throw new HttpError(
    503,
    'DESKTOP_OFFLINE',
    `${desktop?.name ?? 'The PC'} is offline and no copy of this session from the last ${env.SESSION_SNAPSHOT_DAYS} days is saved. Open BambooKit Desktop on that PC to see it.`,
  );
});

// GET /v1/sessions/:id/file-versions?path= — before/after of one file, live from the PC only
historyRouter.get('/:id/file-versions', async (c) => {
  const user = c.get('user');
  const { session } = await assertSessionAccess(user.id, c.req.param('id'), 'read');
  const path = z.string().min(1).max(1000).parse(c.req.query('path'));
  const desktop = await db.get<DeviceRow>('SELECT * FROM devices WHERE id = ?', session.device_id);
  if (!desktop || desktop.revoked_at) throw notFound('Device');
  return c.json({ data: await relay(session.user_id, desktop, 'fileversions', { opencodeSessionId: session.opencode_session_id, path }) });
});

// POST /v1/sessions/:id/snapshot-upload { size } (signed, from the session's PC) → signed PUT URL for the gzip JSON copy
historyRouter.post('/:id/snapshot-upload', requireDevice('desktop'), async (c) => {
  const store = requireStorage();
  const user = c.get('user');
  const device = c.get('device')!;
  const session = await ownedSession(user.id, c.req.param('id'));
  if (session.device_id !== device.id) throw forbidden('Only the PC that runs this session can save its history', 'NOT_SESSION_DEVICE');
  const { size } = z.object({ size: z.number().int().positive() }).parse(JSON.parse(await c.req.text()));
  if (size > MAX_SNAPSHOT_BYTES) throw badRequest('Session history copy is too large', 'SNAPSHOT_TOO_LARGE');
  const key = keys.sessionSnapshot(user.id, session.id);
  const url = await store.presignPut(key, 'application/gzip', size, SIGNED_URL_SECONDS);
  return c.json({ data: { url, method: 'PUT', headers: { 'Content-Type': 'application/gzip' }, expiresIn: SIGNED_URL_SECONDS } });
});

/** Deletes session history copies older than SESSION_SNAPSHOT_DAYS (in addition to any R2 lifecycle rule). */
export async function sweepExpiredSnapshots() {
  if (!storage) return 0;
  const cutoff = Date.now() - maxAgeMs();
  const expired = (await storage.list('users/')).filter((o) => o.key.includes('/sessions/') && o.lastModified.getTime() < cutoff).map((o) => o.key);
  if (expired.length) {
    await storage.deleteKeys(expired);
    logger.info('expired session copies deleted', { count: expired.length });
  }
  return expired.length;
}
