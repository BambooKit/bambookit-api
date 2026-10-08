import { publish } from '../realtime/bus.js';
import { Hono } from 'hono';
import { db } from '../db/database.js';
import { requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { rowToEvent } from '../realtime/bus.js';
import { serializeDevice, serializeSession } from './serializers.js';
import { filesChanged24h } from './stats.js';

export const accountRouter = new Hono<AppEnv>();
accountRouter.use('*', requireUser);

const count = async (sql: string, ...args: unknown[]) => Number((await db.get(sql, ...args))?.n ?? 0);

// GET /v1/overview — real counts for the mobile/web home screen
accountRouter.get('/overview', async (c) => {
  const userId = c.get('user').id;
  const devices = await Promise.all((await db.all<DeviceRow>('SELECT * FROM devices WHERE user_id = ? AND revoked_at IS NULL', userId)).map(serializeDevice));
  const active = await db.all(
    `SELECT s.*, p.name AS project_name,
        (SELECT COUNT(*) FROM approvals a WHERE a.session_id = s.id AND a.status IN ('PENDING','RESPONDING')) AS pending_approvals
      FROM sessions s LEFT JOIN projects p ON p.id = s.project_id
      WHERE s.user_id = ? AND s.status IN ('busy','retry') AND s.parent_opencode_session_id IS NULL ORDER BY s.updated_at DESC`,
    userId,
  );
  const changed24h = await filesChanged24h(userId);
  return c.json({
    data: {
      desktops: devices.filter((d) => d.kind === 'desktop'),
      mobiles: devices.filter((d) => d.kind === 'mobile'),
      activeSessions: active.map(serializeSession),
      pendingApprovals: await count("SELECT COUNT(*) AS n FROM approvals WHERE user_id = ? AND status IN ('PENDING','RESPONDING')", userId),
      // Home's "Files changed (24h)" (see stats.filesChanged24h); recentChangedFiles is the same value for older apps.
      filesChanged24h: changed24h,
      recentChangedFiles: changed24h,
      unreadNotifications: await count('SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read_at IS NULL', userId),
    },
  });
});

// DELETE /v1/activity — clear recent activity and notifications for this account (other users unaffected)
accountRouter.delete('/activity', async (c) => {
  const userId = c.get('user').id;
  const seq = Number((await db.get<{ s: number | null }>('SELECT MAX(seq) AS s FROM events WHERE user_id = ?', userId))?.s ?? 0);
  await db.run('UPDATE users SET activity_cleared_seq = ? WHERE id = ?', seq, userId);
  const removed = await db.run('DELETE FROM notifications WHERE user_id = ?', userId);
  await publish({ userId, type: 'activity.cleared', payload: { clearedThroughSeq: seq } });
  return c.json({ data: { clearedThroughSeq: seq, notificationsRemoved: removed.changes } });
});

// GET /v1/activity?before=<seq>
const ACTIVITY_TYPES = ['activity', 'approval.created', 'approval.updated', 'pairing.completed', 'device.registered', 'device.revoked', 'notification'];
accountRouter.get('/activity', async (c) => {
  const before = Number(c.req.query('before') ?? Number.MAX_SAFE_INTEGER);
  const cleared = Number((await db.get<{ s: number | null }>('SELECT activity_cleared_seq AS s FROM users WHERE id = ?', c.get('user').id))?.s ?? 0);
  const rows = await db.all(
    `SELECT * FROM events WHERE user_id = ? AND seq < ? AND seq > ? AND type IN (${ACTIVITY_TYPES.map(() => '?').join(',')}) ORDER BY seq DESC LIMIT 100`,
    c.get('user').id,
    before,
    cleared,
    ...ACTIVITY_TYPES,
  );
  return c.json({ data: rows.map(rowToEvent) });
});
