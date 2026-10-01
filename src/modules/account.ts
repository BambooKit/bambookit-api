import { Hono } from 'hono';
import { db } from '../db/database.js';
import { requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { rowToEvent } from '../realtime/bus.js';
import { serializeDevice, serializeSession } from './serializers.js';

export const accountRouter = new Hono<AppEnv>();
accountRouter.use('*', requireUser);

// GET /v1/me
accountRouter.get('/me', (c) => {
  const user = c.get('user');
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id) as any;
  return c.json({ data: { id: user.id, email: user.email, name: row?.name ?? user.name, avatarUrl: row?.avatar_url ?? user.avatarUrl, createdAt: row?.created_at } });
});

// GET /v1/overview — real counts for the mobile/web home screen
accountRouter.get('/overview', (c) => {
  const userId = c.get('user').id;
  const devices = (db.prepare('SELECT * FROM devices WHERE user_id = ? AND revoked_at IS NULL').all(userId) as unknown as DeviceRow[]).map(serializeDevice);
  const active = db
    .prepare(`SELECT s.*, p.name AS project_name,
        (SELECT COUNT(*) FROM approvals a WHERE a.session_id = s.id AND a.status IN ('PENDING','RESPONDING')) AS pending_approvals
      FROM sessions s LEFT JOIN projects p ON p.id = s.project_id
      WHERE s.user_id = ? AND s.status IN ('busy','retry') AND s.parent_opencode_session_id IS NULL ORDER BY s.updated_at DESC`)
    .all(userId);
  const pendingApprovals = Number((db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE user_id = ? AND status IN ('PENDING','RESPONDING')").get(userId) as any).n);
  const changedFiles = Number(
    (db.prepare("SELECT COUNT(*) AS n FROM session_diffs d JOIN sessions s ON s.id = d.session_id WHERE s.user_id = ? AND d.updated_at > datetime('now','-1 day')").get(userId) as any).n,
  );
  const unread = Number((db.prepare('SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read_at IS NULL').get(userId) as any).n);
  return c.json({
    data: {
      desktops: devices.filter((d) => d.kind === 'desktop'),
      mobiles: devices.filter((d) => d.kind === 'mobile'),
      activeSessions: active.map(serializeSession),
      pendingApprovals,
      recentChangedFiles: changedFiles,
      unreadNotifications: unread,
    },
  });
});

// GET /v1/activity?before=<seq>
const ACTIVITY_TYPES = ['activity', 'approval.created', 'approval.updated', 'pairing.completed', 'device.registered', 'device.revoked', 'notification'];
accountRouter.get('/activity', (c) => {
  const before = Number(c.req.query('before') ?? Number.MAX_SAFE_INTEGER);
  const rows = db
    .prepare(`SELECT * FROM events WHERE user_id = ? AND seq < ? AND type IN (${ACTIVITY_TYPES.map(() => '?').join(',')}) ORDER BY seq DESC LIMIT 100`)
    .all(c.get('user').id, before, ...ACTIVITY_TYPES);
  return c.json({ data: rows.map(rowToEvent) });
});
