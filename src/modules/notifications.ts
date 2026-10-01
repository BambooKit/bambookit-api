import { Hono } from 'hono';
import { db, now } from '../db/database.js';
import { requireUser, type AppEnv } from '../middleware/auth.js';
import { newId, notFound } from '../lib/http.js';
import { publish } from '../realtime/bus.js';
import { serializeNotification } from './serializers.js';

/**
 * Create a notification. `data` must only carry identifiers — never source code, tokens or secrets.
 * Delivery to phones happens through the realtime stream (and FCM when configured).
 */
export function notify(input: { userId: string; type: string; title: string; body: string; data: Record<string, string> }) {
  const id = newId('ntf');
  db.prepare('INSERT INTO notifications (id, user_id, type, title, body, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    id,
    input.userId,
    input.type,
    input.title,
    input.body.slice(0, 300),
    JSON.stringify(input.data),
    now(),
  );
  const row = db.prepare('SELECT * FROM notifications WHERE id = ?').get(id);
  publish({ userId: input.userId, type: 'notification', payload: serializeNotification(row) });
}

export const notificationsRouter = new Hono<AppEnv>();
notificationsRouter.use('*', requireUser);

notificationsRouter.get('/', (c) => {
  const rows = db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').all(c.get('user').id);
  return c.json({ data: rows.map(serializeNotification) });
});

notificationsRouter.post('/read-all', (c) => {
  const res = db.prepare('UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL').run(now(), c.get('user').id);
  return c.json({ data: { updated: Number(res.changes) } });
});

notificationsRouter.post('/:id/read', (c) => {
  const res = db.prepare('UPDATE notifications SET read_at = COALESCE(read_at, ?) WHERE id = ? AND user_id = ?').run(now(), c.req.param('id'), c.get('user').id);
  if (!res.changes) throw notFound('Notification');
  return c.json({ data: { read: true } });
});
