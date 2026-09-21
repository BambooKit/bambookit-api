import { Hono } from 'hono';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';

export const notificationsRouter = new Hono();

notificationsRouter.use('*', authMiddleware);

// GET /v1/notifications
notificationsRouter.get('/', (c) => {
  const auth = c.get('auth');
  const notifs = memoryDb.data.notifications.filter((n) => n.workspaceId === auth.workspaceId);

  return c.json({ data: notifs, requestId: c.get('requestId') });
});

// POST /v1/notifications/read-all
notificationsRouter.post('/read-all', (c) => {
  const auth = c.get('auth');
  memoryDb.data.notifications = memoryDb.data.notifications.map((n) =>
    n.workspaceId === auth.workspaceId ? { ...n, read: true } : n
  );

  return c.json({ data: { success: true }, requestId: c.get('requestId') });
});
