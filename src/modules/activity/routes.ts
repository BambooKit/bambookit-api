import { Hono } from 'hono';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';

export const activityRouter = new Hono();

activityRouter.use('*', authMiddleware);

// GET /v1/activity
activityRouter.get('/', (c) => {
  const auth = c.get('auth');
  const auditLog = memoryDb.data.auditLog.filter((a) => a.workspaceId === auth.workspaceId);

  return c.json({ data: auditLog, requestId: c.get('requestId') });
});
