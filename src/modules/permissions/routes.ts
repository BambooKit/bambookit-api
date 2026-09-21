import { Hono } from 'hono';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';

export const permissionsRouter = new Hono();

permissionsRouter.use('*', authMiddleware);

// GET /v1/permissions
permissionsRouter.get('/', (c) => {
  const auth = c.get('auth');
  const policies = memoryDb.data.permissions.filter((p) => p.workspaceId === auth.workspaceId);

  return c.json({ data: policies, requestId: c.get('requestId') });
});
