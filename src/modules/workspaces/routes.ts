import { Hono } from 'hono';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';

export const workspacesRouter = new Hono();

workspacesRouter.use('*', authMiddleware);

// GET /v1/workspaces/current
workspacesRouter.get('/current', (c) => {
  const auth = c.get('auth');
  const ws = memoryDb.data.workspace;

  return c.json({
    data: {
      ...ws,
      role: auth.role,
    },
    requestId: c.get('requestId'),
  });
});

// GET /v1/workspaces
workspacesRouter.get('/', (c) => {
  return c.json({
    data: [memoryDb.data.workspace],
    requestId: c.get('requestId'),
  });
});
