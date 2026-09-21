import { Hono } from 'hono';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';

export const deploymentsRouter = new Hono();

deploymentsRouter.use('*', authMiddleware);

// GET /v1/deployments
deploymentsRouter.get('/', (c) => {
  const auth = c.get('auth');
  const projectId = c.req.query('projectId');

  let deployments = memoryDb.data.deployments.filter((d) => d.workspaceId === auth.workspaceId);
  if (projectId) deployments = deployments.filter((d) => d.projectId === projectId);

  return c.json({ data: deployments, requestId: c.get('requestId') });
});
