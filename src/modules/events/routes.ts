import { Hono } from 'hono';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';

export const eventsRouter = new Hono();

eventsRouter.use('*', authMiddleware);

// GET /v1/events
eventsRouter.get('/', (c) => {
  const auth = c.get('auth');
  const taskId = c.req.query('taskId');
  const agentId = c.req.query('agentId');
  const projectId = c.req.query('projectId');

  let events = memoryDb.data.events.filter((e) => e.workspaceId === auth.workspaceId);
  if (taskId) events = events.filter((e) => e.taskId === taskId);
  if (agentId) events = events.filter((e) => e.agentId === agentId);
  if (projectId) events = events.filter((e) => e.projectId === projectId);

  return c.json({ data: events, requestId: c.get('requestId') });
});
