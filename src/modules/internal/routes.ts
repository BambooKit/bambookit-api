import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { memoryDb } from '../../db/memoryDb.js';
import { generateId } from '../../lib/crypto.js';
import { realtimeHub } from '../../realtime/events.js';

export const internalRouter = new Hono();

// Internal worker authentication middleware (Shared secret header)
internalRouter.use('*', async (c, next) => {
  const workerSecret = c.req.header('X-Worker-Secret');
  const expectedSecret = process.env.WORKER_SECRET || 'bambookit_default_internal_worker_secret_2026';

  if (!workerSecret || workerSecret !== expectedSecret) {
    // In dev mode allow test worker traffic if DEV_AUTH_ENABLED
    if (process.env.DEV_AUTH_ENABLED === 'true') {
      return next();
    }
    return c.json({ error: { code: 'UNAUTHORIZED_WORKER', message: 'Invalid or missing X-Worker-Secret' } }, 401);
  }
  await next();
});

const claimTaskSchema = z.object({
  workerId: z.string(),
  capabilities: z.array(z.string()).optional(),
});

const taskEventSchema = z.object({
  type: z.string(),
  summary: z.string(),
  payload: z.record(z.any()).optional(),
  severity: z.enum(['INFO', 'WARN', 'ERROR']).default('INFO'),
});

// POST /v1/internal/tasks/claim (Cloud worker leases next queued task)
internalRouter.post('/tasks/claim', zValidator('json', claimTaskSchema), (c) => {
  const { workerId } = c.req.valid('json');

  // Find next QUEUED task
  const task = memoryDb.data.tasks.find((t) => t.status === 'QUEUED');
  if (!task) {
    return c.json({ data: null, message: 'No queued tasks available', requestId: c.get('requestId') });
  }

  task.status = 'STARTING';
  task.startedAt = new Date();
  task.updatedAt = new Date();

  realtimeHub.broadcast(`task:${task.id}`, 'task.claimed', { taskId: task.id, workerId });

  return c.json({ data: task, requestId: c.get('requestId') });
});

// POST /v1/internal/tasks/:id/events (Worker streams execution events)
internalRouter.post('/tasks/:id/events', zValidator('json', taskEventSchema), (c) => {
  const taskId = c.req.param('id');
  const body = c.req.valid('json');

  const task = memoryDb.data.tasks.find((t) => t.id === taskId);
  if (!task) {
    return c.json({ error: { code: 'TASK_NOT_FOUND', message: 'Task not found' } }, 404);
  }

  const newEvent = {
    id: generateId('evt'),
    workspaceId: task.workspaceId,
    projectId: task.projectId,
    agentId: task.agentId,
    taskId: task.id,
    type: body.type,
    summary: body.summary,
    payload: body.payload || null,
    severity: body.severity,
    actor: 'AGENT',
    timestamp: new Date(),
  };

  memoryDb.data.events.push(newEvent);

  // Broadcast realtime stream
  realtimeHub.broadcast(`task:${task.id}`, 'agent.event', newEvent);

  return c.json({ data: newEvent, requestId: c.get('requestId') }, 201);
});

// POST /v1/internal/tasks/:id/complete (Worker reports task completed)
internalRouter.post('/tasks/:id/complete', (c) => {
  const taskId = c.req.param('id');
  const task = memoryDb.data.tasks.find((t) => t.id === taskId);
  if (!task) {
    return c.json({ error: { code: 'TASK_NOT_FOUND', message: 'Task not found' } }, 404);
  }

  task.status = 'COMPLETED';
  task.completedAt = new Date();
  task.updatedAt = new Date();

  realtimeHub.broadcast(`task:${task.id}`, 'task.completed', { taskId: task.id });

  return c.json({ data: task, requestId: c.get('requestId') });
});
