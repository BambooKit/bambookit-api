import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';
import { generateId } from '../../lib/crypto.js';
import { realtimeHub } from '../../realtime/events.js';

export const tasksRouter = new Hono();

tasksRouter.use('*', authMiddleware);

const createTaskSchema = z.object({
  projectId: z.string(),
  agentId: z.string(),
  title: z.string().min(3),
  prompt: z.string().min(5),
  executionMode: z.enum(['CLOUD', 'LOCAL']).default('CLOUD'),
});

// GET /v1/tasks
tasksRouter.get('/', (c) => {
  const auth = c.get('auth');
  const projectId = c.req.query('projectId');
  const agentId = c.req.query('agentId');

  let tasks = memoryDb.data.tasks.filter((t) => t.workspaceId === auth.workspaceId);
  if (projectId) tasks = tasks.filter((t) => t.projectId === projectId);
  if (agentId) tasks = tasks.filter((t) => t.agentId === agentId);

  return c.json({ data: tasks, requestId: c.get('requestId') });
});

// GET /v1/tasks/:id
tasksRouter.get('/:id', (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');

  const task = memoryDb.data.tasks.find((t) => t.id === id && t.workspaceId === auth.workspaceId);
  if (!task) {
    return c.json({ error: { code: 'TASK_NOT_FOUND', message: 'Task not found' } }, 404);
  }

  return c.json({ data: task, requestId: c.get('requestId') });
});

// POST /v1/tasks
tasksRouter.post('/', zValidator('json', createTaskSchema), (c) => {
  const auth = c.get('auth');
  const body = c.req.valid('json');

  const newTask = {
    id: generateId('task'),
    workspaceId: auth.workspaceId,
    projectId: body.projectId,
    agentId: body.agentId,
    title: body.title,
    prompt: body.prompt,
    status: 'QUEUED' as const,
    executionMode: body.executionMode,
    branch: `feat/task-${Date.now().toString().slice(-4)}`,
    commitSha: null,
    startedAt: null,
    completedAt: null,
    error: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  memoryDb.data.tasks.unshift(newTask);

  // Broadcast realtime event
  realtimeHub.broadcast(`workspace:${auth.workspaceId}`, 'task.created', newTask);

  return c.json({ data: newTask, requestId: c.get('requestId') }, 201);
});

// POST /v1/tasks/:id/cancel
tasksRouter.post('/:id/cancel', (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');

  const task = memoryDb.data.tasks.find((t) => t.id === id && t.workspaceId === auth.workspaceId);
  if (!task) {
    return c.json({ error: { code: 'TASK_NOT_FOUND', message: 'Task not found' } }, 404);
  }

  task.status = 'CANCELLED';
  task.completedAt = new Date();
  task.updatedAt = new Date();

  realtimeHub.broadcast(`task:${task.id}`, 'task.cancelled', { taskId: task.id });

  return c.json({ data: task, requestId: c.get('requestId') });
});
