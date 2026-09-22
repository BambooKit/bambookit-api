import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';
import { generateId } from '../../lib/crypto.js';

export const sessionsRouter = new Hono();

sessionsRouter.use('*', authMiddleware);

const registerSessionSchema = z.object({
  id: z.string(),
  deviceId: z.string(),
  title: z.string().optional(),
  status: z.string().optional(),
  agentName: z.string().optional(),
  model: z.string().optional(),
  projectPath: z.string().optional(),
  fileChanges: z.array(z.any()).optional(),
  tests: z.string().optional(),
});

const remoteMessageSchema = z.object({
  prompt: z.string().min(1),
  agentId: z.string().optional(),
});

// GET /v1/sessions
sessionsRouter.get('/', (c) => {
  const auth = c.get('auth');
  const sessions = memoryDb.data.sessions || [];
  return c.json({ data: sessions, requestId: c.get('requestId') });
});

// GET /v1/sessions/:id
sessionsRouter.get('/:id', (c) => {
  const id = c.req.param('id');
  const session = (memoryDb.data.sessions || []).find((s) => s.id === id);
  if (!session) {
    return c.json({ error: { code: 'SESSION_NOT_FOUND', message: 'Session not found' } }, 404);
  }
  return c.json({ data: session, requestId: c.get('requestId') });
});

// POST /v1/sessions (Desktop registers / updates OpenCode session)
sessionsRouter.post('/', zValidator('json', registerSessionSchema), (c) => {
  const body = c.req.valid('json');
  memoryDb.data.sessions = memoryDb.data.sessions || [];

  const existingIdx = memoryDb.data.sessions.findIndex((s) => s.id === body.id);
  const sessionRecord = {
    id: body.id,
    deviceId: body.deviceId,
    title: body.title || 'OpenCode Autonomous Session',
    status: body.status || 'RUNNING',
    agentName: body.agentName || 'OpenCode',
    model: body.model || 'auto',
    projectPath: body.projectPath || process.cwd(),
    fileChanges: body.fileChanges || [],
    tests: body.tests || 'IDLE',
    updatedAt: new Date().toISOString(),
  };

  if (existingIdx >= 0) {
    memoryDb.data.sessions[existingIdx] = { ...memoryDb.data.sessions[existingIdx], ...sessionRecord };
  } else {
    memoryDb.data.sessions.unshift(sessionRecord);
  }

  return c.json({ data: sessionRecord, requestId: c.get('requestId') }, 200);
});

// POST /v1/sessions/:id/message (Android sends remote directive to OpenCode session)
sessionsRouter.post('/:id/message', zValidator('json', remoteMessageSchema), (c) => {
  const sessionId = c.req.param('id');
  const body = c.req.valid('json');
  const auth = c.get('auth');

  const session = (memoryDb.data.sessions || []).find((s) => s.id === sessionId);
  const targetDeviceId = session?.deviceId || 'dev_win_default';

  memoryDb.data.deviceCommands = memoryDb.data.deviceCommands || [];
  const commandRecord = {
    id: generateId('cmd'),
    deviceId: targetDeviceId,
    sessionId,
    type: 'SEND_MESSAGE',
    payload: { prompt: body.prompt, agentId: body.agentId },
    status: 'QUEUED',
    createdAt: new Date().toISOString(),
  };

  memoryDb.data.deviceCommands.push(commandRecord);

  // Also record as a task / event in BambooKit control plane
  const newTask = {
    id: generateId('task'),
    workspaceId: auth.workspaceId,
    projectId: 'proj_bambookit_web',
    title: body.prompt.length > 60 ? `${body.prompt.slice(0, 57)}...` : body.prompt,
    prompt: body.prompt,
    agentId: 'agent_opencode_01',
    status: 'RUNNING',
    executionMode: 'LOCAL',
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  memoryDb.data.tasks.unshift(newTask as any);

  return c.json({
    data: {
      commandId: commandRecord.id,
      sessionId,
      status: 'DISPATCHED_TO_DESKTOP',
      task: newTask,
    },
    message: 'Directive forwarded to Windows OpenCode workstation',
    requestId: c.get('requestId'),
  }, 200);
});

// GET /v1/sessions/:id/events (Get events for session)
sessionsRouter.get('/:id/events', (c) => {
  const sessionId = c.req.param('id');
  const events = (memoryDb.data.events || []).filter((e: any) => e.sessionId === sessionId || e.taskId === sessionId);
  return c.json({ data: events, requestId: c.get('requestId') });
});
