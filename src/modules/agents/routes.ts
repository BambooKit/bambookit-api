import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';
import { generateId } from '../../lib/crypto.js';
import { realtimeHub } from '../../realtime/events.js';

export const agentsRouter = new Hono();

agentsRouter.use('*', authMiddleware);

const createAgentSchema = z.object({
  projectId: z.string(),
  name: z.string().min(2),
  description: z.string().optional(),
  provider: z.enum(['OPENAI', 'ANTHROPIC', 'GOOGLE', 'OPENROUTER', 'OLLAMA', 'CUSTOM']),
  model: z.string(),
  agentType: z.enum(['CODING', 'DEBUGGING', 'REFACTORING', 'TESTING', 'DOCUMENTATION', 'DEPLOYMENT', 'CUSTOM']).default('CODING'),
  executionMode: z.enum(['CLOUD', 'LOCAL']).default('CLOUD'),
});

// GET /v1/agents
agentsRouter.get('/', (c) => {
  const auth = c.get('auth');
  const projectId = c.req.query('projectId');

  let agents = memoryDb.data.agents.filter((a) => a.workspaceId === auth.workspaceId);
  if (projectId) {
    agents = agents.filter((a) => a.projectId === projectId);
  }

  return c.json({ data: agents, requestId: c.get('requestId') });
});

// GET /v1/agents/:id
agentsRouter.get('/:id', (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');

  const agent = memoryDb.data.agents.find((a) => a.id === id && a.workspaceId === auth.workspaceId);
  if (!agent) {
    return c.json({ error: { code: 'AGENT_NOT_FOUND', message: 'Agent not found' } }, 404);
  }

  return c.json({ data: agent, requestId: c.get('requestId') });
});

// POST /v1/agents
agentsRouter.post('/', zValidator('json', createAgentSchema), (c) => {
  const auth = c.get('auth');
  const body = c.req.valid('json');

  const newAgent = {
    id: generateId('agent'),
    workspaceId: auth.workspaceId,
    projectId: body.projectId,
    name: body.name,
    description: body.description || null,
    agentType: body.agentType,
    provider: body.provider,
    model: body.model,
    status: 'IDLE' as const,
    executionMode: body.executionMode,
    permissionPolicyId: 'pol_default',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  memoryDb.data.agents.unshift(newAgent);

  return c.json({ data: newAgent, requestId: c.get('requestId') }, 201);
});

// POST /v1/agents/:id/stop
agentsRouter.post('/:id/stop', (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');

  const agent = memoryDb.data.agents.find((a) => a.id === id && a.workspaceId === auth.workspaceId);
  if (!agent) {
    return c.json({ error: { code: 'AGENT_NOT_FOUND', message: 'Agent not found' } }, 404);
  }

  agent.status = 'IDLE';
  agent.updatedAt = new Date();

  realtimeHub.broadcast(`agent:${agent.id}`, 'agent.stopped', { agentId: agent.id });

  return c.json({ data: agent, requestId: c.get('requestId') });
});
