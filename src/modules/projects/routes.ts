import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';
import { generateId } from '../../lib/crypto.js';

export const projectsRouter = new Hono();

projectsRouter.use('*', authMiddleware);

const createProjectSchema = z.object({
  name: z.string().min(2),
  description: z.string().optional(),
  executionMode: z.enum(['CLOUD', 'LOCAL', 'HYBRID']).default('CLOUD'),
  defaultBranch: z.string().default('main'),
});

// GET /v1/projects
projectsRouter.get('/', (c) => {
  const auth = c.get('auth');
  // Workspace isolation filter
  const projects = memoryDb.data.projects.filter((p) => p.workspaceId === auth.workspaceId);

  return c.json({
    data: projects,
    requestId: c.get('requestId'),
  });
});

// GET /v1/projects/:id
projectsRouter.get('/:id', (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');

  const project = memoryDb.data.projects.find(
    (p) => (p.id === id || p.slug === id) && p.workspaceId === auth.workspaceId
  );

  if (!project) {
    return c.json({ error: { code: 'PROJECT_NOT_FOUND', message: 'Project not found in current workspace' } }, 404);
  }

  return c.json({ data: project, requestId: c.get('requestId') });
});

// POST /v1/projects
projectsRouter.post('/', zValidator('json', createProjectSchema), (c) => {
  const auth = c.get('auth');
  const body = c.req.valid('json');

  const newProject = {
    id: generateId('proj'),
    workspaceId: auth.workspaceId,
    repositoryId: null,
    name: body.name,
    slug: body.name.toLowerCase().replace(/\s+/g, '-'),
    description: body.description || null,
    executionMode: body.executionMode,
    defaultBranch: body.defaultBranch,
    status: 'ACTIVE',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  memoryDb.data.projects.unshift(newProject);

  return c.json({ data: newProject, requestId: c.get('requestId') }, 201);
});
