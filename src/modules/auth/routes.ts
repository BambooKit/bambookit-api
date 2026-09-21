import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { generateId, hashPassword, comparePassword, signToken } from '../../lib/crypto.js';
import { memoryDb } from '../../db/memoryDb.js';

export const authRouter = new Hono();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(2),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

// POST /v1/auth/register
authRouter.post('/register', zValidator('json', registerSchema), async (c) => {
  const { email, password, name } = c.req.valid('json');

  if (memoryDb.data.user.email === email) {
    return c.json({ error: { code: 'USER_EXISTS', message: 'User with this email already exists' } }, 409);
  }

  const passwordHash = await hashPassword(password);
  const newUser = {
    id: generateId('usr'),
    email,
    passwordHash,
    name,
    avatarUrl: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const newWorkspace = {
    id: generateId('ws'),
    name: `${name}'s Workspace`,
    slug: `${name.toLowerCase().replace(/\s+/g, '-')}-ws`,
    ownerId: newUser.id,
    tier: 'FREE',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  memoryDb.data.user = newUser;
  memoryDb.data.workspace = newWorkspace;

  const token = signToken({
    userId: newUser.id,
    email: newUser.email,
    name: newUser.name,
    workspaceId: newWorkspace.id,
    role: 'OWNER',
  });

  return c.json({
    data: {
      user: { id: newUser.id, email: newUser.email, name: newUser.name },
      workspace: newWorkspace,
      token,
    },
    requestId: c.get('requestId'),
  });
});

// POST /v1/auth/login
authRouter.post('/login', zValidator('json', loginSchema), async (c) => {
  const { email, password } = c.req.valid('json');

  if (email !== memoryDb.data.user.email) {
    return c.json({ error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' } }, 401);
  }

  const token = signToken({
    userId: memoryDb.data.user.id,
    email: memoryDb.data.user.email,
    name: memoryDb.data.user.name,
    workspaceId: memoryDb.data.workspace.id,
    role: 'OWNER',
  });

  return c.json({
    data: {
      user: { id: memoryDb.data.user.id, email: memoryDb.data.user.email, name: memoryDb.data.user.name },
      workspace: memoryDb.data.workspace,
      token,
    },
    requestId: c.get('requestId'),
  });
});
