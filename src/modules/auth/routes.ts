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

const googleVerifySchema = z.object({
  idToken: z.string().min(10),
});

// POST /v1/auth/google/verify
// Verifies Google ID token, authenticates or provisions BambooKit account
authRouter.post('/google/verify', zValidator('json', googleVerifySchema), async (c) => {
  const { idToken } = c.req.valid('json');

  try {
    // 1. Verify token against Google tokeninfo endpoint
    const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
    if (!response.ok) {
      return c.json({ error: { code: 'INVALID_GOOGLE_TOKEN', message: 'Failed to verify Google identity token' } }, 401);
    }

    const payload = (await response.json()) as {
      sub: string;
      email: string;
      name?: string;
      picture?: string;
      aud: string;
    };

    // 2. Associate or create BambooKit user
    let user = memoryDb.data.user;
    if (user.email !== payload.email) {
      user = {
        id: generateId('usr'),
        email: payload.email,
        passwordHash: null,
        name: payload.name || payload.email.split('@')[0],
        avatarUrl: payload.picture || null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      memoryDb.data.user = user;
    }

    const token = signToken({
      userId: user.id,
      email: user.email,
      name: user.name,
      workspaceId: memoryDb.data.workspace.id,
      role: 'OWNER',
    });

    return c.json({
      data: {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          avatarUrl: user.avatarUrl,
        },
        workspace: memoryDb.data.workspace,
        token,
      },
      requestId: c.get('requestId'),
    });
  } catch (err: any) {
    return c.json({ error: { code: 'GOOGLE_AUTH_ERROR', message: err.message } }, 500);
  }
});

// GET /v1/auth/me
authRouter.get('/me', (c) => {
  const user = memoryDb.data.user;
  const workspace = memoryDb.data.workspace;
  return c.json({
    data: {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
      },
      workspace: {
        id: workspace.id,
        name: workspace.name,
        slug: workspace.slug,
        tier: workspace.tier,
      },
    },
    requestId: c.get('requestId'),
  });
});

