import { Context, MiddlewareHandler } from 'hono';
import { verifyToken } from '../lib/crypto.js';
import { env } from '../config/env.js';
import { memoryDb } from '../db/memoryDb.js';

export interface AuthContext {
  userId: string;
  email: string;
  name: string;
  workspaceId: string;
  role: 'OWNER' | 'ADMIN' | 'DEVELOPER' | 'VIEWER';
}

declare module 'hono' {
  interface ContextVariableMap {
    auth: AuthContext;
    requestId: string;
  }
}

export const authMiddleware: MiddlewareHandler = async (c, next) => {
  const authHeader = c.req.header('Authorization');

  // 1. Bearer Token Authentication
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const decoded = verifyToken<AuthContext>(token);

    if (decoded && decoded.userId) {
      c.set('auth', decoded);
      return next();
    }
  }

  // 2. Explicit Development Mode Bypass (Guarded by DEV_AUTH_ENABLED)
  if (env.DEV_AUTH_ENABLED && env.NODE_ENV !== 'production') {
    const devWorkspaceHeader = c.req.header('X-Workspace-Id');
    c.set('auth', {
      userId: memoryDb.data.user.id,
      email: memoryDb.data.user.email,
      name: memoryDb.data.user.name,
      workspaceId: devWorkspaceHeader || memoryDb.data.workspace.id,
      role: 'OWNER',
    });
    return next();
  }

  return c.json(
    {
      error: {
        code: 'UNAUTHORIZED',
        message: 'Missing or invalid authentication token. Provide Authorization: Bearer <token>',
      },
      requestId: c.get('requestId') || 'unknown',
    },
    401
  );
};

export function requireRole(...allowedRoles: Array<'OWNER' | 'ADMIN' | 'DEVELOPER' | 'VIEWER'>): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.get('auth');
    if (!auth) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } }, 401);
    }

    if (!allowedRoles.includes(auth.role)) {
      return c.json(
        {
          error: {
            code: 'FORBIDDEN',
            message: `Insufficient permissions. Required one of: ${allowedRoles.join(', ')}`,
          },
          requestId: c.get('requestId'),
        },
        403
      );
    }

    return next();
  };
}
