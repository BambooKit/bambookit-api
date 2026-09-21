import { MiddlewareHandler } from 'hono';
import { logger } from '../lib/logger.js';

export const loggingMiddleware: MiddlewareHandler = async (c, next) => {
  const start = Date.now();
  const requestId = c.get('requestId') || 'unknown';

  await next();

  const duration = Date.now() - start;
  const status = c.res.status;

  logger.info(`${c.req.method} ${c.req.path} ${status} - ${duration}ms`, {
    requestId,
    method: c.req.method,
    path: c.req.path,
    status,
    durationMs: duration,
    userId: c.get('auth')?.userId,
    workspaceId: c.get('auth')?.workspaceId,
  });
};
