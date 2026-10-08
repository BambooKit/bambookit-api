import { MiddlewareHandler } from 'hono';
import { logger } from '../lib/logger.js';
import { API_VERSION } from '../lib/compat.js';
import { recordRequest } from '../lib/monitor.js';

export const loggingMiddleware: MiddlewareHandler = async (c, next) => {
  const start = Date.now();
  const requestId = c.get('requestId') || 'unknown';

  await next();
  try {
    c.res.headers.set('X-BambooKit-API', API_VERSION);
  } catch {
    // Streaming responses can have immutable headers.
  }

  const duration = Date.now() - start;
  const status = c.res.status;
  recordRequest(status, c.get('expectedError') === true);

  logger.info(`${c.req.method} ${c.req.path} ${status} - ${duration}ms`, {
    requestId,
    method: c.req.method,
    path: c.req.path,
    status,
    durationMs: duration,
    userId: c.get('user')?.id,
    // e.g. "android/1.0.6", "desktop/1.0.3", "web/1.0.1" — sent by BambooKit clients (no secrets).
    client: c.req.header('X-BK-Client')?.slice(0, 60),
  });
};
