import { recordServerError } from '../lib/monitor.js';
import { ErrorHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { ZodError } from 'zod';
import { HttpError } from '../lib/http.js';
import { logger } from '../lib/logger.js';

function remember(c: any, status: number, code: string, message: string, requestId: string) {
  recordServerError({
    at: new Date().toISOString(),
    method: c.req.method,
    path: c.req.path,
    status,
    code,
    message: String(message ?? '').slice(0, 300),
    requestId,
    client: c.req.header('X-BK-Client')?.slice(0, 60) ?? null,
  });
}

export const errorHandler: ErrorHandler = (err, c) => {
  const requestId = c.get('requestId') || 'unknown';

  if (err instanceof HttpError) {
    if (err.status >= 500) {
      logger.error(err.message, { requestId, code: err.code });
      // Relay outcomes (PC offline/timeout) are expected, not server faults.
      if (!['DESKTOP_OFFLINE', 'DESKTOP_TIMEOUT'].includes(err.code)) remember(c, err.status, err.code, err.message, requestId);
    }
    return c.json({ error: { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) }, requestId }, err.status);
  }

  if (err instanceof ZodError) {
    return c.json(
      {
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid request body or parameters',
          details: err.errors.map((e) => ({ field: e.path.join('.'), message: e.message })),
        },
        requestId,
      },
      400,
    );
  }

  if (err instanceof SyntaxError) {
    return c.json({ error: { code: 'INVALID_JSON', message: 'Request body is not valid JSON' }, requestId }, 400);
  }

  if (err instanceof HTTPException) {
    return c.json({ error: { code: 'HTTP_ERROR', message: err.message }, requestId }, err.status);
  }

  remember(c, 500, 'INTERNAL_SERVER_ERROR', err.message, requestId);
  logger.error('Unhandled server error', {
    requestId,
    error: err.message,
    stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined,
  });

  return c.json(
    {
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: process.env.NODE_ENV === 'production' ? 'An unexpected internal error occurred' : err.message,
      },
      requestId,
    },
    500,
  );
};
