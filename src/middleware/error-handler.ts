import { ErrorHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { ZodError } from 'zod';
import { HttpError } from '../lib/http.js';
import { logger } from '../lib/logger.js';

export const errorHandler: ErrorHandler = (err, c) => {
  const requestId = c.get('requestId') || 'unknown';

  if (err instanceof HttpError) {
    if (err.status >= 500) logger.error(err.message, { requestId, code: err.code });
    return c.json({ error: { code: err.code, message: err.message }, requestId }, err.status);
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
