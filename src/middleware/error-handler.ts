import { ErrorHandler } from 'hono';
import { ZodError } from 'zod';
import { logger } from '../lib/logger.js';

export const errorHandler: ErrorHandler = (err, c) => {
  const requestId = c.get('requestId') || 'unknown';

  if (err instanceof ZodError) {
    logger.warn('Validation error', { requestId, errors: err.errors });
    return c.json(
      {
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid request body or parameters',
          details: err.errors.map((e) => ({
            field: e.path.join('.'),
            message: e.message,
          })),
        },
        requestId,
      },
      400
    );
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
    500
  );
};
