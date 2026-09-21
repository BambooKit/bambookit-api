import { MiddlewareHandler } from 'hono';
import { generateId } from '../lib/crypto.js';

export const requestIdMiddleware: MiddlewareHandler = async (c, next) => {
  const requestId = c.req.header('X-Request-Id') || generateId('req');
  c.set('requestId', requestId);
  c.header('X-Request-Id', requestId);
  await next();
};
