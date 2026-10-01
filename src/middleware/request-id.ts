import { MiddlewareHandler } from 'hono';
import { newId } from '../lib/http.js';

export const requestIdMiddleware: MiddlewareHandler = async (c, next) => {
  const requestId = c.req.header('X-Request-Id') || newId('req');
  c.set('requestId', requestId);
  c.header('X-Request-Id', requestId);
  await next();
};
