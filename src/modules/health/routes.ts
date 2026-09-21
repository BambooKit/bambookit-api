import { Hono } from 'hono';
import { CONSTANTS } from '../../config/constants.js';

export const healthRouter = new Hono();

// GET /health
healthRouter.get('/health', (c) => {
  return c.json({
    status: 'ok',
    service: 'bambookit-api',
    version: CONSTANTS.VERSION,
    timestamp: new Date().toISOString(),
  });
});

// GET /ready
healthRouter.get('/ready', (c) => {
  return c.json({
    status: 'ready',
    database: 'healthy',
    eventRelay: 'operational',
    timestamp: new Date().toISOString(),
  });
});

// GET /live
healthRouter.get('/live', (c) => {
  return c.json({ status: 'live' });
});
