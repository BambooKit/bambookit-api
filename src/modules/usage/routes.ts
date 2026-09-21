import { Hono } from 'hono';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';

export const usageRouter = new Hono();

usageRouter.use('*', authMiddleware);

// GET /v1/usage
usageRouter.get('/', (c) => {
  const auth = c.get('auth');
  const usage = memoryDb.data.usage;

  return c.json({
    data: {
      ...usage,
      budgetCapUsd: '75.00',
      percentBudgetUsed: 58,
    },
    requestId: c.get('requestId'),
  });
});
