import { serve } from '@hono/node-server';
import { app } from './app.js';
import { env, VERSION } from './config/env.js';
import { logger } from './lib/logger.js';

logger.info(`Starting BambooKit API v${VERSION}`, {
  port: env.PORT,
  environment: env.NODE_ENV,
  database: env.DATABASE_PATH,
  supabase: env.SUPABASE_URL,
});

serve({ fetch: app.fetch, port: env.PORT, hostname: '0.0.0.0' }, (info) => {
  logger.info(`BambooKit API listening on http://localhost:${info.port}`);
});
