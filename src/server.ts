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

// '::' listens on IPv6 and IPv4 (dual stack), so both localhost and 127.0.0.1 work.
serve({ fetch: app.fetch, port: env.PORT, hostname: '::' }, (info) => {
  logger.info(`BambooKit API listening on http://localhost:${info.port}`);
});
