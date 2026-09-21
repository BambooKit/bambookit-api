import { serve } from '@hono/node-server';
import { app } from './app.js';
import { env } from './config/env.js';
import { logger } from './lib/logger.js';
import { CONSTANTS } from './config/constants.js';

const port = env.PORT;

logger.info(`Starting ${CONSTANTS.APP_NAME} v${CONSTANTS.VERSION}...`, {
  port,
  environment: env.NODE_ENV,
});

serve(
  {
    fetch: app.fetch,
    port,
  },
  (info) => {
    logger.info(`BambooKit API Server listening on http://localhost:${info.port}`);
  }
);
