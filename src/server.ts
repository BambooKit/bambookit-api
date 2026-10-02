import { serve } from '@hono/node-server';
import { app } from './app.js';
import { env, VERSION } from './config/env.js';
import { logger } from './lib/logger.js';

logger.info(`Starting BambooKit API v${VERSION}`, {
  port: env.PORT,
  environment: env.NODE_ENV,
  database: env.POSTGRES_URL ? 'postgres' : env.DATABASE_PATH,
  supabase: env.SUPABASE_URL,
});

// '::' listens on IPv6 and IPv4 (dual stack), so both localhost and 127.0.0.1 work.
serve({ fetch: app.fetch, port: env.PORT, hostname: '::' }, (info) => {
  logger.info(`BambooKit API listening on http://localhost:${info.port}`);
});

// Render's free tier stops a web service after 15 minutes without inbound traffic. Requesting our
// own public URL goes through Render's proxy and counts as traffic, so once awake the API stays up
// 24/7 (one always-on service fits in the 750 free instance hours a month). /ready also touches the
// database, which keeps a free Supabase project from pausing for inactivity.
const selfUrl = process.env.KEEP_ALIVE_URL ?? process.env.RENDER_EXTERNAL_URL;
if (selfUrl && process.env.KEEP_ALIVE !== 'off') {
  const ping = () =>
    fetch(`${selfUrl.replace(/\/+$/, '')}/ready`, { signal: AbortSignal.timeout(30_000) })
      .then((res) => logger.debug('keep-alive', { status: res.status }))
      .catch((err) => logger.warn('keep-alive ping failed', { error: String(err?.message ?? err) }));
  setInterval(ping, 10 * 60_000).unref();
  logger.info('Keep-alive enabled', { url: selfUrl, everyMinutes: 10 });
}
