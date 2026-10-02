import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { env, VERSION } from './config/env.js';
import { db } from './db/database.js';
import { requestIdMiddleware } from './middleware/request-id.js';
import { loggingMiddleware } from './middleware/logging.js';
import { errorHandler } from './middleware/error-handler.js';
import type { AppEnv } from './middleware/auth.js';
import { accountRouter } from './modules/account.js';
import { devicesRouter } from './modules/devices.js';
import { pairingRouter } from './modules/pairing.js';
import { projectsRouter, sessionsRouter } from './modules/sessions.js';
import { commandsRouter } from './modules/commands.js';
import { approvalsRouter } from './modules/approvals.js';
import { notificationsRouter } from './modules/notifications.js';
import { syncRouter } from './modules/sync.js';
import { realtimeRouter } from './modules/realtime.js';
import { sharesRouter } from './modules/shares.js';
import { relayRouter } from './modules/relay.js';

export const app = new Hono<AppEnv>();

app.use('*', requestIdMiddleware);
app.use('*', loggingMiddleware);

const allowedOrigins = env.CORS_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean);
app.use(
  '*',
  cors({
    // Only echo origins that are explicitly allowed. Native apps send no Origin header.
    origin: (origin) => (origin && allowedOrigins.includes(origin) ? origin : null),
    allowMethods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Request-Id', 'X-BK-Device-Id', 'X-BK-Timestamp', 'X-BK-Signature', 'Last-Event-ID'],
    exposeHeaders: ['X-Request-Id'],
  }),
);

app.onError(errorHandler);

const COMMIT = process.env.RENDER_GIT_COMMIT?.slice(0, 7) ?? null;
app.get('/health', (c) => c.json({ status: 'ok', service: 'bambookit-api', version: VERSION, commit: COMMIT, timestamp: new Date().toISOString() }));
app.get('/ready', async (c) => {
  try {
    await db.ping();
    return c.json({ status: 'ready', database: db.dialect });
  } catch (err: any) {
    return c.json({ status: 'not_ready', database: err.message }, 503);
  }
});

const v1 = new Hono<AppEnv>();
v1.route('/', accountRouter); // /me, /overview, /activity
v1.route('/devices', devicesRouter);
v1.route('/pairing', pairingRouter);
v1.route('/projects', projectsRouter);
v1.route('/sessions', sessionsRouter);
v1.route('/commands', commandsRouter);
v1.route('/approvals', approvalsRouter);
v1.route('/notifications', notificationsRouter);
v1.route('/sync', syncRouter);
v1.route('/realtime', realtimeRouter);
v1.route('/relay', relayRouter);

app.route('/v1', v1);
// Public session sharing (OpenCode share protocol + viewer). No user auth: secrets authorize writes.
app.route('/', sharesRouter);
app.notFound((c) => c.json({ error: { code: 'NOT_FOUND', message: 'Route not found' } }, 404));
