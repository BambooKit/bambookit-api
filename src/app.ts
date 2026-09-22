import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { env } from './config/env.js';
import { CONSTANTS } from './config/constants.js';
import { requestIdMiddleware } from './middleware/request-id.js';
import { loggingMiddleware } from './middleware/logging.js';
import { errorHandler } from './middleware/error-handler.js';

// Feature routers
import { healthRouter } from './modules/health/routes.js';
import { authRouter } from './modules/auth/routes.js';
import { workspacesRouter } from './modules/workspaces/routes.js';
import { projectsRouter } from './modules/projects/routes.js';
import { agentsRouter } from './modules/agents/routes.js';
import { tasksRouter } from './modules/tasks/routes.js';
import { approvalsRouter } from './modules/approvals/routes.js';
import { eventsRouter } from './modules/events/routes.js';
import { permissionsRouter } from './modules/permissions/routes.js';
import { providersRouter } from './modules/providers/routes.js';
import { devicesRouter } from './modules/devices/routes.js';
import { deploymentsRouter } from './modules/deployments/routes.js';
import { usageRouter } from './modules/usage/routes.js';
import { activityRouter } from './modules/activity/routes.js';
import { notificationsRouter } from './modules/notifications/routes.js';
import { storageRouter } from './modules/storage/routes.js';
import { internalRouter } from './modules/internal/routes.js';
import { realtimeRouter } from './realtime/routes.js';

export const app = new Hono();


// Global Middlewares
app.use('*', requestIdMiddleware);
app.use('*', loggingMiddleware);

const allowedOrigins = env.CORS_ORIGINS.split(',').map((o) => o.trim());
app.use(
  '*',
  cors({
    origin: (origin) => {
      if (!origin || allowedOrigins.includes(origin)) return origin;
      return allowedOrigins[0];
    },
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Request-Id', 'X-Workspace-Id', 'X-Worker-Secret'],
    exposeHeaders: ['X-Request-Id'],
    credentials: true,
  })
);

app.onError(errorHandler);

// Root health checks
app.route('/', healthRouter);

// OpenAPI specification endpoint
app.get('/openapi.json', (c) => {
  return c.json({
    openapi: '3.0.0',
    info: {
      title: CONSTANTS.APP_NAME,
      version: CONSTANTS.VERSION,
      description: 'Control Plane for Autonomous AI Software Engineers',
    },
    paths: {
      '/v1/auth/login': { post: { summary: 'Authenticate developer' } },
      '/v1/projects': { get: { summary: 'List workspace projects' }, post: { summary: 'Create project' } },
      '/v1/agents': { get: { summary: 'List agents' }, post: { summary: 'Create agent' } },
      '/v1/tasks': { get: { summary: 'List tasks' }, post: { summary: 'Dispatch task' } },
      '/v1/approvals': { get: { summary: 'List approvals' } },
      '/v1/approvals/{id}/respond': { post: { summary: 'Approve or reject dangerous action' } },
      '/v1/providers': { get: { summary: 'List configured BYOK providers' } },
      '/v1/devices': { get: { summary: 'List paired remote devices' } },
      '/v1/realtime/stream': { get: { summary: 'Server-Sent Events telemetry feed' } },
      '/v1/internal/tasks/claim': { post: { summary: 'Worker lease endpoint' } },
    },
  });
});

// Mount /v1 API Endpoints
const v1 = new Hono();
v1.route('/auth', authRouter);
v1.route('/workspaces', workspacesRouter);
v1.route('/projects', projectsRouter);
v1.route('/agents', agentsRouter);
v1.route('/tasks', tasksRouter);
v1.route('/approvals', approvalsRouter);
v1.route('/events', eventsRouter);
v1.route('/permissions', permissionsRouter);
v1.route('/providers', providersRouter);
v1.route('/devices', devicesRouter);
v1.route('/deployments', deploymentsRouter);
v1.route('/usage', usageRouter);
v1.route('/activity', activityRouter);
v1.route('/notifications', notificationsRouter);
v1.route('/internal', internalRouter);
v1.route('/realtime', realtimeRouter);
v1.route('/storage', storageRouter);

app.route('/v1', v1);

