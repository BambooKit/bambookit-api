import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db/database.js';
import { requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { HttpError, badRequest, forbidden, notFound } from '../lib/http.js';
import { commandPayloads, createCommand, resolveIssuer, type CommandType } from './commands.js';
import { serializeProject, serializeSession } from './serializers.js';
import { relay } from './relay.js';
import { partView, type PartSync } from './sync.js';

const SESSION_SELECT = `
  SELECT s.*, p.name AS project_name,
    (SELECT COUNT(*) FROM approvals a WHERE a.session_id = s.id AND a.status IN ('PENDING','RESPONDING')) AS pending_approvals
  FROM sessions s LEFT JOIN projects p ON p.id = s.project_id`;

async function ownedSession(userId: string, id: string): Promise<any> {
  const row = await db.get(`${SESSION_SELECT} WHERE s.id = ? AND s.user_id = ?`, id, userId);
  if (!row) throw notFound('Session');
  return row;
}

const desktopFor = (id: string) => db.get<DeviceRow>('SELECT * FROM devices WHERE id = ?', id);

// ---------------- Projects ----------------
export const projectsRouter = new Hono<AppEnv>();
projectsRouter.use('*', requireUser);

const PROJECT_SELECT = `
  SELECT p.*, d.name AS device_name,
    (SELECT COUNT(*) FROM sessions s WHERE s.project_id = p.id AND s.status IN ('busy','retry')) AS active_sessions,
    (SELECT COUNT(*) FROM sessions s WHERE s.project_id = p.id AND s.parent_opencode_session_id IS NULL) AS total_sessions
  FROM projects p JOIN devices d ON d.id = p.device_id`;

projectsRouter.get('/', async (c) => {
  const rows = await db.all(`${PROJECT_SELECT} WHERE p.user_id = ? AND d.revoked_at IS NULL ORDER BY p.updated_at DESC`, c.get('user').id);
  return c.json({ data: rows.map(serializeProject) });
});

projectsRouter.get('/:id', async (c) => {
  const row = await db.get(`${PROJECT_SELECT} WHERE p.id = ? AND p.user_id = ?`, c.req.param('id'), c.get('user').id);
  if (!row) throw notFound('Project');
  return c.json({ data: serializeProject(row) });
});

// New sessions are started on the PC; phones and the website continue sessions the PC has opened.
projectsRouter.post('/:id/sessions', () => {
  throw forbidden('Start new sessions in BambooKit Desktop on your PC, then continue them from your phone.', 'START_ON_PC');
});

// ---------------- Sessions ----------------
export const sessionsRouter = new Hono<AppEnv>();
sessionsRouter.use('*', requireUser);

// GET /v1/sessions?projectId=&deviceId=&active=true&includeChildren=false
sessionsRouter.get('/', async (c) => {
  const where = ['s.user_id = ?'];
  const args: string[] = [c.get('user').id];
  const projectId = c.req.query('projectId');
  const deviceId = c.req.query('deviceId');
  if (projectId) (where.push('s.project_id = ?'), args.push(projectId));
  if (deviceId) (where.push('s.device_id = ?'), args.push(deviceId));
  if (c.req.query('active') === 'true') where.push("s.status IN ('busy','retry')");
  if (c.req.query('includeChildren') !== 'true') where.push('s.parent_opencode_session_id IS NULL');
  const rows = await db.all(`${SESSION_SELECT} WHERE ${where.join(' AND ')} ORDER BY s.updated_at DESC LIMIT 200`, ...args);
  return c.json({ data: rows.map(serializeSession) });
});

sessionsRouter.get('/:id', async (c) => {
  return c.json({ data: serializeSession(await ownedSession(c.get('user').id, c.req.param('id'))) });
});

async function sessionDesktop(session: any) {
  const desktop = await desktopFor(session.device_id);
  if (!desktop || desktop.revoked_at) throw notFound('Device');
  return desktop;
}

// GET /v1/sessions/:id/parts — chat transcript, read live from the PC (never stored by the API)
sessionsRouter.get('/:id/parts', async (c) => {
  const user = c.get('user');
  const session = await ownedSession(user.id, c.req.param('id'));
  const res = (await relay(user.id, await sessionDesktop(session), 'transcript', { opencodeSessionId: session.opencode_session_id })) as { parts?: PartSync[] } | null;
  const ts = new Date().toISOString();
  return c.json({ data: (res?.parts ?? []).slice(-2000).map((p) => partView(session.id, p, ts)) });
});

// GET /v1/sessions/:id/changes — changed files summary, read live from the PC (patches: GET_DIFF command)
sessionsRouter.get('/:id/changes', async (c) => {
  const user = c.get('user');
  const session = await ownedSession(user.id, c.req.param('id'));
  const res = (await relay(user.id, await sessionDesktop(session), 'changes', { opencodeSessionId: session.opencode_session_id })) as { files?: unknown[] } | null;
  return c.json({ data: res?.files ?? [] });
});

// POST /v1/sessions/:id/commands { type, payload }
const userCommandTypes = [
  'SEND_MESSAGE', 'ABORT', 'CONTINUE', 'RETRY', 'GET_DIFF', 'REFRESH',
  'REVERT', 'UNREVERT', 'SHARE', 'UNSHARE', 'READ_FILE', 'WRITE_FILE',
] as const;
// GET /v1/sessions/:id/filemap — every file the session read, created, edited or deleted (live from the PC)
sessionsRouter.get('/:id/filemap', async (c) => {
  const user = c.get('user');
  const session = await ownedSession(user.id, c.req.param('id'));
  const res = (await relay(user.id, await sessionDesktop(session), 'filemap', { opencodeSessionId: session.opencode_session_id })) as { files?: unknown[] } | null;
  return c.json({ data: res?.files ?? [] });
});

// GET /v1/sessions/:id/diagram — the session's project drawn as components and real references (live from the PC)
sessionsRouter.get('/:id/diagram', async (c) => {
  const user = c.get('user');
  const session = await ownedSession(user.id, c.req.param('id'));
  return c.json({ data: await relay(user.id, await sessionDesktop(session), 'diagram', { opencodeSessionId: session.opencode_session_id }) });
});

// Commands that continue or change the conversation need the session to be continued on the PC first.
const continueCommands = new Set(['SEND_MESSAGE', 'CONTINUE', 'RETRY', 'REVERT', 'UNREVERT', 'WRITE_FILE']);

sessionsRouter.post('/:id/commands', async (c) => {
  const user = c.get('user');
  const session = await ownedSession(user.id, c.req.param('id'));
  const body = z.object({ type: z.enum(userCommandTypes), payload: z.unknown().optional() }).parse(await c.req.json());
  if (!(body.type in commandPayloads)) throw badRequest('Unknown command');
  if (continueCommands.has(body.type) && !Number(session.remote)) {
    throw new HttpError(409, 'SESSION_NOT_CONTINUED', 'Continue this session on your PC first, then you can chat in it from here.');
  }
  const issuer = await resolveIssuer(user.id, c.req.header('X-BK-Device-Id'));
  const res = await createCommand({
    userId: user.id,
    desktop: await desktopFor(session.device_id),
    sessionId: session.id,
    issuer,
    type: body.type as CommandType,
    payload: body.payload ?? {},
  });
  return c.json({ data: res.command, deviceOnline: res.deviceOnline }, 202);
});
