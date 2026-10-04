import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db/database.js';
import { requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { HttpError, badRequest, forbidden, notFound } from '../lib/http.js';
import { commandPayloads, createCommand, resolveIssuer, type CommandType } from './commands.js';
import { serializeProject, serializeSession } from './serializers.js';
import { relay } from './relay.js';
import { publish } from '../realtime/bus.js';
import { transcriptPartView, type PartSync } from './sync.js';

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

// POST /v1/projects/:id/sessions { text, model?, agent? } — start a session on the PC that owns the project.
// The PC creates it in the project's folder and marks it continued, so the phone can keep chatting in it.
projectsRouter.post('/:id/sessions', async (c) => {
  const user = c.get('user');
  const project = await db.get(`${PROJECT_SELECT} WHERE p.id = ? AND p.user_id = ?`, c.req.param('id'), user.id);
  if (!project) throw notFound('Project');
  const body = z
    .object({ text: z.string().min(1).max(20_000), model: z.object({ providerID: z.string().min(1).max(200), modelID: z.string().min(1).max(300) }).optional(), agent: z.string().min(1).max(100).optional() })
    .parse(await c.req.json());
  const res = await createCommand({
    userId: user.id,
    desktop: await desktopFor(project.device_id),
    sessionId: null,
    issuer: await resolveIssuer(user.id, c.req.header('X-BK-Device-Id')),
    type: 'CREATE_SESSION',
    payload: { directory: project.directory, ...body },
  });
  return c.json({ data: res.command, deviceOnline: res.deviceOnline }, 202);
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
  if (c.req.query('starred') === 'true') where.push('s.starred = 1');
  if (c.req.query('includeChildren') !== 'true') where.push('s.parent_opencode_session_id IS NULL');
  const rows = await db.all(`${SESSION_SELECT} WHERE ${where.join(' AND ')} ORDER BY s.updated_at DESC LIMIT 200`, ...args);
  return c.json({ data: rows.map(serializeSession) });
});

sessionsRouter.get('/:id', async (c) => {
  return c.json({ data: serializeSession(await ownedSession(c.get('user').id, c.req.param('id'))) });
});

// GET /v1/sessions/:id/todos — the agent's current todo list, read live from the PC
sessionsRouter.get('/:id/todos', async (c) => {
  const user = c.get('user');
  const session = await ownedSession(user.id, c.req.param('id'));
  return c.json({ data: await relay(user.id, await sessionDesktop(session), 'todos', { opencodeSessionId: session.opencode_session_id }) });
});

// PATCH /v1/sessions/:id { starred } — like / unlike a session (kept by BambooKit only)
sessionsRouter.patch('/:id', async (c) => {
  const user = c.get('user');
  const session = await ownedSession(user.id, c.req.param('id'));
  const { starred } = z.object({ starred: z.boolean() }).strict().parse(await c.req.json());
  await db.run('UPDATE sessions SET starred = ? WHERE id = ?', starred ? 1 : 0, session.id);
  const updated = serializeSession(await ownedSession(user.id, session.id));
  await publish({ userId: user.id, deviceId: session.device_id, projectId: session.project_id, sessionId: session.id, type: 'session.updated', payload: updated });
  return c.json({ data: updated });
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
  // Complete content: full text, tool input/output/errors/diffs (older desktops send only the short live shape).
  return c.json({ data: (res?.parts ?? []).slice(-2000).map((p) => transcriptPartView(session.id, p, ts)) });
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
  // Project files are view-only from phones and the website (READ_FILE, /tree, /file); no remote edits.
  'REVERT', 'UNREVERT', 'SHARE', 'UNSHARE', 'READ_FILE', 'CONTINUE_ON_PC', 'RENAME_SESSION',
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

// GET /v1/sessions/:id/tree?path= — one folder of the session's project (view only, live from the PC)
sessionsRouter.get('/:id/tree', async (c) => {
  const user = c.get('user');
  const session = await ownedSession(user.id, c.req.param('id'));
  const path = z.string().max(1000).parse(c.req.query('path') ?? '');
  return c.json({ data: await relay(user.id, await sessionDesktop(session), 'tree', { opencodeSessionId: session.opencode_session_id, path }) });
});

// GET /v1/sessions/:id/file?path= — a project file's text (view only, live from the PC, never stored)
sessionsRouter.get('/:id/file', async (c) => {
  const user = c.get('user');
  const session = await ownedSession(user.id, c.req.param('id'));
  const path = z.string().min(1).max(1000).parse(c.req.query('path'));
  return c.json({ data: await relay(user.id, await sessionDesktop(session), 'file', { opencodeSessionId: session.opencode_session_id, path }) });
});

// Commands that continue or change the conversation need the session to be continued on the PC first.
const continueCommands = new Set(['SEND_MESSAGE', 'CONTINUE', 'RETRY', 'REVERT', 'UNREVERT']);

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
