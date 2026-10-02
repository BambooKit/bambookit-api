import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db/database.js';
import { requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { badRequest, notFound } from '../lib/http.js';
import { commandPayloads, createCommand, resolveIssuer, type CommandType } from './commands.js';
import { serializePart, serializeProject, serializeSession } from './serializers.js';

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

// POST /v1/projects/:id/sessions { text } — start a new session on the project's desktop
projectsRouter.post('/:id/sessions', async (c) => {
  const user = c.get('user');
  const project = await db.get('SELECT * FROM projects WHERE id = ? AND user_id = ?', c.req.param('id'), user.id);
  if (!project) throw notFound('Project');
  const { text } = z.object({ text: z.string().min(1).max(20_000) }).parse(await c.req.json());
  const issuer = await resolveIssuer(user.id, c.req.header('X-BK-Device-Id'));
  const res = await createCommand({ userId: user.id, desktop: await desktopFor(project.device_id), sessionId: null, issuer, type: 'CREATE_SESSION', payload: { directory: project.directory, text } });
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
  if (c.req.query('includeChildren') !== 'true') where.push('s.parent_opencode_session_id IS NULL');
  const rows = await db.all(`${SESSION_SELECT} WHERE ${where.join(' AND ')} ORDER BY s.updated_at DESC LIMIT 200`, ...args);
  return c.json({ data: rows.map(serializeSession) });
});

sessionsRouter.get('/:id', async (c) => {
  return c.json({ data: serializeSession(await ownedSession(c.get('user').id, c.req.param('id'))) });
});

// GET /v1/sessions/:id/parts — chat transcript (text, reasoning and tool parts)
sessionsRouter.get('/:id/parts', async (c) => {
  const session = await ownedSession(c.get('user').id, c.req.param('id'));
  const rows = await db.all('SELECT * FROM session_parts WHERE session_id = ? ORDER BY sort_key ASC LIMIT 2000', session.id);
  return c.json({ data: rows.map(serializePart) });
});

// GET /v1/sessions/:id/changes — changed files summary (patches are fetched with a GET_DIFF command)
sessionsRouter.get('/:id/changes', async (c) => {
  const session = await ownedSession(c.get('user').id, c.req.param('id'));
  const rows = await db.all('SELECT file, status, additions, deletions, updated_at FROM session_diffs WHERE session_id = ? ORDER BY file', session.id);
  return c.json({ data: rows.map((r) => ({ ...r, additions: Number(r.additions), deletions: Number(r.deletions) })) });
});

// POST /v1/sessions/:id/commands { type, payload }
const userCommandTypes = ['SEND_MESSAGE', 'ABORT', 'CONTINUE', 'RETRY', 'GET_DIFF', 'REFRESH'] as const;
sessionsRouter.post('/:id/commands', async (c) => {
  const user = c.get('user');
  const session = await ownedSession(user.id, c.req.param('id'));
  const body = z.object({ type: z.enum(userCommandTypes), payload: z.unknown().optional() }).parse(await c.req.json());
  if (!(body.type in commandPayloads)) throw badRequest('Unknown command');
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
