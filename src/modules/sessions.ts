import { Hono } from 'hono';
import { z } from 'zod';
import { db, now } from '../db/database.js';
import { requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { HttpError, badRequest, forbidden, newId, notFound } from '../lib/http.js';
import { commandPayloads, createCommand, resolveIssuer, type CommandType } from './commands.js';
import { serializeProject, serializeSession } from './serializers.js';
import { relay } from './relay.js';
import { emitEphemeral, publish } from '../realtime/bus.js';
import { transcriptPartView, type PartSync } from './sync.js';
import { SESSION_SELECT, assertSessionAccess, collaboratorsPayload, emitCollaboratorsUpdated } from './collaborators.js';

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
// Returns the sessions the user owns AND the sessions they collaborate on, each tagged with the user's role.
sessionsRouter.get('/', async (c) => {
  const userId = c.get('user').id;
  const clauses: string[] = [];
  const filterArgs: string[] = [];
  const projectId = c.req.query('projectId');
  const deviceId = c.req.query('deviceId');
  if (projectId) (clauses.push('s.project_id = ?'), filterArgs.push(projectId));
  if (deviceId) (clauses.push('s.device_id = ?'), filterArgs.push(deviceId));
  if (c.req.query('active') === 'true') clauses.push("s.status IN ('busy','retry')");
  if (c.req.query('starred') === 'true') clauses.push('s.starred = 1');
  if (c.req.query('includeChildren') !== 'true') clauses.push('s.parent_opencode_session_id IS NULL');
  const filterSql = clauses.length ? ` AND ${clauses.join(' AND ')}` : '';

  const owned = await db.all(`${SESSION_SELECT} WHERE s.user_id = ?${filterSql} ORDER BY s.updated_at DESC LIMIT 200`, userId, ...filterArgs);
  owned.forEach((r: any) => (r.my_role = 'owner'));

  const memberships = await db.all<{ session_id: string; role: string }>('SELECT session_id, role FROM session_collaborators WHERE user_id = ?', userId);
  const roleBySession = new Map(memberships.map((m) => [m.session_id, m.role]));
  let collaborated: any[] = [];
  if (roleBySession.size) {
    const ids = [...roleBySession.keys()];
    const placeholders = ids.map(() => '?').join(',');
    collaborated = await db.all(`${SESSION_SELECT} WHERE s.id IN (${placeholders})${filterSql} ORDER BY s.updated_at DESC LIMIT 200`, ...ids, ...filterArgs);
    collaborated.forEach((r: any) => (r.my_role = roleBySession.get(r.id)));
  }

  const merged = [...owned, ...collaborated].sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at))).slice(0, 200);
  return c.json({ data: merged.map(serializeSession) });
});

sessionsRouter.get('/:id', async (c) => {
  const { session } = await assertSessionAccess(c.get('user').id, c.req.param('id'), 'read');
  return c.json({ data: serializeSession(session) });
});

// GET /v1/sessions/:id/todos — the agent's current todo list, read live from the PC
sessionsRouter.get('/:id/todos', async (c) => {
  const { session } = await assertSessionAccess(c.get('user').id, c.req.param('id'), 'read');
  return c.json({ data: await relay(session.user_id, await sessionDesktop(session), 'todos', { opencodeSessionId: session.opencode_session_id }) });
});

// PATCH /v1/sessions/:id { starred } — like / unlike a session (kept by BambooKit only). Owner only: the flag
// lives on the owner's session row.
sessionsRouter.patch('/:id', async (c) => {
  const user = c.get('user');
  const { session } = await assertSessionAccess(user.id, c.req.param('id'), 'owner');
  const { starred } = z.object({ starred: z.boolean() }).strict().parse(await c.req.json());
  await db.run('UPDATE sessions SET starred = ? WHERE id = ?', starred ? 1 : 0, session.id);
  const refreshed = await db.get(`${SESSION_SELECT} WHERE s.id = ?`, session.id);
  refreshed.my_role = 'owner';
  const updated = serializeSession(refreshed);
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
  const { session } = await assertSessionAccess(c.get('user').id, c.req.param('id'), 'read');
  const res = (await relay(session.user_id, await sessionDesktop(session), 'transcript', { opencodeSessionId: session.opencode_session_id })) as { parts?: PartSync[] } | null;
  const ts = new Date().toISOString();
  // Complete content: full text, tool input/output/errors/diffs (older desktops send only the short live shape).
  return c.json({ data: (res?.parts ?? []).slice(-2000).map((p) => transcriptPartView(session.id, p, ts)) });
});

// GET /v1/sessions/:id/changes — changed files summary, read live from the PC (patches: GET_DIFF command)
sessionsRouter.get('/:id/changes', async (c) => {
  const { session } = await assertSessionAccess(c.get('user').id, c.req.param('id'), 'read');
  const res = (await relay(session.user_id, await sessionDesktop(session), 'changes', { opencodeSessionId: session.opencode_session_id })) as { files?: unknown[] } | null;
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
  const { session } = await assertSessionAccess(c.get('user').id, c.req.param('id'), 'read');
  const res = (await relay(session.user_id, await sessionDesktop(session), 'filemap', { opencodeSessionId: session.opencode_session_id })) as { files?: unknown[] } | null;
  return c.json({ data: res?.files ?? [] });
});

// GET /v1/sessions/:id/diagram — the session's project drawn as components and real references (live from the PC)
sessionsRouter.get('/:id/diagram', async (c) => {
  const { session } = await assertSessionAccess(c.get('user').id, c.req.param('id'), 'read');
  return c.json({ data: await relay(session.user_id, await sessionDesktop(session), 'diagram', { opencodeSessionId: session.opencode_session_id }) });
});

// GET /v1/sessions/:id/tree?path= — one folder of the session's project (view only, live from the PC)
sessionsRouter.get('/:id/tree', async (c) => {
  const { session } = await assertSessionAccess(c.get('user').id, c.req.param('id'), 'read');
  const path = z.string().max(1000).parse(c.req.query('path') ?? '');
  return c.json({ data: await relay(session.user_id, await sessionDesktop(session), 'tree', { opencodeSessionId: session.opencode_session_id, path }) });
});

// GET /v1/sessions/:id/file?path= — a project file's text (view only, live from the PC, never stored)
sessionsRouter.get('/:id/file', async (c) => {
  const { session } = await assertSessionAccess(c.get('user').id, c.req.param('id'), 'read');
  const path = z.string().min(1).max(1000).parse(c.req.query('path'));
  return c.json({ data: await relay(session.user_id, await sessionDesktop(session), 'file', { opencodeSessionId: session.opencode_session_id, path }) });
});

// Commands that continue or change the conversation need the session to be continued on the PC first.
const continueCommands = new Set(['SEND_MESSAGE', 'CONTINUE', 'RETRY', 'REVERT', 'UNREVERT']);

sessionsRouter.post('/:id/commands', async (c) => {
  const user = c.get('user');
  const body = z.object({ type: z.enum(userCommandTypes), payload: z.unknown().optional() }).parse(await c.req.json());
  if (!(body.type in commandPayloads)) throw badRequest('Unknown command');
  // Collaborators (role 'chat') may SEND_MESSAGE only; every other command stays owner-only.
  const need = body.type === 'SEND_MESSAGE' ? 'chat' : 'owner';
  const { session, isOwner } = await assertSessionAccess(user.id, c.req.param('id'), need);
  if (continueCommands.has(body.type) && !Number(session.remote)) {
    throw new HttpError(409, 'SESSION_NOT_CONTINUED', 'Continue this session on your PC first, then you can chat in it from here.');
  }
  const ownerId = session.user_id as string;
  const desktop = await desktopFor(session.device_id);

  if (isOwner) {
    const issuer = await resolveIssuer(user.id, c.req.header('X-BK-Device-Id'));
    const res = await createCommand({ userId: ownerId, desktop, sessionId: session.id, issuer, type: body.type as CommandType, payload: body.payload ?? {} });
    return c.json({ data: res.command, deviceOnline: res.deviceOnline }, 202);
  }

  // Collaborator SEND_MESSAGE: routed to the owner's PC, but counted against the collaborator's own daily
  // allowance. The collaborator's phone/web is not paired with the owner's PC, so it is not used as the issuer.
  const res = await createCommand({ userId: ownerId, desktop, sessionId: session.id, issuer: null, type: body.type as CommandType, payload: body.payload ?? {}, quotaUserId: user.id });
  // Author attribution for the chat view (the engine cannot carry an author, so the API records it live).
  const sender = await db.get<{ name: string | null; email: string | null }>('SELECT COALESCE(nickname, name) AS name, email FROM users WHERE id = ?', user.id);
  emitEphemeral({
    userId: ownerId,
    deviceId: session.device_id,
    sessionId: session.id,
    type: 'session.message',
    payload: { sessionId: session.id, author: { userId: user.id, name: sender?.name ?? null, email: sender?.email ?? null }, text: (body.payload as any)?.text ?? null },
  });
  return c.json({ data: res.command, deviceOnline: res.deviceOnline }, 202);
});

// ---------------- Collaborators ----------------

// GET /v1/sessions/:id/collaborators — owner or collaborator
sessionsRouter.get('/:id/collaborators', async (c) => {
  const user = c.get('user');
  await assertSessionAccess(user.id, c.req.param('id'), 'read');
  return c.json({ data: await collaboratorsPayload(c.req.param('id'), user.id) });
});

// POST /v1/sessions/:id/collaborators { email, role } — owner only
sessionsRouter.post('/:id/collaborators', async (c) => {
  const user = c.get('user');
  const { session } = await assertSessionAccess(user.id, c.req.param('id'), 'owner');
  const { email, role } = z
    .object({ email: z.string().trim().max(320).email().transform((e) => e.toLowerCase()), role: z.enum(['chat', 'viewer']) })
    .parse(await c.req.json());
  if (session.owner_email && String(session.owner_email).toLowerCase() === email) throw badRequest('You already own this session', 'CANNOT_INVITE_OWNER');
  const existingUser = await db.get<{ id: string }>('SELECT id FROM users WHERE LOWER(email) = ?', email);
  const ts = now();
  const existing = await db.get<{ id: string }>('SELECT id FROM session_collaborators WHERE session_id = ? AND LOWER(email) = ?', session.id, email);
  if (existing) {
    await db.run(
      'UPDATE session_collaborators SET role = ?, user_id = COALESCE(user_id, ?), accepted_at = CASE WHEN user_id IS NULL AND ? IS NOT NULL THEN ? ELSE accepted_at END WHERE id = ?',
      role,
      existingUser?.id ?? null,
      existingUser?.id ?? null,
      ts,
      existing.id,
    );
  } else {
    await db.run(
      'INSERT INTO session_collaborators (id, session_id, user_id, email, role, invited_by, created_at, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      newId('col'),
      session.id,
      existingUser?.id ?? null,
      email,
      role,
      user.id,
      ts,
      existingUser ? ts : null,
    );
  }
  await emitCollaboratorsUpdated(session.id);
  return c.json({ data: await collaboratorsPayload(session.id, user.id) }, existing ? 200 : 201);
});

// DELETE /v1/sessions/:id/collaborators/:collabId — owner, or a collaborator removing themselves.
// :collabId may be the collaborator row id, the collaborator's userId, or their (URL-encoded) email, so
// pending-by-email collaborators (no userId yet) can be removed too.
sessionsRouter.delete('/:id/collaborators/:collabId', async (c) => {
  const user = c.get('user');
  const sessionId = c.req.param('id');
  const key = c.req.param('collabId'); // Hono URL-decodes path params, so an encoded email arrives decoded.
  const row = await db.get<{ id: string; user_id: string | null; owner_id: string }>(
    `SELECT sc.id, sc.user_id, s.user_id AS owner_id FROM session_collaborators sc JOIN sessions s ON s.id = sc.session_id
     WHERE sc.session_id = ? AND (sc.id = ? OR sc.user_id = ? OR LOWER(sc.email) = LOWER(?))`,
    sessionId,
    key,
    key,
    key,
  );
  if (!row) throw notFound('Collaborator');
  const isOwner = row.owner_id === user.id;
  const isSelf = !!row.user_id && row.user_id === user.id;
  if (!isOwner && !isSelf) {
    const member = await db.get('SELECT 1 AS ok FROM session_collaborators WHERE session_id = ? AND user_id = ?', sessionId, user.id);
    throw member ? forbidden('Only the owner can remove other collaborators', 'NOT_ALLOWED') : notFound('Session');
  }
  await db.run('DELETE FROM session_collaborators WHERE id = ?', row.id);
  await emitCollaboratorsUpdated(sessionId, row.user_id ? [row.user_id] : []);
  return c.json({ data: await collaboratorsPayload(sessionId, user.id) });
});
