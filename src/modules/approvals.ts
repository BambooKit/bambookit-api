import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db/database.js';
import { requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { HttpError, badRequest, notFound } from '../lib/http.js';
import { publish } from '../realtime/bus.js';
import { createCommand, resolveIssuer } from './commands.js';
import { serializeApproval } from './serializers.js';
import { relay } from './relay.js';
import { APPROVAL_HISTORY_MS } from './sync.js';

export const approvalsRouter = new Hono<AppEnv>();
approvalsRouter.use('*', requireUser);

const APPROVAL_SELECT = `
  SELECT a.*, s.title AS session_title, p.name AS project_name FROM approvals a
  JOIN sessions s ON s.id = a.session_id LEFT JOIN projects p ON p.id = s.project_id`;

const encodeCursor = (row: { created_at: string; id: string }) => Buffer.from(JSON.stringify([row.created_at, row.id])).toString('base64url');
function decodeCursor(cursor: string): [string, string] {
  try {
    const v = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
    if (Array.isArray(v) && v.length === 2 && typeof v[0] === 'string' && typeof v[1] === 'string') return [v[0], v[1]];
  } catch {}
  throw badRequest('This page cursor is not valid', 'INVALID_CURSOR');
}

/**
 * GET /v1/approvals?status=pending|resolved|all&limit=50&before=<cursor>&sessionId=&deviceId=
 * Newest first, with `nextCursor` for the next page (null at the end). Resolved items (APPROVED, REJECTED,
 * ANSWERED, EXPIRED) are listed for 30 days. Earlier forms keep working: status=PENDING (pending and being
 * answered), status=<exact status>, and no status (everything, up to 200).
 */
approvalsRouter.get('/', async (c) => {
  const where = ['a.user_id = ?'];
  const args: string[] = [c.get('user').id];
  const status = c.req.query('status');
  const sessionId = c.req.query('sessionId');
  const deviceId = c.req.query('deviceId');
  const before = c.req.query('before');
  const since = new Date(Date.now() - APPROVAL_HISTORY_MS).toISOString();
  const history = status === 'pending' || status === 'resolved' || status === 'all';
  const limit = c.req.query('limit') !== undefined ? z.coerce.number().int().min(1).max(200).parse(c.req.query('limit')) : history || before ? 50 : 200;
  if (status === 'PENDING' || status === 'pending') where.push("a.status IN ('PENDING','RESPONDING')");
  else if (status === 'resolved') (where.push("a.status NOT IN ('PENDING','RESPONDING') AND COALESCE(a.resolved_at, a.created_at) >= ?"), args.push(since));
  else if (status === 'all') (where.push("(a.status IN ('PENDING','RESPONDING') OR COALESCE(a.resolved_at, a.created_at) >= ?)"), args.push(since));
  else if (status) (where.push('a.status = ?'), args.push(status));
  if (sessionId) (where.push('a.session_id = ?'), args.push(sessionId));
  if (deviceId) (where.push('a.device_id = ?'), args.push(deviceId));
  if (before) {
    const [at, id] = decodeCursor(before);
    where.push('(a.created_at < ? OR (a.created_at = ? AND a.id < ?))');
    args.push(at, at, id);
  }
  const rows = await db.all(`${APPROVAL_SELECT} WHERE ${where.join(' AND ')} ORDER BY a.created_at DESC, a.id DESC LIMIT ${limit + 1}`, ...args);
  const page = rows.slice(0, limit);
  return c.json({ data: page.map(serializeApproval), nextCursor: rows.length > limit ? encodeCursor(page[page.length - 1]) : null });
});

// GET /v1/approvals/:id/detail — everything the agent attached to the request (full command, proposed diff,
// question context), read live from the PC that asked. Not stored by the API.
approvalsRouter.get('/:id/detail', async (c) => {
  const user = c.get('user');
  const approval = await db.get(`${APPROVAL_SELECT} WHERE a.id = ? AND a.user_id = ?`, c.req.param('id'), user.id);
  if (!approval) throw notFound('Approval');
  const desktop = await db.get<DeviceRow>('SELECT * FROM devices WHERE id = ?', approval.device_id);
  if (!desktop || desktop.revoked_at) throw notFound('Device');
  const session = await db.get<{ opencode_session_id: string }>('SELECT opencode_session_id FROM sessions WHERE id = ?', approval.session_id);
  return c.json({
    data: await relay(user.id, desktop, 'approval', { requestId: approval.opencode_request_id, kind: approval.kind ?? 'permission', opencodeSessionId: session?.opencode_session_id ?? null }),
  });
});

approvalsRouter.get('/:id', async (c) => {
  const row = await db.get(`${APPROVAL_SELECT} WHERE a.id = ? AND a.user_id = ?`, c.req.param('id'), c.get('user').id);
  if (!row) throw notFound('Approval');
  return c.json({ data: serializeApproval(row) });
});

/**
 * Claims a pending approval and forwards the decision to the PC that asked, which answers the engine's own
 * permission or question request. The approval becomes APPROVED/REJECTED only when the engine confirms it.
 */
async function forward(c: any, reply: string, command: { type: 'PERMISSION_REPLY' | 'QUESTION_REPLY' | 'QUESTION_REJECT'; payload: Record<string, unknown> }, approval: any) {
  const user = c.get('user');
  if (approval.status !== 'PENDING') throw new HttpError(409, 'APPROVAL_NOT_PENDING', `Approval is ${String(approval.status).toLowerCase()}`);
  const issuer = await resolveIssuer(user.id, c.req.header('X-BK-Device-Id'));
  const desktop = await db.get<DeviceRow>('SELECT * FROM devices WHERE id = ?', approval.device_id);
  // Who answered: shown in history once the PC confirms (the PC's own report wins if it differs).
  const by = issuer?.kind === 'mobile' ? 'phone' : issuer?.kind === 'desktop' ? 'pc' : 'web';
  const claimed = await db.run("UPDATE approvals SET status = 'RESPONDING', reply = ?, resolved_by = ? WHERE id = ? AND status = 'PENDING'", reply, by, approval.id);
  if (claimed.changes !== 1) throw new HttpError(409, 'APPROVAL_NOT_PENDING', 'Approval was already answered');
  try {
    const res = await createCommand({ userId: user.id, desktop, sessionId: approval.session_id, issuer, type: command.type, payload: command.payload });
    const updated = serializeApproval(await db.get(`${APPROVAL_SELECT} WHERE a.id = ?`, approval.id));
    await publish({ userId: user.id, deviceId: approval.device_id, sessionId: approval.session_id, type: 'approval.updated', payload: updated });
    return c.json({ data: updated, command: res.command, deviceOnline: res.deviceOnline }, 202);
  } catch (err) {
    await db.run("UPDATE approvals SET status = 'PENDING', reply = NULL, resolved_by = NULL WHERE id = ?", approval.id);
    throw err;
  }
}

async function ownedApproval(c: any) {
  const approval = await db.get(`${APPROVAL_SELECT} WHERE a.id = ? AND a.user_id = ?`, c.req.param('id'), c.get('user').id);
  if (!approval) throw notFound('Approval');
  return approval;
}

/**
 * POST /v1/approvals/:id/respond { reply: once | always | reject }
 * For a question, only `reject` (dismiss) is accepted here; answers go to /answer.
 */
approvalsRouter.post('/:id/respond', async (c) => {
  const { reply } = z.object({ reply: z.enum(['once', 'always', 'reject']) }).parse(await c.req.json());
  const approval = await ownedApproval(c);
  if (approval.kind === 'question') {
    if (reply !== 'reject') throw new HttpError(400, 'ANSWER_REQUIRED', 'Answer the question, or dismiss it');
    return forward(c, 'reject', { type: 'QUESTION_REJECT', payload: { requestId: approval.opencode_request_id } }, approval);
  }
  return forward(c, reply, { type: 'PERMISSION_REPLY', payload: { requestId: approval.opencode_request_id, reply } }, approval);
});

/** POST /v1/approvals/:id/answer { answers: string[][] } — one list of chosen labels (or typed text) per question. */
approvalsRouter.post('/:id/answer', async (c) => {
  const { answers } = z
    .object({ answers: z.array(z.array(z.string().trim().min(1).max(2000)).max(50)).min(1).max(10) })
    .parse(await c.req.json());
  const approval = await ownedApproval(c);
  if (approval.kind !== 'question') throw new HttpError(400, 'NOT_A_QUESTION', 'This request is an approval; use /respond');
  const questions = JSON.parse(approval.questions ?? '[]') as unknown[];
  if (questions.length && answers.length !== questions.length) throw new HttpError(400, 'ANSWER_COUNT', `Answer all ${questions.length} questions`);
  return forward(c, 'answer', { type: 'QUESTION_REPLY', payload: { requestId: approval.opencode_request_id, answers } }, approval);
});
