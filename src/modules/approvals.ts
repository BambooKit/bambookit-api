import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db/database.js';
import { requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { HttpError, notFound } from '../lib/http.js';
import { publish } from '../realtime/bus.js';
import { createCommand, resolveIssuer } from './commands.js';
import { serializeApproval } from './serializers.js';

export const approvalsRouter = new Hono<AppEnv>();
approvalsRouter.use('*', requireUser);

const APPROVAL_SELECT = `
  SELECT a.*, s.title AS session_title, p.name AS project_name FROM approvals a
  JOIN sessions s ON s.id = a.session_id LEFT JOIN projects p ON p.id = s.project_id`;

// GET /v1/approvals?status=PENDING&sessionId=
approvalsRouter.get('/', (c) => {
  const where = ['a.user_id = ?'];
  const args: string[] = [c.get('user').id];
  const status = c.req.query('status');
  const sessionId = c.req.query('sessionId');
  if (status === 'PENDING') where.push("a.status IN ('PENDING','RESPONDING')");
  else if (status) (where.push('a.status = ?'), args.push(status));
  if (sessionId) (where.push('a.session_id = ?'), args.push(sessionId));
  const rows = db.prepare(`${APPROVAL_SELECT} WHERE ${where.join(' AND ')} ORDER BY a.created_at DESC LIMIT 200`).all(...args);
  return c.json({ data: rows.map(serializeApproval) });
});

approvalsRouter.get('/:id', (c) => {
  const row = db.prepare(`${APPROVAL_SELECT} WHERE a.id = ? AND a.user_id = ?`).get(c.req.param('id'), c.get('user').id);
  if (!row) throw notFound('Approval');
  return c.json({ data: serializeApproval(row) });
});

/**
 * POST /v1/approvals/:id/respond { reply: once | always | reject }
 * Forwards the decision to the desktop, which answers OpenCode's own permission request.
 * The approval becomes APPROVED/REJECTED only when OpenCode confirms it (permission.replied).
 */
approvalsRouter.post('/:id/respond', async (c) => {
  const user = c.get('user');
  const { reply } = z.object({ reply: z.enum(['once', 'always', 'reject']) }).parse(await c.req.json());
  const approval = db.prepare(`${APPROVAL_SELECT} WHERE a.id = ? AND a.user_id = ?`).get(c.req.param('id'), user.id) as any;
  if (!approval) throw notFound('Approval');
  if (approval.status !== 'PENDING') throw new HttpError(409, 'APPROVAL_NOT_PENDING', `Approval is ${approval.status.toLowerCase()}`);

  const issuer = resolveIssuer(user.id, c.req.header('X-BK-Device-Id'));
  const desktop = db.prepare('SELECT * FROM devices WHERE id = ?').get(approval.device_id) as unknown as DeviceRow;
  const claimed = db.prepare("UPDATE approvals SET status = 'RESPONDING', reply = ? WHERE id = ? AND status = 'PENDING'").run(reply, approval.id);
  if (claimed.changes !== 1) throw new HttpError(409, 'APPROVAL_NOT_PENDING', 'Approval was already answered');

  try {
    const res = createCommand({
      userId: user.id,
      desktop,
      sessionId: approval.session_id,
      issuer,
      type: 'PERMISSION_REPLY',
      payload: { requestId: approval.opencode_request_id, reply },
    });
    const updated = serializeApproval(db.prepare(`${APPROVAL_SELECT} WHERE a.id = ?`).get(approval.id));
    publish({ userId: user.id, deviceId: desktop.id, sessionId: approval.session_id, type: 'approval.updated', payload: updated });
    return c.json({ data: updated, command: res.command, deviceOnline: res.deviceOnline }, 202);
  } catch (err) {
    db.prepare("UPDATE approvals SET status = 'PENDING', reply = NULL WHERE id = ?").run(approval.id);
    throw err;
  }
});
