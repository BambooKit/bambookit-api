import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';
import { generateId } from '../../lib/crypto.js';
import { realtimeHub } from '../../realtime/events.js';

export const approvalsRouter = new Hono();

approvalsRouter.use('*', authMiddleware);

const respondApprovalSchema = z.object({
  status: z.enum(['APPROVED', 'REJECTED']),
  scope: z.enum(['ONCE', 'TASK', 'PROJECT', 'SESSION']).default('ONCE'),
  note: z.string().optional(),
});

// GET /v1/approvals
approvalsRouter.get('/', (c) => {
  const auth = c.get('auth');
  const status = c.req.query('status');

  let approvals = memoryDb.data.approvals.filter((a) => a.workspaceId === auth.workspaceId);
  if (status) {
    approvals = approvals.filter((a) => a.status === status);
  }

  return c.json({ data: approvals, requestId: c.get('requestId') });
});

// GET /v1/approvals/:id
approvalsRouter.get('/:id', (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');

  const approval = memoryDb.data.approvals.find((a) => a.id === id && a.workspaceId === auth.workspaceId);
  if (!approval) {
    return c.json({ error: { code: 'APPROVAL_NOT_FOUND', message: 'Approval request not found' } }, 404);
  }

  return c.json({ data: approval, requestId: c.get('requestId') });
});

// POST /v1/approvals/:id/respond
approvalsRouter.post('/:id/respond', zValidator('json', respondApprovalSchema), (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');
  const { status, scope, note } = c.req.valid('json');

  const approval = memoryDb.data.approvals.find((a) => a.id === id && a.workspaceId === auth.workspaceId);
  if (!approval) {
    return c.json({ error: { code: 'APPROVAL_NOT_FOUND', message: 'Approval request not found' } }, 404);
  }

  if (approval.status !== 'PENDING') {
    return c.json({ error: { code: 'ALREADY_RESOLVED', message: `Approval has already been ${approval.status}` } }, 400);
  }

  approval.status = status;
  approval.scope = scope;
  approval.resolvedAt = new Date();
  approval.resolvedById = auth.userId;

  // Append immutable audit log event
  memoryDb.data.auditLog.unshift({
    id: generateId('aud'),
    workspaceId: auth.workspaceId,
    actorType: 'USER',
    actorId: auth.userId,
    actorName: auth.name,
    action: status === 'APPROVED' ? `Approved (${scope})` : 'Rejected Action',
    resourceType: 'APPROVAL',
    resourceId: approval.id,
    metadata: { note: note || null, action: approval.action, scope },
    ipAddress: c.req.header('x-forwarded-for') || '127.0.0.1',
    createdAt: new Date(),
  });

  // Broadcast realtime gate resolution
  realtimeHub.broadcast(`workspace:${auth.workspaceId}`, 'approval.resolved', approval);

  return c.json({ data: approval, requestId: c.get('requestId') });
});
