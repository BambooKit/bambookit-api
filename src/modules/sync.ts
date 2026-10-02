import { Hono } from 'hono';
import { z } from 'zod';
import { db, now } from '../db/database.js';
import { requireDevice, requireUser, type AppEnv } from '../middleware/auth.js';
import { stableId } from '../lib/http.js';
import { publish } from '../realtime/bus.js';
import { notify } from './notifications.js';
import { serializeApproval, serializePart, serializeProject, serializeSession } from './serializers.js';

/**
 * Desktop → API state sync. The desktop is the authority for OpenCode state; it pushes the
 * minimum metadata needed for remote monitoring. Source code is never sent here except
 * assistant/user message text that the user sees in the chat transcript.
 */
export const syncRouter = new Hono<AppEnv>();
syncRouter.use('*', requireUser, requireDevice('desktop'));

const MAX_TEXT = 20_000;
const status = z.enum(['idle', 'busy', 'retry', 'error']);

const partSchema = z.object({
  opencodeSessionId: z.string().max(200),
  messageId: z.string().max(200),
  partId: z.string().max(200),
  role: z.enum(['user', 'assistant']),
  type: z.enum(['text', 'reasoning', 'tool']),
  text: z.string().nullish(),
  tool: z.string().max(100).nullish(),
  toolStatus: z.string().max(40).nullish(),
  toolTitle: z.string().max(500).nullish(),
  sortKey: z.string().max(100),
});

const syncSchema = z.object({
  projects: z
    .array(z.object({ opencodeProjectId: z.string().min(1), name: z.string().min(1).max(200), directory: z.string().min(1).max(1000), branch: z.string().max(200).nullish() }))
    .max(200)
    .optional(),
  sessions: z
    .array(
      z.object({
        opencodeSessionId: z.string().min(1).max(200),
        opencodeProjectId: z.string().max(200).nullish(),
        parentId: z.string().max(200).nullish(),
        directory: z.string().min(1).max(1000),
        title: z.string().max(500),
        status,
        statusMessage: z.string().max(1000).nullish(),
        agent: z.string().max(100).nullish(),
        model: z.string().max(200).nullish(),
        additions: z.number().int().nonnegative().default(0),
        deletions: z.number().int().nonnegative().default(0),
        files: z.number().int().nonnegative().default(0),
        currentAction: z.string().max(500).nullish(),
        createdAt: z.string().optional(),
      }),
    )
    .max(500)
    .optional(),
  removedSessions: z.array(z.string().max(200)).max(500).optional(),
  parts: z.array(partSchema).max(500).optional(),
  // Full transcript of a session, replacing what is stored (used after resync, rewind or deletions).
  transcripts: z.array(z.object({ opencodeSessionId: z.string().max(200), parts: z.array(partSchema).max(2000) })).max(5).optional(),
  diffs: z
    .array(
      z.object({
        opencodeSessionId: z.string().max(200),
        files: z
          .array(z.object({ file: z.string().max(1000), status: z.string().max(20).nullish(), additions: z.number().int().nonnegative(), deletions: z.number().int().nonnegative() }))
          .max(2000),
      }),
    )
    .max(100)
    .optional(),
  approvals: z
    .array(
      z.object({
        opencodeSessionId: z.string().max(200),
        requestId: z.string().max(200),
        permission: z.string().max(100),
        title: z.string().max(1000).nullish(),
        patterns: z.array(z.string().max(1000)).max(50).default([]),
        status: z.enum(['PENDING', 'APPROVED', 'REJECTED']),
        reply: z.string().max(20).nullish(),
      }),
    )
    .max(200)
    .optional(),
  // Local engine state reported by the desktop (for the live architecture map). Names and statuses only.
  engine: z
    .object({
      version: z.string().max(40).nullish(),
      mcp: z.array(z.object({ name: z.string().max(100), status: z.string().max(40) })).max(100).default([]),
      providers: z.array(z.object({ id: z.string().max(100), name: z.string().max(100) })).max(200).default([]),
      terminals: z.array(z.object({ id: z.string().max(100), title: z.string().max(200).nullish(), status: z.string().max(40).nullish() })).max(50).default([]),
    })
    .optional(),
  // Complete list of request ids still pending on the desktop; anything else pending is expired.
  pendingApprovalSnapshot: z.array(z.string().max(200)).max(500).optional(),
  activity: z
    .array(z.object({ opencodeSessionId: z.string().max(200).nullish(), type: z.string().max(60), summary: z.string().max(1000), data: z.record(z.unknown()).optional() }))
    .max(200)
    .optional(),
});

export type SyncPayload = z.infer<typeof syncSchema>;

syncRouter.post('/', async (c) => {
  const user = c.get('user');
  const device = c.get('device')!;
  const body = syncSchema.parse(JSON.parse(await c.req.text()));
  const ts = now();
  const out: Array<Parameters<typeof publish>[0]> = [];
  const notes: Array<Parameters<typeof notify>[0]> = [];
  const projectIds = new Map<string, string>();
  const sessionIdFor = (ocId: string) => stableId('ses', device.id, ocId);

  await db.tx(async (q) => {
    const ownsSession = async (id: string) => !!(await q.get('SELECT 1 AS ok FROM sessions WHERE id = ? AND user_id = ?', id, user.id));
    const approvalRow = (id: string) =>
      q.get(`SELECT a.*, s.title AS session_title, p.name AS project_name FROM approvals a
        JOIN sessions s ON s.id = a.session_id LEFT JOIN projects p ON p.id = s.project_id WHERE a.id = ?`, id);

    for (const p of body.projects ?? []) {
      const id = stableId('prj', device.id, p.opencodeProjectId);
      projectIds.set(p.opencodeProjectId, id);
      await q.run(
        `INSERT INTO projects (id, user_id, device_id, opencode_project_id, name, directory, branch, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, directory = excluded.directory, branch = excluded.branch, updated_at = excluded.updated_at`,
        id, user.id, device.id, p.opencodeProjectId, p.name, p.directory, p.branch ?? null, ts, ts,
      );
      out.push({ userId: user.id, deviceId: device.id, projectId: id, type: 'project.updated', payload: serializeProject(await q.get('SELECT * FROM projects WHERE id = ?', id)) });
    }

    for (const s of body.sessions ?? []) {
      const id = sessionIdFor(s.opencodeSessionId);
      const projectId = s.opencodeProjectId ? projectIds.get(s.opencodeProjectId) ?? stableId('prj', device.id, s.opencodeProjectId) : null;
      const projectExists = projectId ? !!(await q.get('SELECT 1 AS ok FROM projects WHERE id = ?', projectId)) : false;
      const previous = await q.get('SELECT status, title FROM sessions WHERE id = ?', id);
      await q.run(
        `INSERT INTO sessions (id, user_id, device_id, project_id, opencode_session_id, parent_opencode_session_id, directory, title, status,
           status_message, agent, model, additions, deletions, files, current_action, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET project_id = COALESCE(excluded.project_id, sessions.project_id), directory = excluded.directory,
           title = excluded.title, status = excluded.status, status_message = excluded.status_message,
           agent = COALESCE(excluded.agent, sessions.agent), model = COALESCE(excluded.model, sessions.model),
           additions = excluded.additions, deletions = excluded.deletions, files = excluded.files,
           current_action = excluded.current_action, updated_at = excluded.updated_at`,
        id, user.id, device.id, projectExists ? projectId : null, s.opencodeSessionId, s.parentId ?? null, s.directory, s.title || 'Untitled session',
        s.status, s.statusMessage ?? null, s.agent ?? null, s.model ?? null, s.additions, s.deletions, s.files, s.currentAction ?? null, s.createdAt ?? ts, ts,
      );
      const row = await q.get('SELECT s.*, p.name AS project_name FROM sessions s LEFT JOIN projects p ON p.id = s.project_id WHERE s.id = ?', id);
      out.push({ userId: user.id, deviceId: device.id, projectId: row.project_id, sessionId: id, type: 'session.updated', payload: serializeSession(row) });

      // Notifications only on real state transitions reported by the engine.
      if (previous && previous.status !== s.status && !s.parentId) {
        const title = s.title || 'Session';
        if ((previous.status === 'busy' || previous.status === 'retry') && s.status === 'idle') {
          notes.push({ userId: user.id, type: 'session.completed', title: 'Agent finished', body: title, data: { sessionId: id } });
        } else if (s.status === 'error') {
          notes.push({ userId: user.id, type: 'session.failed', title: 'Agent failed', body: title, data: { sessionId: id } });
        }
      }
    }

    for (const ocId of body.removedSessions ?? []) {
      const id = sessionIdFor(ocId);
      if (!(await ownsSession(id))) continue;
      await q.run('DELETE FROM session_parts WHERE session_id = ?', id);
      await q.run('DELETE FROM session_diffs WHERE session_id = ?', id);
      await q.run('DELETE FROM approvals WHERE session_id = ?', id);
      await q.run('UPDATE commands SET session_id = NULL WHERE session_id = ?', id);
      const res = await q.run('DELETE FROM sessions WHERE id = ?', id);
      if (res.changes) out.push({ userId: user.id, deviceId: device.id, sessionId: id, type: 'session.removed', payload: { id } });
    }

    for (const p of body.parts ?? []) {
      const sessionId = sessionIdFor(p.opencodeSessionId);
      if (!(await ownsSession(sessionId))) continue;
      const id = stableId('prt', sessionId, p.partId);
      await q.run(
        `INSERT INTO session_parts (id, session_id, message_id, role, type, text, tool, tool_status, tool_title, sort_key, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET text = excluded.text, tool_status = excluded.tool_status, tool_title = excluded.tool_title, updated_at = excluded.updated_at`,
        id, sessionId, p.messageId, p.role, p.type, p.text?.slice(0, MAX_TEXT) ?? null, p.tool ?? null, p.toolStatus ?? null, p.toolTitle ?? null, p.sortKey, ts,
      );
      out.push({ userId: user.id, deviceId: device.id, sessionId, type: 'session.part', payload: serializePart(await q.get('SELECT * FROM session_parts WHERE id = ?', id)) });
    }

    for (const t of body.transcripts ?? []) {
      const sessionId = sessionIdFor(t.opencodeSessionId);
      if (!(await ownsSession(sessionId))) continue;
      await q.run('DELETE FROM session_parts WHERE session_id = ?', sessionId);
      for (const p of t.parts) {
        await q.run(
          `INSERT INTO session_parts (id, session_id, message_id, role, type, text, tool, tool_status, tool_title, sort_key, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`,
          stableId('prt', sessionId, p.partId), sessionId, p.messageId, p.role, p.type, p.text?.slice(0, MAX_TEXT) ?? null,
          p.tool ?? null, p.toolStatus ?? null, p.toolTitle ?? null, p.sortKey, ts,
        );
      }
      out.push({ userId: user.id, deviceId: device.id, sessionId, type: 'session.transcript', payload: { sessionId, parts: t.parts.length } });
    }

    for (const d of body.diffs ?? []) {
      const sessionId = sessionIdFor(d.opencodeSessionId);
      if (!(await ownsSession(sessionId))) continue;
      await q.run('DELETE FROM session_diffs WHERE session_id = ?', sessionId);
      for (const f of d.files) {
        await q.run(
          'INSERT INTO session_diffs (session_id, file, status, additions, deletions, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (session_id, file) DO NOTHING',
          sessionId, f.file, f.status ?? null, f.additions, f.deletions, ts,
        );
      }
      out.push({ userId: user.id, deviceId: device.id, sessionId, type: 'session.diff', payload: { sessionId, files: d.files } });
    }

    for (const a of body.approvals ?? []) {
      const sessionId = sessionIdFor(a.opencodeSessionId);
      if (!(await ownsSession(sessionId))) continue;
      const id = stableId('apr', device.id, a.requestId);
      const existing = await q.get('SELECT status FROM approvals WHERE id = ?', id);
      if (!existing) {
        await q.run(
          `INSERT INTO approvals (id, user_id, device_id, session_id, opencode_request_id, permission, title, patterns, status, reply, created_at, resolved_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          id, user.id, device.id, sessionId, a.requestId, a.permission, a.title ?? null, JSON.stringify(a.patterns), a.status, a.reply ?? null, ts, a.status === 'PENDING' ? null : ts,
        );
        if (a.status === 'PENDING') {
          notes.push({ userId: user.id, type: 'approval.required', title: 'Approval required', body: `${a.permission}${a.title ? `: ${a.title.slice(0, 120)}` : ''}`, data: { approvalId: id, sessionId } });
        }
      } else if (a.status !== 'PENDING') {
        await q.run('UPDATE approvals SET status = ?, reply = ?, resolved_at = ? WHERE id = ?', a.status, a.reply ?? null, ts, id);
      } else {
        continue;
      }
      out.push({ userId: user.id, deviceId: device.id, sessionId, type: existing ? 'approval.updated' : 'approval.created', payload: serializeApproval(await approvalRow(id)) });
    }

    if (body.pendingApprovalSnapshot) {
      const keep = new Set(body.pendingApprovalSnapshot);
      const pending = await q.all("SELECT id, opencode_request_id, session_id FROM approvals WHERE device_id = ? AND status IN ('PENDING','RESPONDING')", device.id);
      for (const p of pending) {
        if (keep.has(p.opencode_request_id)) continue;
        await q.run("UPDATE approvals SET status = 'EXPIRED', resolved_at = ? WHERE id = ?", ts, p.id);
        out.push({ userId: user.id, deviceId: device.id, sessionId: p.session_id, type: 'approval.updated', payload: serializeApproval(await approvalRow(p.id)) });
      }
    }

    if (body.engine) {
      await q.run(
        `INSERT INTO device_state (device_id, user_id, state, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(device_id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at`,
        device.id, user.id, JSON.stringify(body.engine), ts,
      );
      out.push({ userId: user.id, deviceId: device.id, type: 'engine.updated', payload: body.engine });
    }

    for (const a of body.activity ?? []) {
      const sessionId = a.opencodeSessionId ? sessionIdFor(a.opencodeSessionId) : null;
      out.push({ userId: user.id, deviceId: device.id, sessionId, type: 'activity', payload: { kind: a.type, summary: a.summary, data: a.data ?? {} } });
    }
  });

  for (const e of out) await publish(e);
  for (const n of notes) await notify(n);
  return c.json({ data: { accepted: true, events: out.length } });
});
