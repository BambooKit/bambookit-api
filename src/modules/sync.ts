import { Hono } from 'hono';
import { z } from 'zod';
import { db, now } from '../db/database.js';
import { requireDevice, requireUser, type AppEnv } from '../middleware/auth.js';
import { stableId } from '../lib/http.js';
import { emitEphemeral, publish } from '../realtime/bus.js';
import { notify } from './notifications.js';
import { serializeApproval, serializeProject, serializeSession } from './serializers.js';

/**
 * Desktop → API state sync. The PC is the only place session content is stored. The API keeps a
 * small index (projects and sessions: names, titles, status, timestamps) plus approvals, so phones
 * and the website can list sessions and answer approvals. Chat parts, diffs and activity are passed
 * straight to connected clients as live-only events and are never written to the database.
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
        // True once the user has continued this session on the PC; only then may phones chat in it.
        remote: z.boolean().default(false),
        createdAt: z.string().optional(),
      }),
    )
    .max(500)
    .optional(),
  removedSessions: z.array(z.string().max(200)).max(500).optional(),
  parts: z.array(partSchema).max(500).optional(),
  // A session's transcript changed as a whole (rewind, deletions): clients refetch it from the PC.
  transcriptsChanged: z.array(z.string().max(200)).max(50).optional(),
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
        kind: z.enum(['permission', 'question']).default('permission'),
        questions: z
          .array(
            z.object({
              header: z.string().max(200).default(''),
              question: z.string().max(4000),
              options: z.array(z.object({ label: z.string().max(500), description: z.string().max(2000).default('') })).max(30).default([]),
              multiple: z.boolean().optional(),
              custom: z.boolean().optional(),
            }),
          )
          .max(10)
          .nullish(),
        answers: z.array(z.array(z.string().max(2000)).max(50)).max(10).nullish(),
      }),
    )
    .max(200)
    .optional(),
  // The agent's todo list per session, passed live to open streams (the PC is the source of truth).
  todos: z
    .array(
      z.object({
        opencodeSessionId: z.string().max(200),
        todos: z.array(z.object({ id: z.string().max(200), content: z.string().max(4000), status: z.string().max(40), priority: z.string().max(40).nullish() })).max(500),
      }),
    )
    .max(50)
    .optional(),
  // Complete list of request ids still pending on the desktop; anything else pending is expired.
  pendingApprovalSnapshot: z.array(z.string().max(200)).max(500).optional(),
  activity: z
    .array(z.object({ opencodeSessionId: z.string().max(200).nullish(), type: z.string().max(60), summary: z.string().max(1000), data: z.record(z.unknown()).optional() }))
    .max(200)
    .optional(),
});

export type SyncPayload = z.infer<typeof syncSchema>;
export type PartSync = z.infer<typeof partSchema>;

/** Shape clients receive for a chat part (same for live events and transcripts fetched from the PC). */
export function partView(sessionId: string, p: PartSync, ts: string) {
  return {
    id: stableId('prt', sessionId, p.partId),
    sessionId,
    messageId: p.messageId,
    role: p.role,
    type: p.type,
    text: p.text?.slice(0, MAX_TEXT) ?? null,
    tool: p.tool ?? null,
    toolStatus: p.toolStatus ?? null,
    toolTitle: p.toolTitle ?? null,
    sortKey: p.sortKey,
    updatedAt: ts,
  };
}

/**
 * One part of the complete transcript the PC returns on request (GET /v1/sessions/:id/parts): the live shape
 * plus full text and tool details. Only known fields are passed on; nothing here is stored.
 */
export function transcriptPartView(sessionId: string, p: any, ts: string) {
  const str = (v: unknown, max: number) => (typeof v === 'string' ? v.slice(0, max) : null);
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
  const flag = (v: unknown) => v === true;
  const time = p?.time && typeof p.time === 'object' ? { start: num(p.time.start), end: num(p.time.end) } : null;
  const base = { ...partView(sessionId, { ...p, text: null }, ts), text: str(p?.text, 1_048_576), truncated: flag(p?.truncated), time };
  if (p?.type !== 'tool') return base;
  return {
    ...base,
    callId: str(p.callId, 200),
    status: str(p.status, 40),
    title: str(p.title, 2000),
    input: p.input && typeof p.input === 'object' ? p.input : null,
    inputTruncated: flag(p.inputTruncated),
    output: str(p.output, 262_144),
    outputTruncated: flag(p.outputTruncated),
    error: str(p.error, 65_536),
    diff: str(p.diff, 524_288),
    diffTruncated: flag(p.diffTruncated),
    exitCode: num(p.exitCode),
    files: Array.isArray(p.files) ? p.files.slice(0, 200) : null,
  };
}

syncRouter.post('/', async (c) => {
  const user = c.get('user');
  const device = c.get('device')!;
  const body = syncSchema.parse(JSON.parse(await c.req.text()));
  const ts = now();
  const out: Array<Parameters<typeof publish>[0]> = [];
  const live: Array<Parameters<typeof emitEphemeral>[0]> = [];
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
           status_message, agent, model, additions, deletions, files, current_action, remote, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET project_id = COALESCE(excluded.project_id, sessions.project_id), directory = excluded.directory,
           title = excluded.title, status = excluded.status, status_message = excluded.status_message,
           agent = COALESCE(excluded.agent, sessions.agent), model = COALESCE(excluded.model, sessions.model),
           additions = excluded.additions, deletions = excluded.deletions, files = excluded.files,
           current_action = excluded.current_action, remote = excluded.remote, updated_at = excluded.updated_at`,
        id, user.id, device.id, projectExists ? projectId : null, s.opencodeSessionId, s.parentId ?? null, s.directory, s.title || 'Untitled session',
        s.status, s.statusMessage ?? null, s.agent ?? null, s.model ?? null, s.additions, s.deletions, s.files, s.currentAction ?? null, s.remote ? 1 : 0, s.createdAt ?? ts, ts,
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
      live.push({ userId: user.id, deviceId: device.id, sessionId, type: 'session.part', payload: partView(sessionId, p, ts) });
    }

    for (const ocId of body.transcriptsChanged ?? []) {
      const sessionId = sessionIdFor(ocId);
      if (!(await ownsSession(sessionId))) continue;
      live.push({ userId: user.id, deviceId: device.id, sessionId, type: 'session.transcript', payload: { sessionId } });
    }

    for (const d of body.diffs ?? []) {
      const sessionId = sessionIdFor(d.opencodeSessionId);
      if (!(await ownsSession(sessionId))) continue;
      live.push({ userId: user.id, deviceId: device.id, sessionId, type: 'session.diff', payload: { sessionId, files: d.files } });
    }

    for (const a of body.approvals ?? []) {
      const sessionId = sessionIdFor(a.opencodeSessionId);
      if (!(await ownsSession(sessionId))) continue;
      const id = stableId('apr', device.id, a.requestId);
      const existing = await q.get('SELECT status FROM approvals WHERE id = ?', id);
      if (!existing) {
        await q.run(
          `INSERT INTO approvals (id, user_id, device_id, session_id, opencode_request_id, permission, title, patterns, status, reply, kind, questions, answers, created_at, resolved_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          id, user.id, device.id, sessionId, a.requestId, a.permission, a.title ?? null, JSON.stringify(a.patterns), a.status, a.reply ?? null,
          a.kind, a.questions ? JSON.stringify(a.questions) : null, a.answers ? JSON.stringify(a.answers) : null, ts, a.status === 'PENDING' ? null : ts,
        );
        if (a.status === 'PENDING') {
          notes.push(
            a.kind === 'question'
              ? { userId: user.id, type: 'question.asked', title: 'BambooKit has a question', body: (a.title ?? a.questions?.[0]?.question ?? 'The agent needs your answer').slice(0, 200), data: { approvalId: id, sessionId } }
              : { userId: user.id, type: 'approval.required', title: 'Approval required', body: `${a.permission}${a.title ? `: ${a.title.slice(0, 120)}` : ''}`, data: { approvalId: id, sessionId } },
          );
        }
      } else if (a.status !== 'PENDING') {
        await q.run('UPDATE approvals SET status = ?, reply = ?, answers = COALESCE(?, answers), resolved_at = ? WHERE id = ?', a.status, a.reply ?? null, a.answers ? JSON.stringify(a.answers) : null, ts, id);
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

    for (const t of body.todos ?? []) {
      const sessionId = sessionIdFor(t.opencodeSessionId);
      if (!(await ownsSession(sessionId))) continue;
      live.push({ userId: user.id, deviceId: device.id, sessionId, type: 'session.todos', payload: { sessionId, todos: t.todos } });
    }

    for (const a of body.activity ?? []) {
      const sessionId = a.opencodeSessionId ? sessionIdFor(a.opencodeSessionId) : null;
      live.push({ userId: user.id, deviceId: device.id, sessionId, type: 'activity', payload: { kind: a.type, summary: a.summary, data: a.data ?? {} } });
    }
  });

  for (const e of out) await publish(e);
  for (const e of live) emitEphemeral(e);
  for (const n of notes) await notify(n);
  return c.json({ data: { accepted: true, events: out.length } });
});
