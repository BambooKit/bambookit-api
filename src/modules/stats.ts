import { Hono } from 'hono';
import { z } from 'zod';
import { db, now, type Queryable } from '../db/database.js';
import { requireUser, type AppEnv } from '../middleware/auth.js';
import { newId, notFound } from '../lib/http.js';
import { publish } from '../realtime/bus.js';
import { notify } from './notifications.js';

/**
 * Profile statistics, coding time and achievements — all computed from real BambooKit records.
 *
 * Coding time: a session "works" from the moment the engine reports it busy until it reports idle or
 * error. Each such stretch is one work interval (one agent task). Time the app is merely open does not
 * count. A single interval is capped at MAX_INTERVAL_MS so a PC that loses power mid-task cannot add days.
 *
 * Code statistics: the PC reports per-session totals (files created/modified/deleted/renamed, lines added
 * and deleted, tests, commits, deployments) computed from its own edit history. They replace the previous
 * totals for that session on every sync, so the same event is never counted twice. Rule for a file edited
 * several times in one session: it counts once in files* (by its final state) and every edit counts in
 * `edits` and in the line totals.
 */

export const MAX_INTERVAL_MS = 6 * 60 * 60 * 1000;
const NIGHT_START_HOUR = 22;
const NIGHT_END_HOUR = 5;

export async function trackWork(
  q: Queryable,
  input: { userId: string; sessionId: string; projectId: string | null; previous: string | null; status: string; parent: boolean; ts: string },
) {
  const working = (s: string | null) => s === 'busy' || s === 'retry';
  if (working(input.status) && !working(input.previous)) {
    await q.run('UPDATE sessions SET busy_since = COALESCE(busy_since, ?) WHERE id = ?', input.ts, input.sessionId);
    return;
  }
  if (working(input.status) || !working(input.previous)) return;
  const row = await q.get<{ busy_since: string | null }>('SELECT busy_since FROM sessions WHERE id = ?', input.sessionId);
  await q.run('UPDATE sessions SET busy_since = NULL WHERE id = ?', input.sessionId);
  if (!row?.busy_since) return;
  const ms = Math.max(0, Math.min(MAX_INTERVAL_MS, Date.parse(input.ts) - Date.parse(row.busy_since)));
  const outcome = input.status === 'error' ? 'failed' : 'completed';
  await q.run(
    `UPDATE sessions SET active_ms = active_ms + ?, ${outcome === 'failed' ? 'tasks_failed = tasks_failed + 1' : 'tasks_completed = tasks_completed + 1'} WHERE id = ?`,
    ms,
    input.sessionId,
  );
  await q.run(
    'INSERT INTO work_intervals (id, user_id, project_id, session_id, started_at, ended_at, duration_ms, outcome) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    newId('wrk'), input.userId, input.projectId, input.sessionId, row.busy_since, input.ts, ms, outcome,
  );
}

type SessionStats = {
  filesCreated: number; filesModified: number; filesDeleted: number; filesRenamed: number;
  linesAdded: number; linesDeleted: number; edits: number;
  testsRun: number; testsPassed: number; testsFailed: number; commits: number; deployments: number; debugging: boolean;
};
const ZERO: SessionStats = {
  filesCreated: 0, filesModified: 0, filesDeleted: 0, filesRenamed: 0, linesAdded: 0, linesDeleted: 0, edits: 0,
  testsRun: 0, testsPassed: 0, testsFailed: 0, commits: 0, deployments: 0, debugging: false,
};

function parseStats(raw: unknown): SessionStats {
  if (typeof raw !== 'string' || !raw) return ZERO;
  try {
    return { ...ZERO, ...JSON.parse(raw) };
  } catch {
    return ZERO;
  }
}

/** Hour of day and calendar boundaries in the user's time zone (IANA name; UTC when unknown). */
function zoned(timeZone: string | null) {
  let tz = 'UTC';
  try {
    if (timeZone) {
      new Intl.DateTimeFormat('en-US', { timeZone });
      tz = timeZone;
    }
  } catch {}
  const parts = (d: Date) => {
    const p = Object.fromEntries(
      new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', weekday: 'short' })
        .formatToParts(d)
        .map((x) => [x.type, x.value]),
    );
    return { year: +p.year, month: +p.month, day: +p.day, hour: +p.hour, weekday: p.weekday as string };
  };
  return { tz, parts };
}

/** Milliseconds of [start, end) that fall within night hours (22:00–05:00 local), sampled every 5 minutes. */
function nightMs(start: number, end: number, parts: ReturnType<typeof zoned>['parts']) {
  let total = 0;
  const step = 5 * 60_000;
  for (let t = start; t < end; t += step) {
    const h = parts(new Date(t)).hour;
    if (h >= NIGHT_START_HOUR || h < NIGHT_END_HOUR) total += Math.min(step, end - t);
  }
  return total;
}

export async function computeStats(userId: string) {
  const user = await db.get<{ created_at: string; timezone: string | null }>('SELECT created_at, timezone FROM users WHERE id = ?', userId);
  const { tz, parts } = zoned(user?.timezone ?? null);
  const projects = await db.all<any>('SELECT id, name, status, branch, created_at, updated_at FROM projects WHERE user_id = ?', userId);
  const sessions = await db.all<any>(
    'SELECT id, project_id, status, stats, active_ms, tasks_completed, tasks_failed, created_at, updated_at FROM sessions WHERE user_id = ? AND parent_opencode_session_id IS NULL',
    userId,
  );
  const intervals = await db.all<any>('SELECT project_id, started_at, ended_at, duration_ms FROM work_intervals WHERE user_id = ?', userId);

  const nowDate = new Date();
  const today = parts(nowDate);
  const weekdayIndex = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].indexOf(today.weekday);
  const sameMonth = (d: Date) => {
    const p = parts(d);
    return p.year === today.year && p.month === today.month;
  };
  // Start of this calendar week (Monday) in the user's time zone, approximated to the hour boundary.
  const weekStart = nowDate.getTime() - (weekdayIndex * 24 + today.hour) * 3_600_000 - (nowDate.getTime() % 3_600_000);

  let total = 0, week = 0, month = 0, night = 0, longest = 0;
  const perProject = new Map<string, number>();
  for (const i of intervals) {
    const ms = Number(i.duration_ms) || 0;
    const start = Date.parse(i.started_at);
    total += ms;
    if (start >= weekStart) week += ms;
    if (sameMonth(new Date(start))) month += ms;
    longest = Math.max(longest, ms);
    night += nightMs(start, start + ms, parts);
    if (i.project_id) perProject.set(i.project_id, (perProject.get(i.project_id) ?? 0) + ms);
  }

  const code = { ...ZERO, debugging: 0 } as Record<string, number>;
  let tasksCompleted = 0, tasksFailed = 0, debuggingTasks = 0, sessionsWithWork = 0;
  const projectSessions = new Map<string, { sessions: number; tasks: number; files: number; last: string }>();
  for (const s of sessions) {
    const st = parseStats(s.stats);
    for (const k of Object.keys(ZERO) as Array<keyof SessionStats>) if (k !== 'debugging') code[k] += Number(st[k]) || 0;
    tasksCompleted += Number(s.tasks_completed) || 0;
    tasksFailed += Number(s.tasks_failed) || 0;
    if (Number(s.tasks_completed) > 0) sessionsWithWork++;
    if (st.debugging && Number(s.tasks_completed) > 0) debuggingTasks++;
    if (s.project_id) {
      const p = projectSessions.get(s.project_id) ?? { sessions: 0, tasks: 0, files: 0, last: s.updated_at };
      p.sessions++;
      p.tasks += (Number(s.tasks_completed) || 0) + (Number(s.tasks_failed) || 0);
      p.files += st.filesCreated + st.filesModified + st.filesDeleted + st.filesRenamed;
      if (s.updated_at > p.last) p.last = s.updated_at;
      projectSessions.set(s.project_id, p);
    }
  }
  delete code.debugging;

  const byStatus = (status: string) => projects.filter((p) => (p.status ?? 'active') === status).length;
  const projectList = projects
    .map((p) => {
      const ps = projectSessions.get(p.id);
      return {
        id: p.id,
        name: p.name,
        status: p.status ?? 'active',
        branch: p.branch ?? null,
        createdAt: p.created_at,
        updatedAt: p.updated_at,
        lastActivityAt: ps?.last && ps.last > p.updated_at ? ps.last : p.updated_at,
        sessions: ps?.sessions ?? 0,
        tasks: ps?.tasks ?? 0,
        filesChanged: ps?.files ?? 0,
        codingMs: perProject.get(p.id) ?? 0,
      };
    })
    .sort((a, b) => b.lastActivityAt.localeCompare(a.lastActivityAt));

  return {
    timeZone: tz,
    memberSince: user?.created_at ?? null,
    projects: { total: projects.length, active: byStatus('active'), completed: byStatus('completed'), archived: byStatus('archived'), list: projectList },
    sessions: { total: sessions.length, withCompletedWork: sessionsWithWork },
    tasks: { total: tasksCompleted + tasksFailed, completed: tasksCompleted, failed: tasksFailed, debugging: debuggingTasks },
    codingTime: { totalMs: total, thisWeekMs: week, thisMonthMs: month, nightMs: night, longestMs: longest },
    code: code as Omit<SessionStats, 'debugging'>,
    rules: {
      codingTime: 'Time the agent was working (busy → idle/error), per task; app-open time does not count; one task counts at most 6 h.',
      files: 'Per session, each file counts once by its final state; every edit counts in edits and line totals.',
      nightHours: `${NIGHT_START_HOUR}:00–0${NIGHT_END_HOUR}:00 in ${tz}`,
    },
  };
}

type Stats = Awaited<ReturnType<typeof computeStats>>;

/** Achievement definitions. Add new ones here; state is stored per user in user_achievements. */
export const ACHIEVEMENTS: Array<{ id: string; title: string; description: string; target: number; unit?: 'ms'; value: (s: Stats) => number }> = [
  { id: 'first-project', title: 'First Project', description: 'Open your first project in BambooKit.', target: 1, value: (s) => s.projects.total },
  { id: 'first-session', title: 'First Session', description: 'Complete your first AI coding session.', target: 1, value: (s) => s.sessions.withCompletedWork },
  { id: 'first-change', title: 'First Change', description: 'Make your first code change through BambooKit.', target: 1, value: (s) => s.code.edits },
  { id: 'hundred-files', title: '100 Files', description: 'Create or modify 100 files.', target: 100, value: (s) => s.code.filesCreated + s.code.filesModified },
  { id: 'thousand-lines', title: '1,000 Lines', description: 'Add 1,000 lines of code.', target: 1000, value: (s) => s.code.linesAdded },
  { id: 'code-builder', title: 'Code Builder', description: 'Complete 10 agent tasks.', target: 10, value: (s) => s.tasks.completed },
  { id: 'project-manager', title: 'Project Manager', description: 'Manage 5 projects.', target: 5, value: (s) => s.projects.total },
  { id: 'night-coder', title: 'Night Coder', description: 'Code for 2 hours between 22:00 and 05:00.', target: 2 * 3_600_000, unit: 'ms', value: (s) => s.codingTime.nightMs },
  { id: 'debugger', title: 'Debugger', description: 'Complete 3 debugging sessions.', target: 3, value: (s) => s.tasks.debugging },
  { id: 'tester', title: 'Tester', description: 'Run 10 passing test commands.', target: 10, value: (s) => s.code.testsPassed },
  { id: 'ship-it', title: 'Ship It', description: 'Complete a deployment.', target: 1, value: (s) => s.code.deployments },
  { id: 'agent-commander', title: 'Agent Commander', description: 'Run 10 agent sessions.', target: 10, value: (s) => s.sessions.withCompletedWork },
  { id: 'long-session', title: 'Long Session', description: 'Keep the agent working on one task for an hour.', target: 3_600_000, unit: 'ms', value: (s) => s.codingTime.longestMs },
  { id: 'cleanup-crew', title: 'Cleanup Crew', description: 'Remove 500 lines of obsolete code.', target: 500, value: (s) => s.code.linesDeleted },
  { id: 'marathon', title: 'Marathon', description: 'Reach 24 hours of total coding time.', target: 24 * 3_600_000, unit: 'ms', value: (s) => s.codingTime.totalMs },
];

/** Unlocks achievements whose targets are now met. Idempotent: each one unlocks once per user. */
export async function refreshAchievements(userId: string, stats?: Stats) {
  const s = stats ?? (await computeStats(userId));
  const have = new Set((await db.all<{ achievement: string }>('SELECT achievement FROM user_achievements WHERE user_id = ?', userId)).map((r) => r.achievement));
  for (const a of ACHIEVEMENTS) {
    if (have.has(a.id) || a.value(s) < a.target) continue;
    const ts = now();
    const res = await db.run('INSERT INTO user_achievements (user_id, achievement, unlocked_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING', userId, a.id, ts);
    if (res.changes !== 1) continue;
    await publish({ userId, type: 'achievement.unlocked', payload: { id: a.id, title: a.title, unlockedAt: ts } });
    await notify({ userId, type: 'achievement.unlocked', title: 'Achievement unlocked', body: a.title, data: { achievementId: a.id } });
  }
  return s;
}

export async function achievementList(userId: string, stats: Stats) {
  const unlocked = new Map(
    (await db.all<{ achievement: string; unlocked_at: string }>('SELECT achievement, unlocked_at FROM user_achievements WHERE user_id = ?', userId)).map((r) => [r.achievement, r.unlocked_at]),
  );
  return ACHIEVEMENTS.map((a) => ({
    id: a.id,
    title: a.title,
    description: a.description,
    progress: Math.min(a.value(stats), a.target),
    target: a.target,
    unit: a.unit ?? 'count',
    unlocked: unlocked.has(a.id),
    unlockedAt: unlocked.get(a.id) ?? null,
  }));
}

export const statsRouter = new Hono<AppEnv>();
statsRouter.use('*', requireUser);

// GET /v1/me/stats — profile statistics, projects managed and achievements
statsRouter.get('/me/stats', async (c) => {
  const userId = c.get('user').id;
  const stats = await refreshAchievements(userId);
  return c.json({ data: { ...stats, achievements: await achievementList(userId, stats) } });
});

// GET /v1/me/achievements
statsRouter.get('/me/achievements', async (c) => {
  const userId = c.get('user').id;
  return c.json({ data: await achievementList(userId, await refreshAchievements(userId)) });
});

// PATCH /v1/projects/:id { status: active | completed | archived } — the user's own project status
statsRouter.patch('/projects/:id', async (c) => {
  const user = c.get('user');
  const { status } = z.object({ status: z.enum(['active', 'completed', 'archived']) }).parse(await c.req.json());
  const project = await db.get<{ id: string; device_id: string }>('SELECT id, device_id FROM projects WHERE id = ? AND user_id = ?', c.req.param('id'), user.id);
  if (!project) throw notFound('Project');
  await db.run('UPDATE projects SET status = ? WHERE id = ?', status, project.id);
  const row = await db.get('SELECT * FROM projects WHERE id = ?', project.id);
  await publish({ userId: user.id, deviceId: project.device_id, projectId: project.id, type: 'project.updated', payload: { id: project.id, status } });
  return c.json({ data: { id: project.id, status: row.status } });
});
