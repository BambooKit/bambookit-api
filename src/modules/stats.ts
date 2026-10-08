import { Hono } from 'hono';
import { z } from 'zod';
import { db, now, type Queryable } from '../db/database.js';
import { requireUser, type AppEnv } from '../middleware/auth.js';
import { newId, notFound } from '../lib/http.js';
import { publish } from '../realtime/bus.js';
import { notify } from './notifications.js';
import { logger } from '../lib/logger.js';

/**
 * Profile statistics, coding time and achievements — all computed from real BambooKit records.
 *
 * Coding time: a session "works" from the moment the engine reports it busy until it reports idle or
 * error. Each such stretch is one work interval (one agent task). Time the app is merely open does not
 * count. A single interval is capped at MAX_INTERVAL_MS so a PC that loses power mid-task cannot add days.
 *
 * Code statistics: the PC reports per-session totals (files created/modified/deleted/renamed, lines added
 * and deleted, tests, commits, deployments; from desktop 1.0.6 also prompts, tool calls, shell commands,
 * sub-agents, MCP tools, agents, installs, branches, merges, pull requests, cloud deployments, cleanups,
 * documentation files, session intents, retries and active time) computed from its own records. They replace the previous
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

/** Counters the PC reports per session (summed over the user's sessions). Desktops before 1.0.6 send only the first 12. */
const CODE_KEYS = [
  'filesCreated', 'filesModified', 'filesDeleted', 'filesRenamed', 'linesAdded', 'linesDeleted', 'edits',
  'testsRun', 'testsPassed', 'testsFailed', 'commits', 'deployments',
] as const;
const ACTIVITY_KEYS = [
  'prompts', 'bugPrompts', 'toolCalls', 'terminalCommands', 'subagentTasks', 'mcpToolCalls', 'packagesInstalled',
  'branches', 'merges', 'pullRequests', 'cloudDeployments', 'cleanups', 'docFiles',
] as const;
type CodeKey = (typeof CODE_KEYS)[number];
type ActivityKey = (typeof ACTIVITY_KEYS)[number];

type RawStats = Partial<Record<CodeKey | ActivityKey | 'retries' | 'activeSeconds', number>> & {
  debugging?: boolean; refactoring?: boolean; review?: boolean; experiment?: boolean; firstTryPass?: boolean;
  mcpTools?: string[]; agents?: string[];
};

function parseStats(raw: unknown): RawStats {
  if (typeof raw !== 'string' || !raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0);
const strings = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.length > 0) : []);

/** Calendar parts in the user's time zone (IANA name; UTC when unknown). One formatter per call of computeStats. */
function zoned(timeZone: string | null) {
  let tz = 'UTC';
  try {
    if (timeZone) {
      new Intl.DateTimeFormat('en-US', { timeZone });
      tz = timeZone;
    }
  } catch {}
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', weekday: 'short',
  });
  const parts = (d: Date) => {
    const p = Object.fromEntries(fmt.formatToParts(d).map((x) => [x.type, x.value]));
    return { year: +p.year, month: +p.month, day: +p.day, hour: +p.hour % 24, minute: +p.minute, second: +p.second, weekday: p.weekday as string };
  };
  /** Offset of local time from UTC at instant t, in ms (local = t + offset). */
  const offset = (t: number) => {
    const p = parts(new Date(t));
    return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - Math.floor(t / 1000) * 1000;
  };
  return { tz, parts, offset };
}

const DAY_MS = 86_400_000;
/** Local day number (days since 1970-01-01 in local time) of instant t with the given offset. */
const dayOf = (t: number, offset: number) => Math.floor((t + offset) / DAY_MS);

/**
 * Night time and nights of one work interval: milliseconds within 22:00–05:00 local time and the nights
 * they belong to (a night is named by the local day it started on, so 01:00 counts for the evening before).
 * Uses the offset at the interval's start (intervals are at most 6 h, so a DST change inside one shifts at most an hour).
 */
function nightsOf(start: number, end: number, offset: number, nights: Set<number>) {
  let ms = 0;
  let t = start;
  while (t < end) {
    const local = t + offset;
    const day = Math.floor(local / DAY_MS);
    const hourMs = local - day * DAY_MS;
    let windowEnd: number; // local ms where the current night/day window ends
    let night: number | null;
    if (hourMs < NIGHT_END_HOUR * 3_600_000) {
      night = day - 1;
      windowEnd = day * DAY_MS + NIGHT_END_HOUR * 3_600_000;
    } else if (hourMs >= NIGHT_START_HOUR * 3_600_000) {
      night = day;
      windowEnd = (day + 1) * DAY_MS + NIGHT_END_HOUR * 3_600_000;
    } else {
      night = null;
      windowEnd = day * DAY_MS + NIGHT_START_HOUR * 3_600_000;
    }
    const next = Math.min(end, windowEnd - offset);
    if (night !== null && next > t) {
      ms += next - t;
      nights.add(night);
    }
    t = Math.max(next, t + 1);
  }
  return ms;
}

/** Longest run of consecutive days, and the run that ends today or yesterday (else 0). */
export function streaks(days: Iterable<number>, today: number) {
  const sorted = [...new Set(days)].sort((a, b) => a - b);
  let longest = 0, run = 0, prev = Number.NaN;
  for (const d of sorted) {
    run = d === prev + 1 ? run + 1 : 1;
    longest = Math.max(longest, run);
    prev = d;
  }
  const set = new Set(sorted);
  let current = 0;
  let d = set.has(today) ? today : set.has(today - 1) ? today - 1 : null;
  while (d !== null && set.has(d)) {
    current++;
    d--;
  }
  return { current, longest };
}

/** MCP server of a tool name: the part before the first '_' (e.g. github_create_issue → github), else the name. */
export function mcpServer(tool: string) {
  const i = tool.indexOf('_');
  return i > 0 ? tool.slice(0, i) : tool;
}

/** Everything the profile and the achievements need, from a handful of aggregate queries (no per-achievement queries). */
async function gather(userId: string) {
  const user = await db.get<{ created_at: string; timezone: string | null; key_changes: number | null }>('SELECT created_at, timezone, key_changes FROM users WHERE id = ?', userId);
  const { tz, parts, offset } = zoned(user?.timezone ?? null);
  const projects = await db.all<any>('SELECT id, name, status, branch, created_at, updated_at FROM projects WHERE user_id = ?', userId);
  const sessions = await db.all<any>(
    'SELECT id, project_id, status, agent, stats, active_ms, tasks_completed, tasks_failed, created_at, updated_at FROM sessions WHERE user_id = ? AND parent_opencode_session_id IS NULL',
    userId,
  );
  const intervals = await db.all<any>(
    `SELECT w.project_id, w.started_at, w.ended_at, w.duration_ms, w.outcome, s.parent_opencode_session_id AS parent
     FROM work_intervals w LEFT JOIN sessions s ON s.id = w.session_id WHERE w.user_id = ?`,
    userId,
  );
  const agentRows = await db.all<{ agent: string }>('SELECT DISTINCT agent FROM sessions WHERE user_id = ? AND agent IS NOT NULL', userId);
  const approvalRows = await db.all<{ kind: string | null; status: string; n: number }>(
    // Requests the PC approved by itself (approval mode) are not answers by the user.
    "SELECT kind, status, COUNT(*) AS n FROM approvals WHERE user_id = ? AND (resolved_by IS NULL OR resolved_by <> 'auto') GROUP BY kind, status",
    userId,
  );
  const deviceRow = await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM devices WHERE user_id = ?', userId);

  const nowDate = new Date();
  const nowMs = nowDate.getTime();
  const nowOffset = offset(nowMs);
  const today = parts(nowDate);
  const todayNum = dayOf(nowMs, nowOffset);
  const weekdayIndex = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].indexOf(today.weekday);
  // Start of this calendar week (Monday 00:00) and month in the user's time zone.
  const weekStart = (todayNum - weekdayIndex) * DAY_MS - nowOffset;
  const monthStart = Date.UTC(today.year, today.month - 1, 1) - nowOffset;

  let total = 0, week = 0, month = 0, night = 0, longest = 0, speedTasks = 0;
  const perProject = new Map<string, number>();
  const activeDays = new Set<number>();
  const nights = new Set<number>();
  for (const i of intervals) {
    const ms = Number(i.duration_ms) || 0;
    const start = Date.parse(i.started_at);
    if (!Number.isFinite(start)) continue;
    total += ms;
    if (start >= weekStart) week += ms;
    if (start >= monthStart) month += ms;
    longest = Math.max(longest, ms);
    const off = offset(start);
    night += nightsOf(start, start + ms, off, nights);
    for (let d = dayOf(start, off); d <= dayOf(start + ms, off); d++) activeDays.add(d);
    if (i.project_id) perProject.set(i.project_id, (perProject.get(i.project_id) ?? 0) + ms);
    if (!i.parent && i.outcome === 'completed' && ms > 0 && ms <= 5 * 60_000) speedTasks++;
  }

  const code = Object.fromEntries(CODE_KEYS.map((k) => [k, 0])) as Record<CodeKey, number>;
  const activity = Object.fromEntries(ACTIVITY_KEYS.map((k) => [k, 0])) as Record<ActivityKey, number>;
  const mcpTools = new Set<string>();
  const agents = new Set<string>(agentRows.map((r) => r.agent).filter(Boolean));
  const builtProjects = new Set<string>();
  const counts = {
    bugsFixed: 0, fastFixes: 0, oneShotFixes: 0, noRetryTasks: 0, successfulSessions: 0, productionFixes: 0,
    reviews: 0, refactors: 0, experiments: 0, longestSessionMs: 0,
  };
  let tasksCompleted = 0, tasksFailed = 0, sessionsWithWork = 0;
  const projectSessions = new Map<string, { sessions: number; tasks: number; files: number; last: string }>();
  for (const s of sessions) {
    const st = parseStats(s.stats);
    for (const k of CODE_KEYS) code[k] += num(st[k]);
    for (const k of ACTIVITY_KEYS) activity[k] += num(st[k]);
    for (const t of strings(st.mcpTools)) mcpTools.add(t);
    for (const a of strings(st.agents)) agents.add(a);
    const done = Number(s.tasks_completed) || 0;
    const failed = Number(s.tasks_failed) || 0;
    const files = num(st.filesCreated) + num(st.filesModified) + num(st.filesDeleted) + num(st.filesRenamed);
    const activeMs = Math.max(Number(s.active_ms) || 0, num(st.activeSeconds) * 1000);
    tasksCompleted += done;
    tasksFailed += failed;
    counts.longestSessionMs = Math.max(counts.longestSessionMs, activeMs);
    if (done > 0) {
      sessionsWithWork++;
      if (st.debugging) {
        counts.bugsFixed++;
        if (activeMs > 0 && activeMs <= 10 * 60_000) counts.fastFixes++;
        if (st.prompts === 1 && failed === 0) counts.oneShotFixes++;
        if (num(st.deployments) + num(st.cloudDeployments) > 0) counts.productionFixes++;
      }
      // Only desktops that report retries (1.0.6+) can prove a session needed none.
      if (typeof st.retries === 'number' && st.retries === 0 && failed === 0 && s.status !== 'error') counts.noRetryTasks++;
      if (s.status === 'idle' && files > 0 && (num(st.testsFailed) === 0 || num(st.testsPassed) > 0)) counts.successfulSessions++;
      if (st.review) counts.reviews++;
      if (st.refactoring) counts.refactors++;
      if (st.experiment) counts.experiments++;
    }
    if (s.project_id && files > 0) builtProjects.add(s.project_id);
    if (s.project_id) {
      const p = projectSessions.get(s.project_id) ?? { sessions: 0, tasks: 0, files: 0, last: s.updated_at };
      p.sessions++;
      p.tasks += done + failed;
      p.files += files;
      if (s.updated_at > p.last) p.last = s.updated_at;
      projectSessions.set(s.project_id, p);
    }
    const created = Date.parse(s.created_at);
    if (Number.isFinite(created)) activeDays.add(dayOf(created, offset(created)));
  }

  let approvalsAnswered = 0;
  for (const r of approvalRows) {
    if ((r.kind ?? 'permission') === 'permission' && (r.status === 'APPROVED' || r.status === 'REJECTED')) approvalsAnswered += Number(r.n) || 0;
  }
  const streak = streaks(activeDays, todayNum);

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

  const stats = {
    timeZone: tz,
    memberSince: user?.created_at ?? null,
    projects: { total: projects.length, active: byStatus('active'), completed: byStatus('completed'), archived: byStatus('archived'), list: projectList },
    sessions: { total: sessions.length, withCompletedWork: sessionsWithWork },
    tasks: { total: tasksCompleted + tasksFailed, completed: tasksCompleted, failed: tasksFailed, debugging: counts.bugsFixed },
    codingTime: { totalMs: total, thisWeekMs: week, thisMonthMs: month, nightMs: night, longestMs: longest },
    code,
    activity: { ...activity, mcpTools: mcpTools.size, agents: agents.size, approvalsAnswered, nights: nights.size },
    streak,
    rules: {
      codingTime: 'Time the agent was working (busy → idle/error), per task; app-open time does not count; one task counts at most 6 h.',
      files: 'Per session, each file counts once by its final state; every edit counts in edits and line totals.',
      nightHours: `${NIGHT_START_HOUR}:00–0${NIGHT_END_HOUR}:00 in ${tz}`,
      streak: `Consecutive days in ${tz} with agent work or a new session.`,
    },
  };

  const hours = (ms: number) => Math.floor(ms / 360_000) / 10;
  const values: Record<string, number> = {
    'coding-streak': streak.longest,
    'code-written': code.linesAdded,
    'code-changes': code.edits,
    'files-changed': code.filesCreated + code.filesModified + code.filesDeleted + code.filesRenamed,
    'projects-built': builtProjects.size,
    'ai-sessions': sessionsWithWork,
    'prompts-sent': activity.prompts,
    'tasks-completed': tasksCompleted,
    'bugs-fixed': counts.bugsFixed,
    'bug-hunter': activity.bugPrompts,
    'tests-run': code.testsRun,
    'tests-passed': code.testsPassed,
    deployments: code.deployments,
    'cloud-builder': activity.cloudDeployments,
    commits: code.commits,
    'branches-created': activity.branches,
    merges: activity.merges,
    approvals: approvalsAnswered,
    'tool-calls': activity.toolCalls,
    'agent-tasks': activity.subagentTasks,
    'multi-agent': agents.size,
    integrations: new Set([...mcpTools].map(mcpServer)).size,
    'mcp-tools': mcpTools.size,
    'terminal-commands': activity.terminalCommands,
    'packages-installed': activity.packagesInstalled,
    'long-sessions': hours(counts.longestSessionMs),
    'coding-time': hours(total),
    'night-coder': nights.size,
    'fast-fix': counts.fastFixes,
    'one-shot-fix': counts.oneShotFixes,
    'tasks-without-retry': counts.noRetryTasks,
    'successful-sessions': counts.successfulSessions,
    'code-cleanup': activity.cleanups,
    'code-deleted': code.linesDeleted,
    'files-created': code.filesCreated,
    'files-deleted': code.filesDeleted,
    refactors: counts.refactors,
    'projects-managed': projects.length,
    'pull-requests': activity.pullRequests,
    'production-fixes': counts.productionFixes,
    'devices-connected': Number(deviceRow?.n) || 0,
    'secure-actions': approvalsAnswered + (Number(user?.key_changes) || 0),
    'code-reviews': counts.reviews,
    documentation: activity.docFiles,
    experiments: counts.experiments,
    'speed-builder': speedTasks,
  };
  return { stats, values };
}

export async function computeStats(userId: string) {
  return (await gather(userId)).stats;
}

type Stats = Awaited<ReturnType<typeof computeStats>>;

export const TIERS = ['bronze', 'silver', 'gold', 'platinum', 'diamond'] as const;
export type TierName = (typeof TIERS)[number];
const TIER_LABEL: Record<TierName, string> = { bronze: 'Bronze', silver: 'Silver', gold: 'Gold', platinum: 'Platinum', diamond: 'Diamond' };

type AchievementDef = {
  id: string;
  emoji: string;
  title: string;
  description: string;
  unit: string;
  thresholds: [number, number, number, number, number];
  /** false: not measurable yet; `reason` is shown to users instead of any progress. */
  trackable?: false;
  reason?: string;
};

const GITHUB = 'Needs a GitHub connection — coming later';
export const MASTER_ID = 'bambookit-master';

/**
 * The 50 tiered achievements (Bronze → Diamond). Every trackable value comes from recorded BambooKit data
 * (see `values` in gather): session totals the PC reports, work intervals measured by this API, approvals,
 * devices and projects. Unlocks are stored per tier in user_achievements as `${id}:${tier}`; rows from the
 * earlier 15 flat achievements (ids without ':') are kept but ignored.
 */
export const ACHIEVEMENTS: AchievementDef[] = [
  { id: 'coding-streak', emoji: '🔥', title: 'Coding Streak', description: 'Code on consecutive days (longest streak; agent work or a new session counts).', unit: 'days', thresholds: [1, 7, 30, 60, 360] },
  { id: 'code-written', emoji: '💻', title: 'Code Written', description: 'Lines of code added through BambooKit.', unit: 'lines', thresholds: [100, 1_000, 10_000, 50_000, 100_000] },
  { id: 'code-changes', emoji: '✏️', title: 'Code Changes', description: 'Edits made by the agent.', unit: 'edits', thresholds: [10, 100, 1_000, 5_000, 10_000] },
  { id: 'files-changed', emoji: '🗂️', title: 'Files Changed', description: 'Files created, modified, deleted or renamed (once per session).', unit: 'files', thresholds: [5, 50, 250, 1_000, 5_000] },
  { id: 'projects-built', emoji: '🏗️', title: 'Projects Built', description: 'Projects with at least one session that changed files.', unit: 'projects', thresholds: [1, 5, 10, 25, 50] },
  { id: 'ai-sessions', emoji: '🤖', title: 'AI Sessions', description: 'Sessions in which the agent completed work.', unit: 'sessions', thresholds: [5, 25, 100, 500, 1_000] },
  { id: 'prompts-sent', emoji: '🧠', title: 'Prompts Sent', description: 'Prompts you sent to the agent.', unit: 'prompts', thresholds: [10, 100, 1_000, 5_000, 10_000] },
  { id: 'tasks-completed', emoji: '⚡', title: 'Tasks Completed', description: 'Agent tasks that finished without an error.', unit: 'tasks', thresholds: [5, 25, 100, 500, 1_000] },
  { id: 'bugs-fixed', emoji: '🐛', title: 'Bugs Fixed', description: 'Debugging sessions the agent completed.', unit: 'bugs', thresholds: [5, 25, 100, 500, 1_000] },
  { id: 'bug-hunter', emoji: '🕵️', title: 'Bug Hunter', description: 'Prompts about fixing a bug, an error or a crash.', unit: 'prompts', thresholds: [10, 50, 250, 1_000, 5_000] },
  { id: 'tests-run', emoji: '🧪', title: 'Tests Run', description: 'Test commands that finished.', unit: 'runs', thresholds: [10, 100, 500, 2_500, 10_000] },
  { id: 'tests-passed', emoji: '✅', title: 'Tests Passed', description: 'Test commands that passed.', unit: 'runs', thresholds: [10, 100, 500, 2_500, 10_000] },
  { id: 'deployments', emoji: '🚀', title: 'Deployments', description: 'Successful deploy commands (vercel, netlify, firebase, fly, npm publish, …).', unit: 'deploys', thresholds: [1, 5, 25, 100, 500] },
  { id: 'cloud-builder', emoji: '☁️', title: 'Cloud Builder', description: 'Deployments to hosted platforms (Vercel, Netlify, Firebase, Fly, Cloudflare, Render, registries, Kubernetes).', unit: 'deploys', thresholds: [1, 5, 20, 100, 500] },
  { id: 'commits', emoji: '🔀', title: 'Commits', description: 'Successful git commits.', unit: 'commits', thresholds: [10, 100, 500, 2_500, 10_000] },
  { id: 'branches-created', emoji: '🌿', title: 'Branches Created', description: 'Git branches created.', unit: 'branches', thresholds: [5, 25, 100, 500, 2_500] },
  { id: 'merges', emoji: '🔀', title: 'Merges', description: 'Successful git merges.', unit: 'merges', thresholds: [5, 25, 100, 500, 2_500] },
  { id: 'approvals', emoji: '🛡️', title: 'Approvals', description: 'Permission requests you answered (approved or rejected).', unit: 'approvals', thresholds: [5, 25, 100, 500, 2_500] },
  { id: 'tool-calls', emoji: '🔧', title: 'Tool Calls', description: 'Tools the agent called.', unit: 'calls', thresholds: [25, 250, 1_000, 5_000, 25_000] },
  { id: 'agent-tasks', emoji: '🤖', title: 'Agent Tasks', description: 'Tasks handed to sub-agents.', unit: 'tasks', thresholds: [5, 25, 100, 500, 2_500] },
  { id: 'multi-agent', emoji: '👥', title: 'Multi-Agent', description: 'Different agents and sub-agents used.', unit: 'agents', thresholds: [2, 5, 10, 25, 50] },
  { id: 'integrations', emoji: '🧩', title: 'Integrations', description: 'Different MCP servers used.', unit: 'servers', thresholds: [1, 5, 10, 25, 50] },
  { id: 'mcp-tools', emoji: '🔌', title: 'MCP Tools', description: 'Different MCP tools used.', unit: 'tools', thresholds: [1, 5, 10, 25, 50] },
  { id: 'terminal-commands', emoji: '🖥️', title: 'Terminal Commands', description: 'Shell commands the agent ran.', unit: 'commands', thresholds: [25, 250, 1_000, 5_000, 25_000] },
  { id: 'packages-installed', emoji: '📦', title: 'Packages Installed', description: 'Successful package installs (npm, pip, cargo, go, …).', unit: 'installs', thresholds: [5, 25, 100, 500, 1_000] },
  { id: 'long-sessions', emoji: '🔥', title: 'Long Sessions', description: 'Active agent time in your longest session.', unit: 'hours', thresholds: [1, 5, 25, 100, 500] },
  { id: 'coding-time', emoji: '⏱️', title: 'Coding Time', description: 'Total time the agent was working for you.', unit: 'hours', thresholds: [5, 25, 100, 500, 1_000] },
  { id: 'night-coder', emoji: '🌙', title: 'Night Coder', description: 'Nights with agent work between 22:00 and 05:00 in your time zone.', unit: 'nights', thresholds: [1, 7, 30, 60, 360] },
  { id: 'fast-fix', emoji: '⚡', title: 'Fast Fix', description: 'Debugging sessions completed within 10 minutes of agent time.', unit: 'fixes', thresholds: [1, 5, 25, 100, 500] },
  { id: 'one-shot-fix', emoji: '🎯', title: 'One-Shot Fix', description: 'Debugging sessions completed from a single prompt.', unit: 'fixes', thresholds: [1, 5, 25, 100, 500] },
  { id: 'tasks-without-retry', emoji: '🏆', title: 'Tasks Without Retry', description: 'Completed sessions with no failed or retried turn.', unit: 'sessions', thresholds: [5, 25, 100, 500, 1_000] },
  { id: 'successful-sessions', emoji: '📈', title: 'Successful Sessions', description: 'Finished sessions that changed files and did not end with only failing tests.', unit: 'sessions', thresholds: [5, 25, 100, 500, 1_000] },
  { id: 'code-cleanup', emoji: '🧹', title: 'Code Cleanup', description: 'Edits that removed more lines than they added.', unit: 'cleanups', thresholds: [5, 25, 100, 500, 2_500] },
  { id: 'code-deleted', emoji: '🗑️', title: 'Code Deleted', description: 'Lines of code removed.', unit: 'lines', thresholds: [100, 1_000, 10_000, 50_000, 100_000] },
  { id: 'files-created', emoji: '➕', title: 'Files Created', description: 'New files created.', unit: 'files', thresholds: [5, 50, 250, 1_000, 5_000] },
  { id: 'files-deleted', emoji: '🗑️', title: 'Files Deleted', description: 'Files deleted.', unit: 'files', thresholds: [5, 25, 100, 500, 2_500] },
  { id: 'refactors', emoji: '♻️', title: 'Refactors', description: 'Completed sessions that set out to refactor or clean up code.', unit: 'sessions', thresholds: [5, 25, 100, 500, 2_500] },
  { id: 'projects-managed', emoji: '📊', title: 'Projects Managed', description: 'Projects opened in BambooKit.', unit: 'projects', thresholds: [1, 5, 10, 25, 50] },
  { id: 'open-source', emoji: '🌐', title: 'Open Source', description: 'Open-source projects you work on.', unit: 'projects', thresholds: [1, 5, 10, 25, 50], trackable: false, reason: GITHUB },
  { id: 'github-stars', emoji: '⭐', title: 'GitHub Stars Earned', description: 'Stars on your GitHub repositories.', unit: 'stars', thresholds: [1, 10, 100, 500, 1_000], trackable: false, reason: GITHUB },
  { id: 'contributions', emoji: '🤝', title: 'Contributions', description: 'Contributions to other people\'s repositories.', unit: 'contributions', thresholds: [1, 5, 25, 100, 500], trackable: false, reason: GITHUB },
  { id: 'pull-requests', emoji: '🏅', title: 'Pull Requests', description: 'Pull requests opened (gh pr create).', unit: 'pull requests', thresholds: [1, 10, 50, 250, 1_000] },
  { id: 'production-fixes', emoji: '🔥', title: 'Production Fixes', description: 'Debugging sessions that also deployed the fix.', unit: 'fixes', thresholds: [1, 5, 25, 100, 500] },
  { id: 'devices-connected', emoji: '📱', title: 'Devices Connected', description: 'PCs and phones you have connected to BambooKit.', unit: 'devices', thresholds: [1, 2, 5, 10, 25] },
  { id: 'secure-actions', emoji: '🔐', title: 'Secure Actions', description: 'Permission requests you answered plus provider API keys you set or removed end-to-end encrypted.', unit: 'actions', thresholds: [5, 25, 100, 500, 2_500] },
  { id: 'code-reviews', emoji: '🧑‍💻', title: 'Code Reviews', description: 'Completed sessions that set out to review or audit code.', unit: 'reviews', thresholds: [5, 25, 100, 500, 2_500] },
  { id: 'documentation', emoji: '📚', title: 'Documentation', description: 'Documentation files written or updated (Markdown, docs/ …).', unit: 'pages', thresholds: [1, 10, 50, 250, 1_000] },
  { id: 'experiments', emoji: '🧪', title: 'Experiments', description: 'Completed sessions that set out to experiment or prototype.', unit: 'experiments', thresholds: [5, 25, 100, 500, 2_500] },
  { id: 'speed-builder', emoji: '🏎️', title: 'Speed Builder', description: 'Agent tasks completed within 5 minutes.', unit: 'tasks', thresholds: [5, 25, 100, 500, 1_000] },
  {
    id: MASTER_ID, emoji: '👑', title: 'BambooKit Master',
    description: 'Achievements at Bronze or better (this one counts once it reaches Bronze). Diamond needs all 50, so it waits for the three GitHub achievements.',
    unit: 'achievements', thresholds: [10, 25, 35, 45, 50],
  },
];

const POINTS: Record<TierName, number> = { bronze: 1, silver: 2, gold: 3, platinum: 4, diamond: 5 };

/** Achievements with at least Bronze among `others`; this one counts itself once it reaches Bronze. */
export function masterValue(others: number) {
  return others >= ACHIEVEMENTS.find((a) => a.id === MASTER_ID)!.thresholds[0] ? others + 1 : others;
}

const metTiers = (a: AchievementDef, value: number) => (a.trackable === false ? [] : TIERS.filter((_, i) => value >= a.thresholds[i]));

/** Per-user debounce for refreshes triggered by sync (GET requests always refresh). */
const REFRESH_INTERVAL_MS = 30_000;
const lastRefresh = new Map<string, number>();
const pendingRefresh = new Map<string, ReturnType<typeof setTimeout>>();

/** Refresh after a sync: at most once per 30 s per user; a later sync inside the window schedules one trailing refresh. */
export async function refreshAchievementsSoon(userId: string) {
  const since = Date.now() - (lastRefresh.get(userId) ?? 0);
  if (since >= REFRESH_INTERVAL_MS) {
    await refreshAchievements(userId);
    return;
  }
  if (pendingRefresh.has(userId)) return;
  const timer = setTimeout(() => {
    pendingRefresh.delete(userId);
    refreshAchievements(userId).catch((err) => logger.warn('achievement refresh failed', { error: String(err?.message ?? err) }));
  }, REFRESH_INTERVAL_MS - since);
  timer.unref?.();
  pendingRefresh.set(userId, timer);
}

/**
 * Computes every value and stores newly reached tiers (idempotent: INSERT … ON CONFLICT DO NOTHING per
 * `${id}:${tier}`). Notifications: one per new tier when at most 3 unlock together, otherwise a single
 * summary ("You unlocked 12 achievement tiers") — so the first computation for an account is one notification.
 */
export async function refreshAchievements(userId: string) {
  lastRefresh.set(userId, Date.now());
  const { stats, values } = await gather(userId);
  const rows = await db.all<{ achievement: string; unlocked_at: string }>('SELECT achievement, unlocked_at FROM user_achievements WHERE user_id = ?', userId);
  const unlocked = new Map(rows.filter((r) => r.achievement.includes(':')).map((r) => [r.achievement, r.unlocked_at]));
  const fresh: Array<{ a: AchievementDef; tier: TierName; at: string }> = [];
  const store = async (a: AchievementDef, value: number) => {
    for (const tier of metTiers(a, value)) {
      const key = `${a.id}:${tier}`;
      if (unlocked.has(key)) continue;
      const ts = now();
      const res = await db.run('INSERT INTO user_achievements (user_id, achievement, unlocked_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING', userId, key, ts);
      if (res.changes === 1) {
        unlocked.set(key, ts);
        fresh.push({ a, tier, at: ts });
      }
    }
  };
  for (const a of ACHIEVEMENTS) if (a.id !== MASTER_ID) await store(a, values[a.id] ?? 0);
  const others = ACHIEVEMENTS.filter((a) => a.id !== MASTER_ID && unlocked.has(`${a.id}:bronze`)).length;
  values[MASTER_ID] = masterValue(others);
  await store(ACHIEVEMENTS.find((a) => a.id === MASTER_ID)!, values[MASTER_ID]);

  if (fresh.length > 3) {
    const title = `You unlocked ${fresh.length} achievement tiers`;
    await publish({ userId, type: 'achievement.unlocked', payload: { id: 'summary', title, count: fresh.length, unlockedAt: fresh[fresh.length - 1].at } });
    await notify({ userId, type: 'achievement.unlocked', title: 'Achievements unlocked', body: title, data: { count: String(fresh.length) } });
  } else {
    for (const f of fresh) {
      const title = `${f.a.emoji} ${f.a.title} — ${TIER_LABEL[f.tier]}`;
      await publish({ userId, type: 'achievement.unlocked', payload: { id: f.a.id, tier: f.tier, title, unlockedAt: f.at } });
      await notify({ userId, type: 'achievement.unlocked', title: 'Achievement unlocked', body: title, data: { achievementId: f.a.id, tier: f.tier } });
    }
  }
  const list = achievementList(values, unlocked);
  return { stats, achievements: list.items, summary: { ...list.summary, currentStreak: stats.streak.current, longestStreak: stats.streak.longest } };
}

/**
 * Client shape. Older clients read title, description, progress, target, unlocked and unlockedAt; tiers add
 * emoji, value, tiers[], tier (current) and nextTier. progress is the value, capped at target once Diamond is reached.
 */
function achievementList(values: Record<string, number>, unlocked: Map<string, string>) {
  let tiersUnlocked = 0, points = 0, count = 0;
  const items = ACHIEVEMENTS.map((a) => {
    const trackable = a.trackable !== false;
    const value = trackable ? values[a.id] ?? 0 : 0;
    const tiers = TIERS.map((name, i) => ({ name, threshold: a.thresholds[i], unlocked: unlocked.has(`${a.id}:${name}`), unlockedAt: unlocked.get(`${a.id}:${name}`) ?? null }));
    const reached = tiers.filter((t) => t.unlocked);
    const tier = reached.length ? reached[reached.length - 1].name : null;
    const next = tiers.find((t) => !t.unlocked) ?? null;
    const target = next?.threshold ?? a.thresholds[4];
    const unlockedAt = reached.map((t) => t.unlockedAt!).sort().pop() ?? null;
    tiersUnlocked += reached.length;
    points += reached.reduce((n, t) => n + POINTS[t.name], 0);
    if (tier) count++;
    return {
      id: a.id,
      emoji: a.emoji,
      title: a.title,
      description: a.description,
      unit: a.unit,
      trackable,
      ...(trackable ? {} : { reason: a.reason }),
      value,
      tiers,
      tier,
      nextTier: next?.name ?? null,
      progress: next ? value : Math.min(value, target),
      target,
      unlocked: tier !== null,
      unlockedAt,
    };
  });
  return { items, summary: { unlocked: count, total: ACHIEVEMENTS.length, tiersUnlocked, tiersTotal: ACHIEVEMENTS.length * TIERS.length, points } };
}

/**
 * "Files changed (24h)": distinct files changed in sessions (including sub-agent sessions) with real activity
 * in the last 24 hours. Files are told apart by the one-way keys recorded from the PC's diffs, so a file
 * changed in several sessions counts once; sessions without a recorded diff count their own total (the
 * engine's changed-file count or the PC's statistics, whichever is larger).
 */
export async function filesChanged24h(userId: string, nowMs = Date.now()): Promise<number> {
  const since = new Date(nowMs - 86_400_000).toISOString();
  const keyed = await db.get<{ n: number }>(
    `SELECT COUNT(DISTINCT f.file_key) AS n FROM session_files f JOIN sessions s ON s.id = f.session_id
     WHERE s.user_id = ? AND s.activity_at >= ?`,
    userId,
    since,
  );
  const untracked = await db.all<{ files: number; stats: string | null }>(
    `SELECT s.files, s.stats FROM sessions s
     WHERE s.user_id = ? AND s.activity_at >= ? AND NOT EXISTS (SELECT 1 FROM session_files f WHERE f.session_id = s.id)`,
    userId,
    since,
  );
  let n = Number(keyed?.n ?? 0);
  for (const s of untracked) {
    const st = parseStats(s.stats);
    n += Math.max(Number(s.files) || 0, num(st.filesCreated) + num(st.filesModified) + num(st.filesDeleted) + num(st.filesRenamed));
  }
  return n;
}

export const statsRouter = new Hono<AppEnv>();
statsRouter.use('*', requireUser);

// GET /v1/me/stats — profile statistics, projects managed and achievements
statsRouter.get('/me/stats', async (c) => {
  const userId = c.get('user').id;
  const { stats, achievements, summary } = await refreshAchievements(userId);
  return c.json({ data: { ...stats, filesChanged24h: await filesChanged24h(userId), achievements, achievementSummary: summary } });
});

// GET /v1/me/achievements — { data: [50 achievements with tiers], summary }
statsRouter.get('/me/achievements', async (c) => {
  const { achievements, summary } = await refreshAchievements(c.get('user').id);
  return c.json({ data: achievements, summary });
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
