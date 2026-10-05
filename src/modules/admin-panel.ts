import { env, VERSION } from '../config/env.js';
import { db } from '../db/database.js';
import { adminTimeZone } from '../lib/activity.js';
import { localDate, localMidnight, windows, type Windows } from '../lib/timezone.js';
import { health, recentErrors, serverErrorsSince, topErrorCodes } from '../lib/monitor.js';
import { connectionTotals, isConnected } from '../realtime/bus.js';
import { storage } from '../services/storage.js';
import { cashfreeConfig, cashfreeEnvironment } from '../services/cashfree.js';
import { verifierKeysState } from '../services/admob.js';
import { isAdmin } from './admin.js';
import { getPlan, PRODUCTS } from './billing.js';
import { ACHIEVEMENTS, computeStats, TIERS, type TierName } from './stats.js';
import { latestRelease } from './meta.js';

/**
 * Data for the Telegram admin panel. Definitions (all windows use the admin time zone, TELEGRAM_TIMEZONE):
 * - today = since local midnight; yesterday = the previous local day; 7 d / 30 d = the last 7 / 30 local
 *   days including today; the "previous" period is the same length just before it.
 * - active user = users.last_seen_at inside the window (DAU = today, WAU = 7 d, MAU = 30 d). Yesterday's DAU
 *   also counts users seen yesterday and again today (user_active_days).
 * - new user = users.created_at inside the window.
 * - PCs / phones: registered = not revoked; online = an open realtime connection right now.
 * - sessions: top-level only (sub-agent sessions are not counted); working = status busy/retry.
 * - revenue: PAID orders in INR only, from amount_paise, by paid_at.
 * Aggregates and account metadata only — never session content, tokens or keys.
 */

const num = async (sql: string, ...args: unknown[]) => Number((await db.get<{ n: number }>(sql, ...args))?.n ?? 0);
export const PAGE_SIZE = 8;
const TOP = 'parent_opencode_session_id IS NULL';

export function context(at = new Date()) {
  const tz = adminTimeZone();
  return { at, tz, w: windows(at, tz) };
}
type Ctx = ReturnType<typeof context>;

/** -1 / 0 / 1 comparing dotted numeric versions ('1.0.10' > '1.0.9'). */
export function compareVersions(a: string, b: string) {
  const pa = a.replace(/^v/i, '').split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.replace(/^v/i, '').split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d > 0 ? 1 : -1;
  }
  return 0;
}

const proSql = (alias = '') => `${alias}pro_until > ?`;

async function newUsers(w: Windows) {
  const between = (from: string, to: string) => num('SELECT COUNT(*) AS n FROM users WHERE created_at >= ? AND created_at < ?', from, to);
  return {
    today: await between(w.today, w.now),
    yesterday: await between(w.yesterday, w.today),
    d7: await between(w.d7, w.now),
    prev7: await between(w.prev7, w.d7),
    d30: await between(w.d30, w.now),
    prev30: await between(w.prev30, w.d30),
  };
}

/** Users active on the admin-zone day [from, to): recorded active days plus last_seen_at inside it. */
export async function activeOnDay(day: string, from: string, to: string) {
  return num(
    `SELECT COUNT(*) AS n FROM (
       SELECT user_id AS id FROM user_active_days WHERE day = ?
       UNION SELECT id FROM users WHERE last_seen_at >= ? AND last_seen_at < ?
     ) t`,
    day,
    from,
    to,
  );
}

async function active(c: Ctx) {
  const since = (from: string) => num('SELECT COUNT(*) AS n FROM users WHERE last_seen_at >= ?', from);
  return {
    dau: await since(c.w.today),
    dauYesterday: await activeOnDay(localDate(new Date(c.w.yesterday), c.tz), c.w.yesterday, c.w.today),
    wau: await since(c.w.d7),
    mau: await since(c.w.d30),
  };
}

async function revenuePaise(from: string, to: string) {
  return num("SELECT COALESCE(SUM(amount_paise), 0) AS n FROM billing_orders WHERE status = 'PAID' AND currency = 'INR' AND paid_at >= ? AND paid_at < ?", from, to);
}

async function proBySource(at: string) {
  const rows = await db.all<{ source: string | null; n: number }>(`SELECT pro_source AS source, COUNT(*) AS n FROM users WHERE ${proSql()} GROUP BY pro_source`, at);
  const out = { payment: 0, reward: 0, admin: 0, total: 0 };
  for (const r of rows) {
    const k = (r.source ?? 'payment') as keyof typeof out;
    if (k in out) out[k] += Number(r.n);
    out.total += Number(r.n);
  }
  return out;
}

async function deviceRows() {
  return db.all<{ id: string; kind: string; app_version: string | null; created_at: string }>('SELECT id, kind, app_version, created_at FROM devices WHERE revoked_at IS NULL');
}

function byVersion(rows: Array<{ id: string; app_version: string | null }>) {
  const map = new Map<string, { version: string; count: number; online: number }>();
  for (const d of rows) {
    const v = d.app_version || 'unknown';
    const e = map.get(v) ?? { version: v, count: 0, online: 0 };
    e.count++;
    if (isConnected(d.id)) e.online++;
    map.set(v, e);
  }
  return [...map.values()].sort((a, b) => (a.version === 'unknown' ? 1 : b.version === 'unknown' ? -1 : compareVersions(b.version, a.version)));
}

export async function dashboard(c = context()) {
  const devices = await deviceRows();
  const desktops = devices.filter((d) => d.kind === 'desktop');
  const phones = devices.filter((d) => d.kind === 'mobile');
  const h = health();
  const live = connectionTotals();
  return {
    ...c,
    users: { total: await num('SELECT COUNT(*) AS n FROM users'), new: await newUsers(c.w), ...(await active(c)) },
    pro: await proBySource(c.w.now),
    pcs: { registered: desktops.length, online: desktops.filter((d) => isConnected(d.id)).length, versions: byVersion(desktops) },
    phones: { registered: phones.length, online: phones.filter((d) => isConnected(d.id)).length },
    sessions: {
      total: await num(`SELECT COUNT(*) AS n FROM sessions WHERE ${TOP}`),
      working: await num(`SELECT COUNT(*) AS n FROM sessions WHERE ${TOP} AND status IN ('busy','retry')`),
      today: await num(`SELECT COUNT(*) AS n FROM sessions WHERE ${TOP} AND created_at >= ?`, c.w.today),
      yesterday: await num(`SELECT COUNT(*) AS n FROM sessions WHERE ${TOP} AND created_at >= ? AND created_at < ?`, c.w.yesterday, c.w.today),
    },
    approvalsPending: await num("SELECT COUNT(*) AS n FROM approvals WHERE status IN ('PENDING','RESPONDING')"),
    revenue: { todayPaise: await revenuePaise(c.w.today, c.w.now), d30Paise: await revenuePaise(c.w.d30, c.w.now) },
    api: {
      version: VERSION,
      commit: process.env.RENDER_GIT_COMMIT?.slice(0, 7) ?? null,
      uptimeSeconds: h.uptimeSeconds,
      memoryMb: h.memoryMb,
      requests: h.requests,
      clientErrors: h.clientErrors,
      serverErrors: h.serverErrors,
      errorRate: h.requests ? (h.serverErrors / h.requests) * 100 : 0,
    },
    realtime: { streams: live.devices + live.web, devices: live.devices, web: live.web },
  };
}

// ---------------------------------------------------------------- users

export type UserRow = {
  id: string;
  email: string | null;
  name: string | null;
  provider: string | null;
  createdAt: string;
  lastSeenAt: string | null;
  plan: 'pro' | 'free';
  source: string | null;
  admin: boolean;
  devices: number;
};

const USER_SELECT = `SELECT u.id, u.email, u.name, u.nickname, u.provider, u.email_verified, u.created_at, u.last_seen_at, u.pro_until, u.pro_source,
  (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL) AS devices FROM users u`;

function toUserRow(r: any, at: string): UserRow {
  const admin = isAdmin({ email: r.email ?? null, emailVerified: r.email_verified === null || r.email_verified === undefined ? null : !!Number(r.email_verified) });
  const pro = !!r.pro_until && r.pro_until > at;
  return {
    id: r.id,
    email: r.email ?? null,
    name: r.nickname ?? r.name ?? null,
    provider: r.provider ?? null,
    createdAt: r.created_at,
    lastSeenAt: r.last_seen_at ?? null,
    plan: admin || pro ? 'pro' : 'free',
    source: admin ? 'admin' : pro ? r.pro_source ?? 'payment' : null,
    admin,
    devices: Number(r.devices),
  };
}

export async function usersPage(page: number, c = context()) {
  const total = await num('SELECT COUNT(*) AS n FROM users');
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const p = Math.min(Math.max(0, Math.floor(page) || 0), pages - 1);
  const rows = await db.all<any>(`${USER_SELECT} ORDER BY u.created_at DESC, u.id DESC LIMIT ? OFFSET ?`, PAGE_SIZE, p * PAGE_SIZE);
  return { ...c, total, page: p, pages, users: rows.map((r) => toUserRow(r, c.w.now)) };
}

/** Case-insensitive partial match on email (also name/nickname), or an exact / prefix user id. At most 8. */
export async function searchUsers(query: string, c = context()) {
  const q = query.trim().toLowerCase().replace(/[%_\\]/g, '').slice(0, 100);
  if (!q) return { ...c, query: '', users: [] as UserRow[] };
  const like = `%${q}%`;
  const rows = await db.all<any>(
    `${USER_SELECT} WHERE LOWER(u.email) LIKE ? OR LOWER(COALESCE(u.nickname, '')) LIKE ? OR LOWER(COALESCE(u.name, '')) LIKE ? OR u.id = ? OR u.id LIKE ?
     ORDER BY CASE WHEN u.id = ? OR LOWER(u.email) = ? THEN 0 ELSE 1 END, u.created_at DESC LIMIT ?`,
    like, like, like, query.trim(), `${query.trim().replace(/[%_\\]/g, '')}%`, query.trim(), q, PAGE_SIZE,
  );
  return { ...c, query: query.trim(), users: rows.map((r) => toUserRow(r, c.w.now)) };
}

const POINTS: Record<TierName, number> = { bronze: 1, silver: 2, gold: 3, platinum: 4, diamond: 5 };

export async function userCard(userId: string, c = context()) {
  const r = await db.get<any>(`SELECT u.*, (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL) AS devices FROM users u WHERE u.id = ?`, userId);
  if (!r) return null;
  const row = toUserRow(r, c.w.now);
  const plan = await getPlan(userId);
  const devices = (
    await db.all<any>('SELECT id, kind, name, platform, app_version, last_seen_at, created_at FROM devices WHERE user_id = ? AND revoked_at IS NULL ORDER BY kind, created_at', userId)
  ).map((d) => ({ id: d.id, kind: d.kind as string, name: d.name as string, platform: d.platform as string, version: d.app_version as string | null, online: isConnected(d.id), lastSeenAt: d.last_seen_at as string | null }));
  const unlocked = (await db.all<{ achievement: string }>("SELECT achievement FROM user_achievements WHERE user_id = ? AND achievement LIKE '%:%'", userId)).map((x) => x.achievement);
  const ids = new Set(unlocked.map((a) => a.split(':')[0]));
  const points = unlocked.reduce((n, a) => n + (POINTS[a.split(':')[1] as TierName] ?? 0), 0);
  let streak: number | null = null;
  try {
    streak = (await computeStats(userId)).streak.current;
  } catch {}
  const orders = await db.all<any>('SELECT id, product_id, amount_paise, currency, status, created_at, paid_at FROM billing_orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 5', userId);
  return {
    ...c,
    user: {
      ...row,
      realName: r.name ?? null,
      nickname: r.nickname ?? null,
      emailVerified: r.email_verified === null || r.email_verified === undefined ? null : !!Number(r.email_verified),
      timezone: r.timezone ?? null,
      proUntil: r.pro_until ?? null,
      proSource: r.pro_source ?? null,
    },
    plan,
    devices,
    projects: await num('SELECT COUNT(*) AS n FROM projects WHERE user_id = ?', userId),
    sessions: await num(`SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND ${TOP}`, userId),
    codingMs: {
      d7: await num('SELECT COALESCE(SUM(duration_ms), 0) AS n FROM work_intervals WHERE user_id = ? AND started_at >= ?', userId, c.w.d7),
      total: await num('SELECT COALESCE(SUM(duration_ms), 0) AS n FROM work_intervals WHERE user_id = ?', userId),
    },
    achievements: { unlocked: ids.size, total: ACHIEVEMENTS.length, tiers: unlocked.length, tiersTotal: ACHIEVEMENTS.length * TIERS.length, points, streak },
    orders: orders.map((o) => ({ id: o.id as string, product: o.product_id as string, amountPaise: Number(o.amount_paise), currency: o.currency as string, status: o.status as string, createdAt: o.created_at as string, paidAt: o.paid_at as string | null })),
  };
}

// ---------------------------------------------------------------- devices

async function latestVersion(platform: 'windows' | 'android') {
  try {
    return (await latestRelease(platform)).version;
  } catch {
    return null;
  }
}

export async function devicesScreen(c = context()) {
  const devices = await deviceRows();
  const desktops = devices.filter((d) => d.kind === 'desktop');
  const phones = devices.filter((d) => d.kind === 'mobile');
  const [latestDesktop, latestAndroid] = await Promise.all([latestVersion('windows'), latestVersion('android')]);
  const outdated = (rows: typeof devices, latest: string | null) => (latest ? rows.filter((d) => d.app_version && compareVersions(d.app_version, latest) < 0) : []);
  const oldPcs = outdated(desktops, latestDesktop);
  const recent = await db.all<any>(
    `SELECT d.id, d.kind, d.name, d.app_version, d.created_at, u.email FROM devices d LEFT JOIN users u ON u.id = d.user_id
     WHERE d.revoked_at IS NULL ORDER BY d.created_at DESC LIMIT 8`,
  );
  return {
    ...c,
    desktops: { registered: desktops.length, online: desktops.filter((d) => isConnected(d.id)).length, versions: byVersion(desktops), latest: latestDesktop, needUpdate: oldPcs.length, needUpdateOnline: oldPcs.filter((d) => isConnected(d.id)).length },
    phones: { registered: phones.length, online: phones.filter((d) => isConnected(d.id)).length, versions: byVersion(phones), latest: latestAndroid, needUpdate: outdated(phones, latestAndroid).length },
    revoked: await num('SELECT COUNT(*) AS n FROM devices WHERE revoked_at IS NOT NULL'),
    newToday: devices.filter((d) => d.created_at >= c.w.today).length,
    new7d: devices.filter((d) => d.created_at >= c.w.d7).length,
    recent: recent.map((d) => ({ kind: d.kind as string, name: d.name as string, version: d.app_version as string | null, createdAt: d.created_at as string, email: d.email as string | null, online: isConnected(d.id) })),
  };
}

// ---------------------------------------------------------------- sessions

export async function sessionsScreen(c = context()) {
  const working = await db.all<any>(
    `SELECT s.title, s.busy_since, s.updated_at, s.status, u.email, p.name AS project FROM sessions s
     LEFT JOIN users u ON u.id = s.user_id LEFT JOIN projects p ON p.id = s.project_id
     WHERE s.${TOP} AND s.status IN ('busy','retry') ORDER BY COALESCE(s.busy_since, s.updated_at) ASC LIMIT 10`,
  );
  const approvals = await db.all<any>(
    `SELECT a.kind, a.permission, a.title, a.created_at, u.email FROM approvals a LEFT JOIN users u ON u.id = a.user_id
     WHERE a.status IN ('PENDING','RESPONDING') ORDER BY a.created_at ASC LIMIT 8`,
  );
  const top = await db.all<any>(
    `SELECT p.name AS project, u.email, COUNT(*) AS n FROM sessions s JOIN projects p ON p.id = s.project_id LEFT JOIN users u ON u.id = s.user_id
     WHERE s.${TOP} AND s.created_at >= ? GROUP BY p.id, p.name, u.email ORDER BY n DESC, p.name ASC LIMIT 5`,
    c.w.d7,
  );
  const created = (from: string, to: string) => num(`SELECT COUNT(*) AS n FROM sessions WHERE ${TOP} AND created_at >= ? AND created_at < ?`, from, to);
  return {
    ...c,
    workingCount: await num(`SELECT COUNT(*) AS n FROM sessions WHERE ${TOP} AND status IN ('busy','retry')`),
    working: working.map((s) => ({ title: String(s.title ?? ''), email: s.email as string | null, project: s.project as string | null, since: (s.busy_since ?? s.updated_at) as string, status: s.status as string })),
    today: await created(c.w.today, c.w.now),
    yesterday: await created(c.w.yesterday, c.w.today),
    d7: await created(c.w.d7, c.w.now),
    activeToday: await num(`SELECT COUNT(*) AS n FROM sessions WHERE ${TOP} AND updated_at >= ?`, c.w.today),
    tasksToday: await num('SELECT COUNT(*) AS n FROM work_intervals WHERE started_at >= ?', c.w.today),
    codingMsToday: await num('SELECT COALESCE(SUM(duration_ms), 0) AS n FROM work_intervals WHERE started_at >= ?', c.w.today),
    approvalsPending: await num("SELECT COUNT(*) AS n FROM approvals WHERE status IN ('PENDING','RESPONDING')"),
    approvals: approvals.map((a) => ({ kind: (a.kind ?? 'permission') as string, permission: a.permission as string, title: a.title as string | null, createdAt: a.created_at as string, email: a.email as string | null })),
    topProjects: top.map((t) => ({ project: t.project as string, email: t.email as string | null, sessions: Number(t.n) })),
  };
}

// ---------------------------------------------------------------- revenue

export async function revenueScreen(c = context()) {
  const statuses = await db.all<{ status: string; n: number; paise: number }>(
    'SELECT status, COUNT(*) AS n, COALESCE(SUM(amount_paise), 0) AS paise FROM billing_orders WHERE created_at >= ? GROUP BY status',
    c.w.d30,
  );
  const byStatus = { PAID: 0, PENDING: 0, FAILED: 0, EXPIRED: 0 } as Record<string, number>;
  for (const s of statuses) byStatus[s.status] = Number(s.n);
  const checkouts = Object.values(byStatus).reduce((a, b) => a + b, 0);
  const proRows = await db.all<{ source: string | null; product: string | null }>(
    `SELECT u.pro_source AS source, (SELECT o.product_id FROM billing_orders o WHERE o.user_id = u.id AND o.status = 'PAID' ORDER BY o.paid_at DESC LIMIT 1) AS product
     FROM users u WHERE u.pro_until > ?`,
    c.w.now,
  );
  const byProduct: Record<string, number> = {};
  for (const r of proRows) {
    const key = (r.source ?? 'payment') === 'payment' ? (r.product ?? 'payment') : (r.source as string);
    byProduct[key] = (byProduct[key] ?? 0) + 1;
  }
  const payments = await db.all<any>(
    `SELECT o.amount_paise, o.currency, o.product_id, o.paid_at, u.email FROM billing_orders o LEFT JOIN users u ON u.id = o.user_id
     WHERE o.status = 'PAID' ORDER BY o.paid_at DESC LIMIT 10`,
  );
  const paidCount = (from: string, to: string) => num("SELECT COUNT(*) AS n FROM billing_orders WHERE status = 'PAID' AND currency = 'INR' AND paid_at >= ? AND paid_at < ?", from, to);
  const rewards = (from: string) => num('SELECT COUNT(*) AS n FROM reward_grants WHERE granted = 1 AND created_at >= ?', from);
  return {
    ...c,
    configured: !!cashfreeConfig(),
    environment: cashfreeEnvironment(),
    paise: {
      today: await revenuePaise(c.w.today, c.w.now),
      yesterday: await revenuePaise(c.w.yesterday, c.w.today),
      d7: await revenuePaise(c.w.d7, c.w.now),
      prev7: await revenuePaise(c.w.prev7, c.w.d7),
      d30: await revenuePaise(c.w.d30, c.w.now),
      all: await num("SELECT COALESCE(SUM(amount_paise), 0) AS n FROM billing_orders WHERE status = 'PAID' AND currency = 'INR'"),
    },
    paidCount: { today: await paidCount(c.w.today, c.w.now), d7: await paidCount(c.w.d7, c.w.now), d30: await paidCount(c.w.d30, c.w.now) },
    byStatus,
    checkouts,
    conversion: checkouts ? (byStatus.PAID / checkouts) * 100 : null,
    activePro: proRows.length,
    byProduct: Object.entries(byProduct).map(([key, n]) => ({ key, name: (PRODUCTS as any)[key]?.name ?? key, count: n })).sort((a, b) => b.count - a.count),
    rewards: { today: await rewards(c.w.today), d7: await rewards(c.w.d7) },
    payments: payments.map((p) => ({ amountPaise: Number(p.amount_paise), currency: p.currency as string, product: (PRODUCTS as any)[p.product_id]?.name ?? (p.product_id as string), paidAt: p.paid_at as string, email: p.email as string | null })),
  };
}

// ---------------------------------------------------------------- achievements

const TIER_POINTS_SQL = `SUM(CASE WHEN achievement LIKE '%:bronze' THEN 1 WHEN achievement LIKE '%:silver' THEN 2 WHEN achievement LIKE '%:gold' THEN 3
  WHEN achievement LIKE '%:platinum' THEN 4 WHEN achievement LIKE '%:diamond' THEN 5 ELSE 0 END)`;

export async function achievementsScreen(c = context()) {
  const counts = await db.all<{ achievement: string; n: number }>("SELECT achievement, COUNT(*) AS n FROM user_achievements WHERE achievement LIKE '%:%' GROUP BY achievement");
  const tiers: Record<TierName, number> = { bronze: 0, silver: 0, gold: 0, platinum: 0, diamond: 0 };
  const bronzeUsers = new Map<string, number>();
  for (const r of counts) {
    const [id, tier] = r.achievement.split(':');
    if (tier in tiers) tiers[tier as TierName] += Number(r.n);
    if (tier === 'bronze') bronzeUsers.set(id, Number(r.n));
  }
  const defs = new Map(ACHIEVEMENTS.map((a) => [a.id, a]));
  const top = await db.all<{ user_id: string; points: number; tiers: number; email: string | null }>(
    `SELECT a.user_id, ${TIER_POINTS_SQL.replace(/achievement/g, 'a.achievement')} AS points, COUNT(*) AS tiers, MAX(u.email) AS email
     FROM user_achievements a LEFT JOIN users u ON u.id = a.user_id WHERE a.achievement LIKE '%:%'
     GROUP BY a.user_id ORDER BY points DESC, tiers DESC LIMIT 5`,
  );
  const unlockedSince = (from: string, to: string) => num("SELECT COUNT(*) AS n FROM user_achievements WHERE achievement LIKE '%:%' AND unlocked_at >= ? AND unlocked_at < ?", from, to);
  return {
    ...c,
    today: await unlockedSince(c.w.today, c.w.now),
    yesterday: await unlockedSince(c.w.yesterday, c.w.today),
    d7: await unlockedSince(c.w.d7, c.w.now),
    usersWithAny: await num("SELECT COUNT(DISTINCT user_id) AS n FROM user_achievements WHERE achievement LIKE '%:%'"),
    byTier: TIERS.map((t) => ({ tier: t, count: tiers[t] })),
    mostUnlocked: [...bronzeUsers.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([id, users]) => ({ id, title: defs.get(id) ? `${defs.get(id)!.emoji} ${defs.get(id)!.title}` : id, users })),
    topUsers: top.map((t) => ({ userId: t.user_id, email: t.email, points: Number(t.points), tiers: Number(t.tiers) })),
  };
}

// ---------------------------------------------------------------- errors and health

export function errorsScreen(page: number, c = context()) {
  const all = recentErrors();
  const pages = Math.max(1, Math.ceil(all.length / PAGE_SIZE));
  const p = Math.min(Math.max(0, Math.floor(page) || 0), pages - 1);
  return {
    ...c,
    page: p,
    pages,
    total: all.length,
    errors: all.slice(p * PAGE_SIZE, (p + 1) * PAGE_SIZE),
    lastHour: serverErrorsSince(3600_000),
    last24h: serverErrorsSince(86_400_000),
    topCodes: topErrorCodes(5),
    uptimeSeconds: health().uptimeSeconds,
  };
}

export async function healthScreen(c = context()) {
  const started = performance.now();
  let dbOk = true;
  let dbError: string | null = null;
  try {
    await db.get('SELECT 1 AS ok');
  } catch (err: any) {
    dbOk = false;
    dbError = String(err?.code ?? err?.name ?? 'error').slice(0, 60);
  }
  const dbMs = Math.round((performance.now() - started) * 10) / 10;
  return {
    ...c,
    db: { ok: dbOk, dialect: db.dialect, latencyMs: dbMs, error: dbError },
    storage: storage ? storage.driver : null,
    cashfree: { configured: !!cashfreeConfig(), environment: cashfreeEnvironment() },
    admob: verifierKeysState(),
    health: health(),
    adminEmails: (env.ADMIN_EMAILS ?? '').split(',').filter((s) => s.trim()).length,
  };
}

// ---------------------------------------------------------------- daily report

/** Summary of the admin-zone day before `at` (compared with the day before that). */
export async function dailyReport(at = new Date()) {
  const tz = adminTimeZone();
  const start = localMidnight(at, tz, -1).toISOString();
  const end = localMidnight(at, tz, 0).toISOString();
  const before = localMidnight(at, tz, -2).toISOString();
  const day = localDate(new Date(start), tz);
  const prevDay = localDate(new Date(before), tz);
  const count = (sql: string, from: string, to: string) => num(sql, from, to);
  const NEW = 'SELECT COUNT(*) AS n FROM users WHERE created_at >= ? AND created_at < ?';
  const SES = `SELECT COUNT(*) AS n FROM sessions WHERE ${TOP} AND created_at >= ? AND created_at < ?`;
  const TIER = "SELECT COUNT(*) AS n FROM user_achievements WHERE achievement LIKE '%:%' AND unlocked_at >= ? AND unlocked_at < ?";
  const PAID = "SELECT COUNT(*) AS n FROM billing_orders WHERE status = 'PAID' AND currency = 'INR' AND paid_at >= ? AND paid_at < ?";
  return {
    tz,
    day,
    newUsers: await count(NEW, start, end),
    newUsersPrev: await count(NEW, before, start),
    dau: await activeOnDay(day, start, end),
    dauPrev: await activeOnDay(prevDay, before, start),
    sessions: await count(SES, start, end),
    sessionsPrev: await count(SES, before, start),
    revenuePaise: await revenuePaise(start, end),
    revenuePrevPaise: await revenuePaise(before, start),
    payments: await count(PAID, start, end),
    tiers: await count(TIER, start, end),
    totalUsers: await num('SELECT COUNT(*) AS n FROM users'),
    errors24h: serverErrorsSince(86_400_000),
    uptimeSeconds: health().uptimeSeconds,
  };
}
