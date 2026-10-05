import { maskEmail } from '../lib/mask.js';
import { hhmm, shortDateTime } from '../lib/timezone.js';
import type { RecentError } from '../lib/monitor.js';
import type {
  achievementsScreen,
  dailyReport,
  dashboard,
  devicesScreen,
  errorsScreen,
  healthScreen,
  revenueScreen,
  searchUsers,
  sessionsScreen,
  userCard,
  usersPage,
  UserRow,
} from '../modules/admin-panel.js';

/**
 * Text and inline keyboards for the Telegram admin panel (HTML parse mode). Pure functions over the
 * data from modules/admin-panel.ts. Every dynamic value goes through esc(); tags never span lines, so
 * long messages can be split at line breaks.
 */

export type Button = { text: string; callback_data: string };
export type Screen = { text: string; keyboard: Button[][] };

export const esc = (s: unknown) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
const int = (n: number) => Math.round(n).toLocaleString('en-IN');
export const inr = (paise: number) => `₹${(paise / 100).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
const money = (paise: number, currency: string) => (currency === 'INR' ? inr(paise) : `${esc(currency)} ${(paise / 100).toFixed(2)}`);
const pct = (v: number) => `${v >= 10 || v === 0 ? Math.round(v) : v.toFixed(1)}%`;

/** " (▲ 50%)" / " (▼ 20%)" / " (=)" vs the previous period; empty when both are 0. */
export function delta(cur: number, prev: number) {
  if (!prev) return cur ? ' (new)' : '';
  const d = ((cur - prev) / prev) * 100;
  if (Math.abs(d) < 0.5) return ' (=)';
  return ` (${d > 0 ? '▲' : '▼'} ${pct(Math.abs(d))})`;
}

export function dur(seconds: number) {
  const s = Math.max(0, Math.round(seconds));
  if (s >= 86400) return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
  if (s >= 3600) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  if (s >= 60) return `${Math.floor(s / 60)}m`;
  return `${s}s`;
}

export function ago(iso: string | null | undefined, at: Date) {
  if (!iso) return 'never';
  const s = (at.getTime() - Date.parse(iso)) / 1000;
  if (!Number.isFinite(s)) return '—';
  if (s < 60) return 'just now';
  return `${dur(s)} ago`;
}

const trunc = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const footer = (c: { at: Date; tz: string }, extra = '') => `\n<i>as of ${hhmm(c.at, c.tz)} · ${esc(c.tz)}${extra}</i>`;
const nav = (refresh: string, back: Button = { text: '⬅️ Menu', callback_data: 'm' }): Button[] => [{ text: '🔄 Refresh', callback_data: refresh }, back];
const badge = (u: { plan: string; source: string | null; admin: boolean }) => (u.admin ? '👑' : u.plan === 'pro' ? (u.source === 'reward' ? '🎬' : u.source === 'admin' ? '🎁' : '💎') : '·');

export const MENU: Array<[string, string]> = [
  ['📊 Dashboard', 'd'],
  ['👥 Users', 'u:0'],
  ['💻 Devices', 'dv'],
  ['🤖 Sessions', 'ss'],
  ['💰 Revenue', 'rv'],
  ['🏆 Achievements', 'ac'],
  ['⚠️ Errors', 'er:0'],
  ['🩺 Health', 'hl'],
  ['🔔 Alerts', 'al'],
  ['⚙️ Settings', 'st'],
];

export function menuScreen(c: { at: Date; tz: string }): Screen {
  const rows: Button[][] = [];
  for (let i = 0; i < MENU.length; i += 2) rows.push(MENU.slice(i, i + 2).map(([text, data]) => ({ text, callback_data: data })));
  return {
    text: `<b>🎋 BambooKit admin</b>\nChoose a screen. Type an email or user id to find a user.${footer(c)}`,
    keyboard: rows,
  };
}

export function helpText(tz: string) {
  return [
    '<b>BambooKit admin bot</b>',
    'Use the buttons. Every screen has 🔄 Refresh and ⬅️ Menu and updates in place.',
    '• /menu — main menu',
    '• /user &lt;email or id&gt; — find a user (or just type part of an email)',
    '• /help — this help',
    '',
    `<b>Definitions</b> (time zone ${esc(tz)}):`,
    '• today = since local midnight; 7 d / 30 d = last 7 / 30 local days incl. today; ▲▼ compare with the period before',
    '• active (DAU/WAU/MAU) = last seen in the window',
    '• PCs online = open realtime connection right now; revoked devices are excluded',
    '• sessions = top-level only (no sub-agents)',
    '• revenue = PAID orders in INR only',
  ].join('\n');
}

// ---------------------------------------------------------------- dashboard

export function dashboardScreen(d: Awaited<ReturnType<typeof dashboard>>): Screen {
  const u = d.users;
  const versions = d.pcs.versions.map((v) => `${esc(v.version)} ${v.count}${v.online ? ` (${v.online} on)` : ''}`).join(' · ') || '—';
  const text = [
    '<b>📊 Dashboard</b>',
    '',
    `<b>👥 Users</b> ${int(u.total)}`,
    `New: today ${u.new.today}${delta(u.new.today, u.new.yesterday)} · yesterday ${u.new.yesterday}`,
    `New: 7 d ${u.new.d7}${delta(u.new.d7, u.new.prev7)} · 30 d ${u.new.d30}${delta(u.new.d30, u.new.prev30)}`,
    `Active: DAU ${u.dau} (yesterday ${u.dauYesterday}) · WAU ${u.wau} · MAU ${u.mau}`,
    `<b>💎 Pro active</b> ${d.pro.total} · paid ${d.pro.payment} · ads ${d.pro.reward} · admin ${d.pro.admin}`,
    '',
    `<b>💻 PCs</b> ${d.pcs.registered} registered · ${d.pcs.online} online now`,
    `Versions: ${versions}`,
    `<b>📱 Phones</b> ${d.phones.registered} registered · ${d.phones.online} online now`,
    `<b>🤖 Sessions</b> ${int(d.sessions.total)} · working now ${d.sessions.working}`,
    `New today ${d.sessions.today}${delta(d.sessions.today, d.sessions.yesterday)} · yesterday ${d.sessions.yesterday}`,
    `<b>🛡️ Pending approvals</b> ${d.approvalsPending}`,
    `<b>💰 Revenue</b> today ${inr(d.revenue.todayPaise)} · 30 d ${inr(d.revenue.d30Paise)}`,
    '',
    `<b>⚙️ API</b> ${esc(d.api.version)}${d.api.commit ? ` · ${esc(d.api.commit)}` : ''} · up ${dur(d.api.uptimeSeconds)} · ${d.api.memoryMb} MB`,
    `Requests ${int(d.api.requests)} · 4xx ${d.api.clientErrors} · 5xx ${d.api.serverErrors} · error rate ${pct(d.api.errorRate)}`,
    `Realtime streams ${d.realtime.streams} (devices ${d.realtime.devices}, web ${d.realtime.web})`,
  ].join('\n');
  return { text: text + footer(d), keyboard: [[{ text: '👥 Users', callback_data: 'u:0' }, { text: '⚠️ Errors', callback_data: 'er:0' }], nav('d')] };
}

// ---------------------------------------------------------------- users

function userButtons(users: UserRow[]): Button[][] {
  return users.map((u) => [{ text: trunc(`${badge(u)} ${u.email ?? u.name ?? u.id}`, 60), callback_data: `uc:${u.id}` }]);
}

function userLine(u: UserRow, at: Date, i: number) {
  return `${i}. ${badge(u)} <b>${esc(u.email ?? '(no email)')}</b>\n    ${u.plan === 'pro' ? `Pro (${esc(u.source)})` : 'Free'} · ${u.devices} device${u.devices === 1 ? '' : 's'} · seen ${ago(u.lastSeenAt, at)}`;
}

export function usersScreen(d: Awaited<ReturnType<typeof usersPage>>): Screen {
  const lines = d.users.map((u, i) => userLine(u, d.at, d.page * 8 + i + 1));
  const pager: Button[] = [];
  if (d.page > 0) pager.push({ text: '◀', callback_data: `u:${d.page - 1}` });
  pager.push({ text: `${d.page + 1} / ${d.pages}`, callback_data: `u:${d.page}` });
  if (d.page < d.pages - 1) pager.push({ text: '▶', callback_data: `u:${d.page + 1}` });
  return {
    text: [`<b>👥 Users</b> ${int(d.total)} · newest first`, '👑 admin · 💎 paid · 🎬 ads · 🎁 granted', '', ...(lines.length ? lines : ['No users yet.']), '', 'Type an email or user id to search.'].join('\n') + footer(d),
    keyboard: [...userButtons(d.users), pager, nav(`u:${d.page}`)],
  };
}

export function searchScreen(d: Awaited<ReturnType<typeof searchUsers>>): Screen {
  const lines = d.users.map((u, i) => userLine(u, d.at, i + 1));
  return {
    text: [`<b>🔎 Search</b> “${esc(d.query)}”`, '', ...(lines.length ? lines : ['No matching users.']), d.users.length >= 8 ? '\nShowing the first 8 matches; type more of the email to narrow it.' : ''].join('\n') + footer(d),
    keyboard: [...userButtons(d.users), [{ text: '👥 All users', callback_data: 'u:0' }, { text: '⬅️ Menu', callback_data: 'm' }]],
  };
}

const ACTION_LABEL: Record<string, string> = { g7: 'Grant 7 days of Pro', g30: 'Grant 30 days of Pro', rm: 'Remove Pro (end it now)' };
export const ACTIONS = Object.keys(ACTION_LABEL);

export function userCardScreen(d: NonNullable<Awaited<ReturnType<typeof userCard>>>, opts: { notice?: string; confirm?: { action: string; data: string } } = {}): Screen {
  const u = d.user;
  const at = d.at;
  const proActive = !!u.proUntil && u.proUntil > d.w.now;
  const p = d.plan;
  const limit = (used: number, max: number | null) => (max === null ? `${used} (unlimited)` : `${used} / ${max}`);
  const devices = d.devices.length
    ? d.devices.map((x) => `${x.kind === 'desktop' ? '💻' : '📱'} ${esc(trunc(x.name, 30))} · ${esc(x.version ?? '?')} · ${x.online ? '🟢 online' : `seen ${ago(x.lastSeenAt, at)}`}`)
    : ['No devices.'];
  const orders = d.orders.length
    ? d.orders.map((o) => `${o.status === 'PAID' ? '✅' : o.status === 'PENDING' ? '⏳' : '✖️'} ${esc(o.status)} ${money(o.amountPaise, o.currency)} · ${esc(o.product)} · ${shortDateTime(o.paidAt ?? o.createdAt, d.tz)}`)
    : ['No orders.'];
  const a = d.achievements;
  const lines = [
    opts.notice ? `${opts.notice}\n` : '',
    `<b>👤 ${esc(u.email ?? '(no email)')}</b>`,
    `Name: ${esc(u.realName ?? '—')}${u.nickname ? ` · nickname ${esc(u.nickname)}` : ''}`,
    `ID: <code>${esc(u.id)}</code>`,
    `Sign-in: ${esc(u.provider ?? '?')} · email ${u.emailVerified === null ? 'verification unknown' : u.emailVerified ? 'verified ✅' : 'not verified'}`,
    `Created ${shortDateTime(u.createdAt, d.tz)} · last seen ${ago(u.lastSeenAt, at)}`,
    `Time zone: ${esc(u.timezone ?? 'not set')}`,
    '',
    `<b>Plan</b>: ${p.plan === 'pro' ? '💎 Pro' : 'Free'}${p.source ? ` (${esc(p.source)})` : ''}${u.admin ? ' · admin account (always Pro)' : ''}`,
    proActive ? `Pro until ${shortDateTime(u.proUntil, d.tz)} (${dur((Date.parse(u.proUntil!) - at.getTime()) / 1000)} left) · source ${esc(u.proSource ?? 'payment')}` : u.proUntil ? `Pro ended ${shortDateTime(u.proUntil, d.tz)}` : 'Never had Pro time.',
    `Today: messages ${limit(p.usage.phoneMessagesToday, p.limits.phoneMessagesPerDay)} · new sessions ${limit(p.usage.phoneSessionsToday, p.limits.phoneSessionsPerDay)} · PCs ${p.usage.desktops} / ${p.limits.desktops} · ads ${p.rewards.todayCount} / ${p.rewards.maxPerDay}`,
    '',
    `<b>Devices</b> (${d.devices.length})`,
    ...devices,
    `Projects ${d.projects} · sessions ${d.sessions} · coding time 7 d ${dur(d.codingMs.d7 / 1000)} · total ${dur(d.codingMs.total / 1000)}`,
    `🏆 ${a.unlocked}/${a.total} achievements · tiers ${a.tiers}/${a.tiersTotal} · ${a.points} points · streak ${a.streak ?? '—'} d`,
    '',
    '<b>Orders</b> (last 5)',
    ...orders,
  ];
  if (opts.confirm) {
    lines.push('', `❓ <b>${esc(ACTION_LABEL[opts.confirm.action] ?? opts.confirm.action)}</b> for ${esc(u.email ?? u.id)}?`);
    return {
      text: lines.filter((l, i) => i || l).join('\n') + footer(d),
      keyboard: [[{ text: '✅ Confirm', callback_data: opts.confirm.data }, { text: '✖️ Cancel', callback_data: `uc:${u.id}` }]],
    };
  }
  const actions: Button[] = [{ text: '🎁 Pro 7 d', callback_data: `ua:g7:${u.id}` }, { text: '🎁 Pro 30 d', callback_data: `ua:g30:${u.id}` }];
  if (proActive) actions.push({ text: '⛔ Remove Pro', callback_data: `ua:rm:${u.id}` });
  return {
    text: lines.filter((l, i) => i || l).join('\n') + footer(d),
    keyboard: [actions, [{ text: '🔄 Refresh', callback_data: `uc:${u.id}` }, { text: '👥 Users', callback_data: 'u:0' }, { text: '⬅️ Menu', callback_data: 'm' }]],
  };
}

// ---------------------------------------------------------------- devices, sessions

export function devicesScreenView(d: Awaited<ReturnType<typeof devicesScreen>>): Screen {
  const ver = (rows: Array<{ version: string; count: number; online: number }>, latest: string | null) =>
    rows.length ? rows.map((v) => `• ${esc(v.version)}${latest && v.version === latest ? ' ✅ latest' : ''}: ${v.count} (${v.online} online)`) : ['• none'];
  const text = [
    '<b>💻 Devices</b>',
    '',
    `<b>PCs</b> ${d.desktops.registered} registered · ${d.desktops.online} online now`,
    `Latest release: ${esc(d.desktops.latest ?? 'unknown')}${d.desktops.latest ? ` · ${d.desktops.needUpdate} need an update (${d.desktops.needUpdateOnline} online)` : ''}`,
    ...ver(d.desktops.versions, d.desktops.latest),
    '',
    `<b>Phones</b> ${d.phones.registered} registered · ${d.phones.online} online now`,
    `Latest release: ${esc(d.phones.latest ?? 'unknown')}${d.phones.latest ? ` · ${d.phones.needUpdate} need an update` : ''}`,
    ...ver(d.phones.versions, d.phones.latest),
    '',
    `New devices: today ${d.newToday} · 7 d ${d.new7d} · revoked (excluded) ${d.revoked}`,
    '<b>Recently registered</b>',
    ...(d.recent.length ? d.recent.map((x) => `${x.kind === 'desktop' ? '💻' : '📱'} ${esc(trunc(x.name, 24))} · ${esc(x.version ?? '?')} · ${esc(maskEmail(x.email))} · ${shortDateTime(x.createdAt, d.tz)}${x.online ? ' 🟢' : ''}`) : ['None yet.']),
  ].join('\n');
  return { text: text + footer(d), keyboard: [nav('dv')] };
}

export function sessionsScreenView(d: Awaited<ReturnType<typeof sessionsScreen>>): Screen {
  const text = [
    '<b>🤖 Sessions</b> (top-level only)',
    '',
    `Working now: <b>${d.workingCount}</b>`,
    ...d.working.map((s) => `• ${esc(trunc(s.title || 'Untitled', 40))} · ${esc(maskEmail(s.email))} · ${esc(trunc(s.project ?? '—', 24))} · ${s.status === 'retry' ? 'retrying, ' : ''}since ${ago(s.since, d.at).replace(' ago', '')}`),
    d.workingCount > d.working.length ? `… and ${d.workingCount - d.working.length} more` : '',
    `New: today ${d.today}${delta(d.today, d.yesterday)} · yesterday ${d.yesterday} · 7 d ${d.d7}`,
    `Active today ${d.activeToday} · agent tasks today ${d.tasksToday} · coding time today ${dur(d.codingMsToday / 1000)}`,
    '',
    `<b>🛡️ Pending approvals</b> ${d.approvalsPending}`,
    ...d.approvals.map((a) => `• ${a.kind === 'question' ? '❓' : '🔐'} ${esc(trunc(a.title ?? a.permission, 40))} · ${esc(maskEmail(a.email))} · waiting ${ago(a.createdAt, d.at).replace(' ago', '')}`),
    '',
    '<b>Top projects</b> (sessions, 7 d)',
    ...(d.topProjects.length ? d.topProjects.map((p, i) => `${i + 1}. ${esc(trunc(p.project, 30))} · ${esc(maskEmail(p.email))} · ${p.sessions}`) : ['None.']),
  ]
    .filter((l, i, all) => l !== '' || (all[i - 1] ?? '') !== '')
    .join('\n');
  return { text: text + footer(d), keyboard: [nav('ss')] };
}

// ---------------------------------------------------------------- revenue, achievements

export function revenueScreenView(d: Awaited<ReturnType<typeof revenueScreen>>): Screen {
  const r = d.paise;
  const text = [
    `<b>💰 Revenue</b> · Cashfree ${d.configured ? esc(d.environment) : 'not configured'}`,
    'PAID orders in INR only',
    '',
    `Today ${inr(r.today)} (${d.paidCount.today})${delta(r.today, r.yesterday)} · yesterday ${inr(r.yesterday)}`,
    `7 d ${inr(r.d7)} (${d.paidCount.d7})${delta(r.d7, r.prev7)}`,
    `30 d ${inr(r.d30)} (${d.paidCount.d30})`,
    `All time ${inr(r.all)}`,
    '',
    `<b>Orders, 30 d</b> (by creation): ✅ PAID ${d.byStatus.PAID} · ⏳ PENDING ${d.byStatus.PENDING} · ✖️ FAILED ${d.byStatus.FAILED} · ⌛ EXPIRED ${d.byStatus.EXPIRED}`,
    `Conversion ${d.conversion === null ? '—' : pct(d.conversion)} (${d.byStatus.PAID} paid / ${d.checkouts} checkouts)`,
    '',
    `<b>💎 Active Pro</b> ${d.activePro}`,
    ...(d.byProduct.length ? d.byProduct.map((p) => `• ${esc(p.key === 'reward' ? 'Rewarded ads' : p.key === 'admin' ? 'Granted by admin' : p.name)}: ${p.count}`) : []),
    `🎬 Rewards granted: today ${d.rewards.today} · 7 d ${d.rewards.d7}`,
    '',
    '<b>Last payments</b>',
    ...(d.payments.length ? d.payments.map((p) => `• ${money(p.amountPaise, p.currency)} · ${esc(p.product)} · ${esc(maskEmail(p.email))} · ${shortDateTime(p.paidAt, d.tz)}`) : ['None yet.']),
  ].join('\n');
  return { text: text + footer(d), keyboard: [nav('rv')] };
}

const TIER_EMOJI: Record<string, string> = { bronze: '🥉', silver: '🥈', gold: '🥇', platinum: '💠', diamond: '💎' };

export function achievementsScreenView(d: Awaited<ReturnType<typeof achievementsScreen>>): Screen {
  const text = [
    '<b>🏆 Achievements</b>',
    '',
    `Tiers unlocked: today ${d.today}${delta(d.today, d.yesterday)} · 7 d ${d.d7}`,
    `Users with any tier: ${d.usersWithAny}`,
    `By tier: ${d.byTier.map((t) => `${TIER_EMOJI[t.tier]} ${t.count}`).join(' · ')}`,
    '',
    '<b>Most unlocked</b> (users with Bronze+)',
    ...(d.mostUnlocked.length ? d.mostUnlocked.map((a, i) => `${i + 1}. ${esc(a.title)} · ${a.users}`) : ['None yet.']),
    '',
    '<b>Top users</b> (points)',
    ...(d.topUsers.length ? d.topUsers.map((u, i) => `${i + 1}. ${esc(maskEmail(u.email))} · ${u.points} pts · ${u.tiers} tiers`) : ['None yet.']),
  ].join('\n');
  return { text: text + footer(d), keyboard: [nav('ac')] };
}

// ---------------------------------------------------------------- errors, health

function errorLine(e: RecentError, tz: string) {
  return `• ${shortDateTime(e.at, tz)} ${esc(e.method)} ${esc(trunc(e.path, 50))} → ${e.status} ${esc(e.code)}\n   <code>${esc(e.requestId)}</code>${e.client ? ` · ${esc(e.client)}` : ''}`;
}

export function errorsScreenView(d: ReturnType<typeof errorsScreen>): Screen {
  const since = d.uptimeSeconds < 86400 ? ` (since restart ${dur(d.uptimeSeconds)} ago)` : '';
  const text = [
    '<b>⚠️ Server errors</b>',
    `Last hour ${d.lastHour} · last 24 h ${d.last24h}${since}`,
    d.topCodes.length ? `Top codes: ${d.topCodes.map((c) => `${esc(c.code)} ×${c.count}`).join(' · ')}` : '',
    '',
    ...(d.errors.length ? d.errors.map((e) => errorLine(e, d.tz)) : ['✅ No server errors since the last start.']),
  ]
    .filter((l, i) => l !== '' || i > 2)
    .join('\n');
  const pager: Button[] = [];
  if (d.page > 0) pager.push({ text: '◀', callback_data: `er:${d.page - 1}` });
  if (d.pages > 1) pager.push({ text: `${d.page + 1} / ${d.pages}`, callback_data: `er:${d.page}` });
  if (d.page < d.pages - 1) pager.push({ text: '▶', callback_data: `er:${d.page + 1}` });
  return { text: text + footer(d), keyboard: [...(pager.length ? [pager] : []), nav(`er:${d.page}`)] };
}

export type WebhookInfo = { pending: number | null; lastError: string | null; lastErrorAt: string | null; ok: boolean };

export function healthScreenView(d: Awaited<ReturnType<typeof healthScreen>>, hook: WebhookInfo): Screen {
  const h = d.health;
  const text = [
    '<b>🩺 Health</b>',
    '',
    `${d.db.ok ? '✅' : '❌'} Database ${esc(d.db.dialect)} · SELECT 1 in ${d.db.latencyMs} ms${d.db.error ? ` · ${esc(d.db.error)}` : ''}`,
    `${d.storage ? '✅' : '➖'} Storage ${d.storage ? esc(d.storage) : 'not configured'}`,
    `${d.cashfree.configured ? '✅' : '➖'} Cashfree ${d.cashfree.configured ? esc(d.cashfree.environment) : 'not configured'}`,
    `${d.admob.keys ? '✅' : d.admob.lastError ? '❌' : '➖'} AdMob SSV keys: ${d.admob.keys ? `${d.admob.keys} cached ${shortDateTime(d.admob.loadedAt, d.tz)}` : 'not loaded yet (loaded on the first reward callback)'}${d.admob.lastError ? ` · last error ${esc(trunc(d.admob.lastError.message, 80))}` : ''}`,
    `${hook.ok ? (hook.lastError ? '⚠️' : '✅') : '❌'} Telegram webhook: ${hook.ok ? `${hook.pending ?? 0} pending updates` : 'info unavailable'}${hook.lastError ? `\n   last error ${esc(trunc(hook.lastError, 120))}${hook.lastErrorAt ? ` at ${shortDateTime(hook.lastErrorAt, d.tz)}` : ''}` : ''}`,
    '',
    `Uptime ${dur(h.uptimeSeconds)} (since ${shortDateTime(h.startedAt, d.tz)})`,
    `Memory ${h.memoryMb} MB RSS · heap ${h.heapMb} MB`,
    `Event loop lag ${h.eventLoopLagMs ?? '—'} ms avg · p99 ${h.eventLoopLagP99Ms ?? '—'} ms`,
    `Requests ${int(h.requests)} · 4xx ${h.clientErrors} · 5xx ${h.serverErrors}`,
    `Admin emails configured: ${d.adminEmails}`,
  ].join('\n');
  return { text: text + footer(d), keyboard: [nav('hl')] };
}

// ---------------------------------------------------------------- alerts, settings, report

export const ALERT_KINDS = [
  ['signup', '🆕 New sign-ups'],
  ['payment', '💰 Payments'],
  ['payment_failed', '💸 Failed payments'],
  ['server_error', '⚠️ Server errors (max 1 per 5 min)'],
  ['error_spike', '📈 Error spikes'],
  ['daily_report', '🗓️ Daily report 09:00'],
] as const;
export type AlertKind = (typeof ALERT_KINDS)[number][0];

export function alertsScreenView(c: { at: Date; tz: string }, on: Record<AlertKind, boolean>, spike: number, notice = ''): Screen {
  const text = [
    notice ? `${notice}\n` : '',
    '<b>🔔 Alerts</b>',
    'Tap to switch an alert on or off. Settings are saved and survive restarts.',
    '',
    ...ALERT_KINDS.map(([k, label]) => `${on[k] ? '✅' : '🔕'} ${label}`),
    `Error spike = more than ${spike} server errors in 5 minutes.`,
  ]
    .filter((l, i) => i || l)
    .join('\n');
  return {
    text: text + footer(c),
    keyboard: [
      ...ALERT_KINDS.map(([k, label]) => [{ text: `${on[k] ? '✅' : '🔕'} ${label.replace(/^\S+ /, '')}`, callback_data: `at:${k}` }]),
      [{ text: '🔔 All on', callback_data: 'at:all1' }, { text: '🔕 All off', callback_data: 'at:all0' }],
      nav('al'),
    ],
  };
}

export function settingsScreenView(c: { at: Date; tz: string }, s: { spike: number; lastReport: string | null; adminChats: number; reportHour: number }, notice = ''): Screen {
  const text = [
    notice ? `${notice}\n` : '',
    '<b>⚙️ Settings</b>',
    '',
    `Time zone: ${esc(c.tz)} (TELEGRAM_TIMEZONE)`,
    `Daily report: every day at ${String(s.reportHour).padStart(2, '0')}:00 · last sent ${esc(s.lastReport ?? 'never')}`,
    `Error spike threshold: more than ${s.spike} server errors in 5 min`,
    `Admin chats: ${s.adminChats}`,
  ]
    .filter((l, i) => i || l)
    .join('\n');
  return {
    text: text + footer(c),
    keyboard: [
      [{ text: '🗓️ Send report now', callback_data: 'sr' }],
      [5, 10, 25, 50].map((n) => ({ text: `${n === s.spike ? '• ' : ''}Spike > ${n}`, callback_data: `sp:${n}` })),
      [{ text: '🔔 Alerts', callback_data: 'al' }, { text: '❓ Help', callback_data: 'hp' }],
      nav('st'),
    ],
  };
}

export function reportText(r: Awaited<ReturnType<typeof dailyReport>>) {
  return [
    `🗓️ <b>Daily report</b> · ${esc(r.day)} (${esc(r.tz)})`,
    '',
    `🆕 New users ${r.newUsers}${delta(r.newUsers, r.newUsersPrev)} · total ${int(r.totalUsers)}`,
    `👥 DAU ${r.dau}${delta(r.dau, r.dauPrev)}`,
    `🤖 New sessions ${r.sessions}${delta(r.sessions, r.sessionsPrev)}`,
    `💰 Revenue ${inr(r.revenuePaise)} from ${r.payments} payment${r.payments === 1 ? '' : 's'}${delta(r.revenuePaise, r.revenuePrevPaise)}`,
    `🏆 Achievement tiers unlocked ${r.tiers}`,
    `⚠️ Server errors (last 24 h) ${r.errors24h}${r.uptimeSeconds < 86400 ? ` · up ${dur(r.uptimeSeconds)}` : ''}`,
  ].join('\n');
}
