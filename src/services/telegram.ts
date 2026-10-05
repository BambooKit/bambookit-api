import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { Hono } from 'hono';
import { env, VERSION } from '../config/env.js';
import { db, now } from '../db/database.js';
import { adminTimeZone } from '../lib/activity.js';
import { newId } from '../lib/http.js';
import { logger } from '../lib/logger.js';
import { maskEmail } from '../lib/mask.js';
import { onServerError, serverErrorsSince } from '../lib/monitor.js';
import { localClock, localDate } from '../lib/timezone.js';
import { setNewUserListener } from '../middleware/auth.js';
import {
  achievementsScreen,
  context,
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
} from '../modules/admin-panel.js';
import { adminGrantPro, adminRemovePro, setPaymentFailedListener, setPaymentListener } from '../modules/billing.js';
import {
  ACTIONS,
  ALERT_KINDS,
  achievementsScreenView,
  alertsScreenView,
  dashboardScreen,
  devicesScreenView,
  errorsScreenView,
  esc,
  healthScreenView,
  helpText,
  menuScreen,
  reportText,
  revenueScreenView,
  searchScreen,
  sessionsScreenView,
  settingsScreenView,
  userCardScreen,
  usersScreen,
  type AlertKind,
  type Button,
  type Screen,
  type WebhookInfo,
} from './telegram-ui.js';

export { maskEmail };

/**
 * BambooKit admin bot for Telegram.
 *
 * - Only chats listed in TELEGRAM_ADMIN_CHAT_IDS can use it; anyone else only learns their own chat id.
 * - Navigation with inline buttons (callback queries): every screen edits its message in place and has
 *   🔄 Refresh and ⬅️ Menu; a short persistent reply keyboard and /menu, /user, /help stay available.
 * - Numbers use the admin time zone (TELEGRAM_TIMEZONE, default Asia/Kolkata); see modules/admin-panel.ts.
 * - Admin actions (grant / remove Pro) need a confirmation tap and are recorded in admin_actions.
 * - Alerts (toggles persisted in telegram_settings) and a daily report at 09:00 admin time.
 * - Outgoing messages are split at 4096 characters and rate limited (1 per second per chat, 30 per second).
 * - Telegram calls the webhook with the secret token; the bot token is never logged, returned or sent in a body.
 */

const token = env.TELEGRAM_BOT_TOKEN?.trim() || null;
const adminChats = new Set((env.TELEGRAM_ADMIN_CHAT_IDS ?? '').split(',').map((s) => s.trim()).filter(Boolean));
export const telegramEnabled = !!token;
export const webhookSecret = env.TELEGRAM_WEBHOOK_SECRET?.trim() || (token ? createHash('sha256').update(`bambookit-telegram:${token}`).digest('hex').slice(0, 48) : '');
export const REPORT_HOUR = 9;
const MAX_TEXT = 4096;

/** Outgoing limits; tests set perChatMs to 0. */
export const telegramLimits = { perChatMs: 1000, globalPerSecond: 30 };

// ---------------------------------------------------------------- transport

async function call(method: string, body: Record<string, unknown>) {
  if (!token) return null;
  try {
    const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    const json: any = await res.json().catch(() => null);
    if (!json?.ok) logger.warn('telegram call failed', { method, status: res.status, description: String(json?.description ?? '').slice(0, 200) });
    return json;
  } catch (err: any) {
    logger.warn('telegram call failed', { method, error: String(err?.name ?? 'network') });
    return null;
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const chains = new Map<string, Promise<unknown>>();
const lastSent = new Map<string, number>();
const globalSent: number[] = [];

async function globalSlot() {
  for (;;) {
    const t = Date.now();
    while (globalSent.length && t - globalSent[0] >= 1000) globalSent.shift();
    if (globalSent.length < telegramLimits.globalPerSecond) {
      globalSent.push(t);
      return;
    }
    await sleep(1000 - (t - globalSent[0]));
  }
}

/** Runs one outgoing message call in order per chat, at most 1 per second per chat and 30 per second overall. */
function queued<T>(chatId: string | number, fn: () => Promise<T>): Promise<T> {
  const key = String(chatId);
  const run = (chains.get(key) ?? Promise.resolve()).then(async () => {
    const wait = (lastSent.get(key) ?? 0) + telegramLimits.perChatMs - Date.now();
    if (wait > 0) await sleep(wait);
    await globalSlot();
    lastSent.set(key, Date.now());
    return fn();
  });
  const tail = run.catch(() => undefined);
  chains.set(key, tail);
  void tail.then(() => {
    if (chains.get(key) === tail) chains.delete(key);
    if (lastSent.size > 1000) lastSent.clear();
  });
  return run;
}

/** Splits HTML text at line breaks into chunks of at most 4096 characters (tags never span lines). */
export function splitMessage(text: string, max = MAX_TEXT): string[] {
  if (text.length <= max) return [text];
  const out: string[] = [];
  let cur = '';
  for (let line of text.split('\n')) {
    if (line.length > max) line = `${line.replace(/<[^>]*>/g, '').slice(0, max - 1)}…`;
    if (cur && cur.length + 1 + line.length > max) {
      out.push(cur);
      cur = line;
    } else cur = cur ? `${cur}\n${line}` : line;
  }
  if (cur) out.push(cur);
  return out;
}

type Markup = { inline_keyboard: Button[][] } | typeof replyKeyboard;

async function send(chatId: string | number, html: string, markup?: Markup) {
  const parts = splitMessage(html);
  let last: any = null;
  for (let i = 0; i < parts.length; i++) {
    const body: Record<string, unknown> = { chat_id: chatId, text: parts[i], parse_mode: 'HTML', disable_web_page_preview: true };
    if (markup && i === parts.length - 1) body.reply_markup = markup;
    last = await queued(chatId, () => call('sendMessage', body));
  }
  return last;
}

/** Edits a screen in place; text beyond 4096 characters follows as extra messages. */
async function edit(chatId: string | number, messageId: number, screen: Screen) {
  const parts = splitMessage(screen.text);
  const res = await queued(chatId, () =>
    call('editMessageText', { chat_id: chatId, message_id: messageId, text: parts[0], parse_mode: 'HTML', disable_web_page_preview: true, reply_markup: { inline_keyboard: compact(screen.keyboard) } }),
  );
  for (const p of parts.slice(1)) await send(chatId, p);
  return res;
}

const sendScreen = (chatId: string | number, screen: Screen) => send(chatId, screen.text, { inline_keyboard: compact(screen.keyboard) });

/** Telegram allows 64 bytes of callback data; longer values are kept here under a short key. */
const longData = new Map<string, string>();
function compact(rows: Button[][]): Button[][] {
  return rows.map((row) =>
    row.map((b) => {
      if (Buffer.byteLength(b.callback_data) <= 64) return b;
      const key = `~${randomBytes(6).toString('base64url')}`;
      longData.set(key, b.callback_data);
      if (longData.size > 2000) longData.delete(longData.keys().next().value!);
      return { ...b, callback_data: key };
    }),
  );
}

export async function sendToAdmins(html: string) {
  if (!token) return;
  for (const chat of adminChats) await send(chat, html, replyKeyboard);
}

// ---------------------------------------------------------------- settings (persisted)

const DEFAULT_SPIKE = 10;
let settingsCache: Map<string, string> | null = null;

async function settings() {
  if (!settingsCache) {
    const rows = await db.all<{ key: string; value: string }>('SELECT key, value FROM telegram_settings');
    settingsCache = new Map(rows.map((r) => [r.key, r.value]));
  }
  return settingsCache;
}

/** Drops the in-memory copy so the next read comes from the database (tests, restarts). */
export function reloadTelegramSettings() {
  settingsCache = null;
}

async function setSetting(key: string, value: string) {
  await db.run(
    'INSERT INTO telegram_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at',
    key,
    value,
    now(),
  );
  (await settings()).set(key, value);
}

export async function alertEnabled(kind: AlertKind) {
  return (await settings()).get(`alert.${kind}`) !== '0';
}

async function alertStates() {
  const s = await settings();
  return Object.fromEntries(ALERT_KINDS.map(([k]) => [k, s.get(`alert.${k}`) !== '0'])) as Record<AlertKind, boolean>;
}

async function spikeThreshold() {
  const v = Number((await settings()).get('spike.threshold'));
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_SPIKE;
}

/** Sends an alert of one kind to every admin chat when that alert is switched on. */
export async function alert(kind: AlertKind, html: string) {
  if (!token) return;
  try {
    if (await alertEnabled(kind)) await sendToAdmins(html);
  } catch (err: any) {
    logger.warn('telegram alert failed', { kind, error: String(err?.message ?? err).slice(0, 200) });
  }
}

// ---------------------------------------------------------------- alert texts

/** Alert text for a successful payment (wired with setPaymentListener). */
export function paymentAlertText(p: { amount: number; currency: string; productName: string; email: string | null; environment: string }) {
  return `💰 <b>Payment received</b>${p.environment === 'sandbox' ? ' (sandbox)' : ''}
${p.currency === 'INR' ? '₹' : `${esc(p.currency)} `}${p.amount.toFixed(2)} · ${esc(p.productName)}
${esc(maskEmail(p.email))}`;
}

export function paymentFailedAlertText(p: { amount: number; currency: string; productName: string; email: string | null; environment: string; reason: string }) {
  return `💸 <b>Payment failed</b>${p.environment === 'sandbox' ? ' (sandbox)' : ''}
${p.currency === 'INR' ? '₹' : `${esc(p.currency)} `}${p.amount.toFixed(2)} · ${esc(p.productName)}
${esc(maskEmail(p.email))} · ${esc(p.reason)}`;
}

export function signupAlertText(u: { email: string | null; provider: string }) {
  return `🆕 <b>New BambooKit user</b>\n${esc(maskEmail(u.email))} · ${esc(u.provider)}`;
}

let wired = false;
let lastErrorAlert = 0;
let lastSpikeAlert = 0;
/** Connects sign-up, payment and server-error events to alerts (once). */
export function wireTelegramAlerts() {
  if (wired || !token) return;
  wired = true;
  setNewUserListener((u) => void alert('signup', signupAlertText(u)));
  setPaymentListener((p) => void alert('payment', paymentAlertText(p)));
  setPaymentFailedListener((p) => void alert('payment_failed', paymentFailedAlertText(p)));
  onServerError((e) => {
    void (async () => {
      const t = Date.now();
      const recent = serverErrorsSince(5 * 60_000, t);
      const threshold = await spikeThreshold();
      if (recent > threshold && t - lastSpikeAlert >= 15 * 60_000) {
        lastSpikeAlert = t;
        await alert('error_spike', `📈 <b>Error spike</b>: ${recent} server errors in the last 5 minutes (threshold ${threshold}).\nLatest: ${esc(e.method)} ${esc(e.path)} → ${e.status} ${esc(e.code)}`);
      }
      if (t - lastErrorAlert < 5 * 60_000) return;
      lastErrorAlert = t;
      await alert('server_error', `⚠️ <b>Server error</b>\n${esc(e.method)} ${esc(e.path)} → ${e.status} ${esc(e.code)}\n${esc(e.message.slice(0, 200))}\n<code>${esc(e.requestId)}</code>`);
    })();
  });
}

// ---------------------------------------------------------------- daily report

async function sendReport(at = new Date()) {
  await sendToAdmins(reportText(await dailyReport(at)));
}

/**
 * Sends the daily report once per admin-zone day, at or after 09:00. The date is claimed in
 * telegram_settings first (atomic upsert), so restarts and several instances never send it twice.
 */
export async function checkDailyReport(at = new Date()): Promise<boolean> {
  if (!token) return false;
  const tz = adminTimeZone();
  if (localClock(at, tz).hour < REPORT_HOUR) return false;
  if (!(await alertEnabled('daily_report'))) return false;
  const day = localDate(at, tz);
  const claimed = await db.run(
    `INSERT INTO telegram_settings (key, value, updated_at) VALUES ('report.last_sent', ?, ?)
     ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at WHERE telegram_settings.value < excluded.value`,
    day,
    now(),
  );
  if (claimed.changes !== 1) return false;
  (await settings()).set('report.last_sent', day);
  await sendReport(at);
  logger.info('telegram daily report sent', { day });
  return true;
}

let reportTimer: ReturnType<typeof setInterval> | null = null;
function startDailyReports() {
  if (reportTimer) return;
  reportTimer = setInterval(() => void checkDailyReport().catch((err) => logger.warn('daily report failed', { error: String(err?.message ?? err).slice(0, 200) })), 60_000);
  reportTimer.unref?.();
}

// ---------------------------------------------------------------- admin actions

async function logAdminAction(chatId: string, action: string, targetUserId: string | null, detail: Record<string, unknown> = {}) {
  await db.run(
    'INSERT INTO admin_actions (id, actor, action, target_user_id, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    newId('adm'),
    `telegram:${chatId}`,
    action,
    targetUserId,
    JSON.stringify(detail),
    now(),
  );
  logger.info('admin action', { actor: `telegram:${chatId}`, action, targetUserId });
}

/** One-time confirmation tokens: a Confirm button works once, for 10 minutes, in the chat that asked. */
const confirmations = new Map<string, { action: string; userId: string; chat: string; expires: number }>();
function confirmationFor(action: string, userId: string, chat: string) {
  const id = randomBytes(9).toString('base64url');
  for (const [k, v] of confirmations) if (v.expires < Date.now()) confirmations.delete(k);
  confirmations.set(id, { action, userId, chat, expires: Date.now() + 10 * 60_000 });
  return `ux:${id}`;
}

async function runAction(chat: string, id: string): Promise<{ screen: Screen; toast: string }> {
  const pending = confirmations.get(id);
  confirmations.delete(id);
  if (!pending || pending.expires < Date.now() || pending.chat !== chat) {
    return { screen: menuScreen(context()), toast: 'This confirmation expired. Open the user again.' };
  }
  const { action, userId } = pending;
  let notice: string;
  if (action === 'g7' || action === 'g30') {
    const days = action === 'g7' ? 7 : 30;
    const until = await adminGrantPro(userId, days);
    await logAdminAction(chat, 'pro.grant', userId, { days, until });
    notice = `✅ Granted ${days} days of Pro.`;
  } else {
    const changed = await adminRemovePro(userId);
    await logAdminAction(chat, 'pro.remove', userId, { changed });
    notice = changed ? '✅ Pro removed (ends now).' : 'ℹ️ No running Pro time to remove.';
  }
  const card = await userCard(userId);
  return { screen: card ? userCardScreen(card, { notice }) : menuScreen(context()), toast: notice.replace(/^\S+ /, '') };
}

// ---------------------------------------------------------------- screens

async function webhookInfo(): Promise<WebhookInfo> {
  const res = await call('getWebhookInfo', {});
  const r = res?.ok ? res.result ?? {} : null;
  return {
    ok: !!r,
    pending: r ? Number(r.pending_update_count ?? 0) : null,
    lastError: r?.last_error_message ? String(r.last_error_message) : null,
    lastErrorAt: r?.last_error_date ? new Date(Number(r.last_error_date) * 1000).toISOString() : null,
  };
}

async function settingsView(notice = '') {
  return settingsScreenView(context(), { spike: await spikeThreshold(), lastReport: (await settings()).get('report.last_sent') ?? null, adminChats: adminChats.size, reportHour: REPORT_HOUR }, notice);
}

/** Builds the screen for callback data (or a reply-keyboard shortcut). `toast` is shown by answerCallbackQuery. */
async function render(data: string, chat: string): Promise<{ screen: Screen; toast?: string }> {
  if (data.startsWith('~')) data = longData.get(data) ?? 'm';
  const [kind, a = '', ...rest] = data.split(':');
  const b = rest.join(':');
  switch (kind) {
    case 'm':
      return { screen: menuScreen(context()) };
    case 'd':
      return { screen: dashboardScreen(await dashboard()) };
    case 'u':
      return { screen: usersScreen(await usersPage(Number(a) || 0)) };
    case 'uc': {
      const id = [a, b].filter(Boolean).join(':');
      const card = await userCard(id);
      return card ? { screen: userCardScreen(card) } : { screen: usersScreen(await usersPage(0)), toast: 'User not found.' };
    }
    case 'ua': {
      if (!ACTIONS.includes(a)) return { screen: menuScreen(context()) };
      const card = await userCard(b);
      if (!card) return { screen: usersScreen(await usersPage(0)), toast: 'User not found.' };
      return { screen: userCardScreen(card, { confirm: { action: a, data: confirmationFor(a, b, chat) } }), toast: 'Confirm below.' };
    }
    case 'ux':
      return runAction(chat, a);
    case 'dv':
      return { screen: devicesScreenView(await devicesScreen()) };
    case 'ss':
      return { screen: sessionsScreenView(await sessionsScreen()) };
    case 'rv':
      return { screen: revenueScreenView(await revenueScreen()) };
    case 'ac':
      return { screen: achievementsScreenView(await achievementsScreen()) };
    case 'er':
      return { screen: errorsScreenView(errorsScreen(Number(a) || 0)) };
    case 'hl':
      return { screen: healthScreenView(await healthScreen(), await webhookInfo()) };
    case 'al':
      return { screen: alertsScreenView(context(), await alertStates(), await spikeThreshold()) };
    case 'at': {
      let notice = '';
      if (a === 'all1' || a === 'all0') {
        for (const [k] of ALERT_KINDS) await setSetting(`alert.${k}`, a === 'all1' ? '1' : '0');
        notice = a === 'all1' ? '🔔 All alerts on.' : '🔕 All alerts off.';
      } else if (ALERT_KINDS.some(([k]) => k === a)) {
        const on = !(await alertEnabled(a as AlertKind));
        await setSetting(`alert.${a}`, on ? '1' : '0');
        notice = `${on ? '🔔' : '🔕'} ${ALERT_KINDS.find(([k]) => k === a)![1]} ${on ? 'on' : 'off'}.`;
      }
      if (notice) await logAdminAction(chat, 'alerts.update', null, { alert: a });
      return { screen: alertsScreenView(context(), await alertStates(), await spikeThreshold(), notice), toast: notice.replace(/^\S+ /, '') };
    }
    case 'st':
      return { screen: await settingsView() };
    case 'sp': {
      const n = Number(a);
      if (![5, 10, 25, 50].includes(n)) return { screen: await settingsView() };
      await setSetting('spike.threshold', String(n));
      await logAdminAction(chat, 'settings.spike', null, { threshold: n });
      return { screen: await settingsView(`✅ Error spike threshold: more than ${n} in 5 min.`), toast: 'Saved.' };
    }
    case 'sr':
      await sendReport();
      await logAdminAction(chat, 'report.send', null);
      return { screen: await settingsView('✅ Report sent (see below).'), toast: 'Report sent.' };
    case 'hp':
      return { screen: { text: helpText(adminTimeZone()), keyboard: [[{ text: '⬅️ Menu', callback_data: 'm' }]] } };
    default:
      return { screen: menuScreen(context()), toast: 'Unknown button.' };
  }
}

// ---------------------------------------------------------------- updates

const SHORTCUTS = {
  menu: '📋 Menu',
  dashboard: '📊 Dashboard',
  users: '👥 Users',
  errors: '⚠️ Errors',
} as const;

const replyKeyboard = {
  keyboard: [
    [{ text: SHORTCUTS.menu }, { text: SHORTCUTS.dashboard }],
    [{ text: SHORTCUTS.users }, { text: SHORTCUTS.errors }],
  ],
  resize_keyboard: true,
  is_persistent: true,
};

/** Typed button labels (current keyboard, menu labels and the previous keyboard) → screens. */
const TEXT_ROUTES: Record<string, string> = {
  [SHORTCUTS.menu]: 'm',
  [SHORTCUTS.dashboard]: 'd',
  [SHORTCUTS.users]: 'u:0',
  [SHORTCUTS.errors]: 'er:0',
  '💻 Devices': 'dv',
  '🤖 Sessions': 'ss',
  '💰 Revenue': 'rv',
  '🏆 Achievements': 'ac',
  '🩺 Health': 'hl',
  '🔔 Alerts': 'al',
  '⚙️ Settings': 'st',
  '📊 Status': 'd',
  '🆕 New sign-ups': 'u:0',
  '🔔 Alerts on/off': 'al',
};

const stranger = (chatId: number | string) => `This bot is private. Your chat id is ${chatId}. If you run this BambooKit server, add it to TELEGRAM_ADMIN_CHAT_IDS.`;

async function onMessage(message: any) {
  const chatId = message.chat.id;
  const chat = String(chatId);
  if (!adminChats.has(chat)) {
    await queued(chatId, () => call('sendMessage', { chat_id: chatId, text: stranger(chatId) }));
    return;
  }
  const text = String(message.text).trim();
  const command = /^\/(\w+)(?:@\w+)?(?:\s+([\s\S]*))?$/.exec(text);
  if (command) {
    const [, name, arg = ''] = command;
    if (name === 'start') {
      await send(chatId, `👋 <b>BambooKit admin</b>\nUse the buttons. Type an email or user id at any time to find a user.`, replyKeyboard);
      await sendScreen(chatId, menuScreen(context()));
    } else if (name === 'menu') await sendScreen(chatId, menuScreen(context()));
    else if (name === 'user' && arg.trim()) await sendScreen(chatId, searchScreen(await searchUsers(arg)));
    else await send(chatId, helpText(adminTimeZone()), replyKeyboard);
    return;
  }
  const route = TEXT_ROUTES[text];
  if (route) {
    await sendScreen(chatId, (await render(route, chat)).screen);
    return;
  }
  if (text.length >= 2) await sendScreen(chatId, searchScreen(await searchUsers(text)));
  else await send(chatId, helpText(adminTimeZone()), replyKeyboard);
}

async function onCallback(cq: any) {
  const chatId = cq.message?.chat?.id;
  const messageId = cq.message?.message_id;
  if (!chatId || !adminChats.has(String(chatId))) {
    await call('answerCallbackQuery', { callback_query_id: cq.id, text: stranger(chatId ?? cq.from?.id ?? '?'), show_alert: true });
    return;
  }
  let toast: string | undefined;
  try {
    const result = await render(String(cq.data ?? 'm'), String(chatId));
    toast = result.toast;
    const res = messageId ? await edit(chatId, messageId, result.screen) : await sendScreen(chatId, result.screen);
    if (res && !res.ok && /not modified/i.test(String(res.description ?? ''))) toast ??= 'Already up to date.';
  } catch (err: any) {
    logger.warn('telegram screen failed', { data: String(cq.data ?? '').slice(0, 20), error: String(err?.message ?? err).slice(0, 200) });
    toast = 'Something went wrong. Try again.';
  } finally {
    await call('answerCallbackQuery', { callback_query_id: cq.id, ...(toast ? { text: toast.slice(0, 190) } : {}) });
  }
}

export const telegramRouter = new Hono();

// POST /telegram/webhook — Telegram delivers bot updates here (secret token header required).
telegramRouter.post('/webhook', async (c) => {
  if (!token) return c.json({ ok: false }, 404);
  const given = Buffer.from(c.req.header('X-Telegram-Bot-Api-Secret-Token') ?? '');
  const want = Buffer.from(webhookSecret);
  if (given.length !== want.length || !timingSafeEqual(given, want)) return c.json({ ok: false }, 403);
  const update: any = await c.req.json().catch(() => null);
  try {
    if (update?.callback_query?.id) await onCallback(update.callback_query);
    else if (update?.message?.chat?.id && typeof update.message.text === 'string') await onMessage(update.message);
  } catch (err: any) {
    logger.warn('telegram update failed', { error: String(err?.message ?? err).slice(0, 200) });
  }
  return c.json({ ok: true });
});

/** Registers the webhook and commands, wires alerts, starts the daily report and announces the start. Called once at boot. */
export async function startTelegram(publicUrl: string | undefined) {
  if (!token) return;
  if (publicUrl) {
    const res = await call('setWebhook', { url: `${publicUrl.replace(/\/+$/, '')}/telegram/webhook`, secret_token: webhookSecret, allowed_updates: ['message', 'callback_query'] });
    logger.info('Telegram bot', { webhook: res?.ok ? 'registered' : 'failed', adminChats: adminChats.size, timeZone: adminTimeZone() });
  } else {
    logger.info('Telegram bot: no public URL, webhook not registered');
  }
  await call('setMyCommands', {
    commands: [
      { command: 'menu', description: 'Admin panel menu' },
      { command: 'user', description: 'Find a user by email or id' },
      { command: 'help', description: 'Help and definitions' },
    ],
  });
  wireTelegramAlerts();
  startDailyReports();
  void checkDailyReport().catch(() => undefined);
  if (await alertEnabled('server_error').catch(() => true)) {
    void sendToAdmins(`🟢 <b>BambooKit API ${esc(VERSION)}</b> started${process.env.RENDER_GIT_COMMIT ? ` (${esc(process.env.RENDER_GIT_COMMIT.slice(0, 7))})` : ''}.`);
  }
}
