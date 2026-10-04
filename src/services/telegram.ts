import { createHash, timingSafeEqual } from 'node:crypto';
import { Hono } from 'hono';
import { env, VERSION } from '../config/env.js';
import { logger } from '../lib/logger.js';
import { onServerError } from '../lib/monitor.js';
import { adminSnapshot, recentUsers } from '../modules/admin.js';

/**
 * BambooKit monitoring bot for Telegram.
 *
 * - Only chats listed in TELEGRAM_ADMIN_CHAT_IDS can use it; anyone else only learns their own chat id
 *   (so the owner can add it) and nothing about the service.
 * - Buttons instead of typed commands (a reply keyboard): Status, Users, Devices, Sessions, Errors,
 *   New sign-ups, Alerts on/off.
 * - Alerts: API started, new sign-ups, server errors (at most one error alert per 5 minutes).
 * - Telegram calls us through a webhook that must carry the secret token; the bot token itself is never
 *   logged or returned.
 */

const token = env.TELEGRAM_BOT_TOKEN?.trim() || null;
const adminChats = new Set((env.TELEGRAM_ADMIN_CHAT_IDS ?? '').split(',').map((s) => s.trim()).filter(Boolean));
export const telegramEnabled = !!token;
export const webhookSecret = env.TELEGRAM_WEBHOOK_SECRET?.trim() || (token ? createHash('sha256').update(`bambookit-telegram:${token}`).digest('hex').slice(0, 48) : '');

let alertsOn = true;
let lastErrorAlert = 0;

const BUTTONS = {
  status: '📊 Status',
  users: '👥 Users',
  devices: '💻 Devices',
  sessions: '🤖 Sessions',
  errors: '⚠️ Errors',
  signups: '🆕 New sign-ups',
  alerts: '🔔 Alerts on/off',
} as const;

const keyboard = {
  keyboard: [
    [{ text: BUTTONS.status }, { text: BUTTONS.users }],
    [{ text: BUTTONS.devices }, { text: BUTTONS.sessions }],
    [{ text: BUTTONS.errors }, { text: BUTTONS.signups }],
    [{ text: BUTTONS.alerts }],
  ],
  resize_keyboard: true,
  is_persistent: true,
};

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

const escape = (s: unknown) => String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!);

export async function sendToAdmins(html: string) {
  if (!token) return;
  for (const chat of adminChats) await call('sendMessage', { chat_id: chat, text: html, parse_mode: 'HTML', disable_web_page_preview: true, reply_markup: keyboard });
}

export function alert(html: string) {
  if (alertsOn) void sendToAdmins(html);
}

const dur = (s: number) => (s >= 86400 ? `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h` : s >= 3600 ? `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m` : `${Math.floor(s / 60)}m`);

async function answer(button: string): Promise<string> {
  const snap = await adminSnapshot();
  switch (button) {
    case BUTTONS.status:
      return [
        `<b>BambooKit API ${escape(VERSION)}</b> · ${snap.service.commit ? escape(snap.service.commit) : 'local'}`,
        `Up ${dur(snap.health.uptimeSeconds)} · ${snap.health.memoryMb} MB`,
        `Database: ${escape(snap.service.database)} · Storage: ${snap.service.storage ? 'on' : 'off'}`,
        `Requests: ${snap.health.requests} · 4xx: ${snap.health.clientErrors} · 5xx: ${snap.health.serverErrors}`,
        `Realtime streams: ${snap.realtime.streams}`,
      ].join('\n');
    case BUTTONS.users:
      return [
        `<b>Users</b>: ${snap.users.total}`,
        `New: ${snap.users.new24h} today · ${snap.users.new7d} this week`,
        `Active (24 h): ${snap.users.active24h}`,
        `Email: ${snap.users.byProvider.email ?? 0} · Google: ${snap.users.byProvider.google ?? 0}`,
      ].join('\n');
    case BUTTONS.devices:
      return [
        `<b>Devices</b>`,
        `PCs: ${snap.devices.desktops} (${snap.devices.desktopsOnline} online)`,
        `Phones: ${snap.devices.phones}`,
        `Desktop versions: ${Object.entries(snap.devices.desktopVersions).map(([v, n]) => `${escape(v)}×${n}`).join(', ') || '—'}`,
      ].join('\n');
    case BUTTONS.sessions:
      return [
        `<b>Sessions</b>: ${snap.sessions.total}`,
        `Working now: ${snap.sessions.working}`,
        `Projects: ${snap.projects.total}`,
        `Pending approvals: ${snap.approvals.pending}`,
        `Coding time (7 d): ${dur(Math.round(snap.work.last7dMs / 1000))}`,
      ].join('\n');
    case BUTTONS.errors: {
      const list = snap.health.recentErrors.slice(0, 8);
      if (!list.length) return '✅ No server errors since the last start.';
      return ['<b>Recent server errors</b>', ...list.map((e) => `${escape(e.at.slice(11, 19))} ${escape(e.method)} ${escape(e.path)} → ${e.status} ${escape(e.code)} <code>${escape(e.requestId)}</code>`)].join('\n');
    }
    case BUTTONS.signups: {
      const users = await recentUsers(8);
      if (!users.length) return 'No users yet.';
      return ['<b>New sign-ups</b>', ...users.map((u) => `${escape(u.createdAt.slice(0, 16).replace('T', ' '))} · ${escape(u.email ?? '(no email)')} · ${escape(u.provider ?? '')}`)].join('\n');
    }
    case BUTTONS.alerts:
      alertsOn = !alertsOn;
      return alertsOn ? '🔔 Alerts are on.' : '🔕 Alerts are off until you turn them on again (or the API restarts).';
    default:
      return 'Choose an option below.';
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
  const message = update?.message;
  const chatId = message?.chat?.id;
  if (!chatId || typeof message?.text !== 'string') return c.json({ ok: true });
  if (!adminChats.has(String(chatId))) {
    await call('sendMessage', {
      chat_id: chatId,
      text: `This bot is private. Your chat id is ${chatId}. If you run this BambooKit server, add it to TELEGRAM_ADMIN_CHAT_IDS.`,
    });
    return c.json({ ok: true });
  }
  const text = message.text.trim();
  const reply = text === '/start' || text === '/menu' ? `👋 BambooKit monitor. Tap a button below.` : await answer(text);
  await call('sendMessage', { chat_id: chatId, text: reply, parse_mode: 'HTML', disable_web_page_preview: true, reply_markup: keyboard });
  return c.json({ ok: true });
});

/** Registers the webhook with Telegram and announces the start. Called once at boot. */
export async function startTelegram(publicUrl: string | undefined) {
  if (!token) return;
  if (publicUrl) {
    const res = await call('setWebhook', { url: `${publicUrl.replace(/\/+$/, '')}/telegram/webhook`, secret_token: webhookSecret, allowed_updates: ['message'] });
    logger.info('Telegram bot', { webhook: res?.ok ? 'registered' : 'failed', adminChats: adminChats.size });
  } else {
    logger.info('Telegram bot: no public URL, webhook not registered');
  }
  onServerError((e) => {
    if (Date.now() - lastErrorAlert < 5 * 60_000) return;
    lastErrorAlert = Date.now();
    alert(`⚠️ <b>Server error</b>\n${escape(e.method)} ${escape(e.path)} → ${e.status} ${escape(e.code)}\n${escape(e.message.slice(0, 200))}\n<code>${escape(e.requestId)}</code>`);
  });
  alert(`🟢 <b>BambooKit API ${escape(VERSION)}</b> started${process.env.RENDER_GIT_COMMIT ? ` (${escape(process.env.RENDER_GIT_COMMIT.slice(0, 7))})` : ''}.`);
}
