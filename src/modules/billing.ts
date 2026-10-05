import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { Hono } from 'hono';
import { z } from 'zod';
import { env } from '../config/env.js';
import { db, now, type Queryable } from '../db/database.js';
import { HttpError, newId, notFound } from '../lib/http.js';
import { logger } from '../lib/logger.js';
import { requireUser, type AppEnv } from '../middleware/auth.js';
import { emitEphemeral } from '../realtime/bus.js';
import { cashfreeConfig, cashfreeCustomerId, cashfreeEnvironment, createCashfreeOrder, getCashfreeOrder, verifyCashfreeSignature } from '../services/cashfree.js';
import { verifySsvQuery } from '../services/admob.js';
import { isAdmin } from './admin.js';

/**
 * Plans, limits, payments (Cashfree) and rewarded ads (AdMob SSV).
 *
 * - Free: 20 phone/web messages and 3 phone/web new sessions per day (the user's local day), 1 PC.
 * - Pro: unlimited messages and sessions, up to 5 PCs. Bought for 30/365 days, or 24 hours per
 *   rewarded ad (at most 2 a day). Admin accounts are always Pro.
 * - Pro time is stored on the user (pro_until, pro_source); every grant extends
 *   max(now, pro_until) and is idempotent (an order is paid once, an ad transaction counts once).
 */

export type PlanName = 'free' | 'pro';
export type PlanSource = 'payment' | 'reward' | 'admin';
export interface PlanLimits {
  phoneMessagesPerDay: number | null;
  phoneSessionsPerDay: number | null;
  desktops: number;
}

export const PLAN_LIMITS: Record<PlanName, PlanLimits> = {
  free: { phoneMessagesPerDay: 20, phoneSessionsPerDay: 3, desktops: 1 },
  pro: { phoneMessagesPerDay: null, phoneSessionsPerDay: null, desktops: 5 },
};

export const PRODUCTS = {
  'pro-month': { id: 'pro-month', name: 'BambooKit Pro (1 month)', amountPaise: 199_00, currency: 'INR', period: 'month', days: 30 },
  'pro-year': { id: 'pro-year', name: 'BambooKit Pro (1 year)', amountPaise: 1999_00, currency: 'INR', period: 'year', days: 365 },
} as const;
export type ProductId = keyof typeof PRODUCTS;

export const REWARD_HOURS = 24;
export const REWARDS_PER_DAY = 2;
const REWARD_TOKEN_SECONDS = 15 * 60;
export const UPGRADE_URL = 'https://bambookit-web.onrender.com/pricing/';
const DEFAULT_RETURN_URL = 'https://bambookit-web.onrender.com/billing/return/';
const DEFAULT_REWARDED_UNIT = 'ca-app-pub-2012618948788123/8440048550';
// Cashfree requires a customer phone number; BambooKit does not collect one, so a placeholder is sent
// unless a phone number is stored for the account. Cashfree's checkout still asks for a real one where needed.
const PLACEHOLDER_PHONE = '9999999999';

/**
 * The PC limit applies only to accounts created on or after this date; earlier accounts keep every PC
 * they register (grandfathered). Mutable only so tests can pin it.
 */
export const planPolicy = { desktopLimitSince: '2026-10-06T00:00:00Z' };

// ---------------------------------------------------------------- time zone days

function validZone(tz: string | null | undefined): string {
  if (tz) {
    try {
      new Intl.DateTimeFormat('en-US', { timeZone: tz });
      return tz;
    } catch {}
  }
  return 'UTC';
}

function localParts(d: Date, tz: string) {
  const p = Object.fromEntries(
    new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
      .formatToParts(d)
      .map((x) => [x.type, x.value]),
  );
  return { y: +p.year, m: +p.month, d: +p.day, h: +p.hour, mi: +p.minute, s: +p.second };
}

/** Calendar day in the zone, e.g. '2026-10-05'. */
export function localDay(d: Date, tz: string): string {
  const p = localParts(d, tz);
  return `${p.y}-${String(p.m).padStart(2, '0')}-${String(p.d).padStart(2, '0')}`;
}

const zoneOffset = (ms: number, tz: string) => {
  const p = localParts(new Date(ms), tz);
  return Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi, p.s) - Math.floor(ms / 1000) * 1000;
};

/** The next local midnight as an ISO instant. */
export function nextLocalMidnight(d: Date, tz: string): string {
  const p = localParts(d, tz);
  const target = Date.UTC(p.y, p.m - 1, p.d + 1);
  let t = target - zoneOffset(target, tz);
  t = target - zoneOffset(t, tz); // second pass settles DST transitions
  return new Date(t).toISOString();
}

// ---------------------------------------------------------------- entitlement

interface UserPlanRow {
  email: string | null;
  email_verified: number | null;
  timezone: string | null;
  created_at: string | null;
  pro_until: string | null;
  pro_source: string | null;
}

async function entitlement(userId: string, q: Queryable = db) {
  const row = await q.get<UserPlanRow>('SELECT email, email_verified, timezone, created_at, pro_until, pro_source FROM users WHERE id = ?', userId);
  const admin = !!row && isAdmin({ email: row.email, emailVerified: row.email_verified === null || row.email_verified === undefined ? null : !!Number(row.email_verified) });
  const active = !!row?.pro_until && Date.parse(row.pro_until) > Date.now();
  const plan: PlanName = admin || active ? 'pro' : 'free';
  const source: PlanSource | null = admin ? 'admin' : active ? ((row!.pro_source as PlanSource) ?? 'payment') : null;
  return { plan, source, admin, proUntil: active ? row!.pro_until : null, tz: validZone(row?.timezone), createdAt: row?.created_at ?? null, email: row?.email ?? null };
}

const count = async (sql: string, ...args: unknown[]) => Number((await db.get<{ n: number }>(sql, ...args))?.n ?? 0);
const activeDesktops = (userId: string) => count("SELECT COUNT(*) AS n FROM devices WHERE user_id = ? AND kind = 'desktop' AND revoked_at IS NULL", userId);
const usageOf = (userId: string, day: string, metric: UsageMetric) => count('SELECT used AS n FROM plan_usage WHERE user_id = ? AND day = ? AND metric = ?', userId, day, metric);

/** The account's plan, limits and today's usage (GET /v1/me/plan and 'plan.updated'). */
export async function getPlan(userId: string) {
  const ent = await entitlement(userId);
  const at = new Date();
  const day = localDay(at, ent.tz);
  return {
    plan: ent.plan,
    source: ent.source,
    proUntil: ent.proUntil,
    limits: PLAN_LIMITS[ent.plan],
    usage: {
      phoneMessagesToday: await usageOf(userId, day, 'messages'),
      phoneSessionsToday: await usageOf(userId, day, 'sessions'),
      desktops: await activeDesktops(userId),
    },
    resetsAt: nextLocalMidnight(at, ent.tz),
    ads: ent.plan === 'free',
    rewards: { todayCount: await count('SELECT COUNT(*) AS n FROM reward_grants WHERE user_id = ? AND day = ? AND granted = 1', userId, day), maxPerDay: REWARDS_PER_DAY, hours: REWARD_HOURS },
  };
}

/** Plan summary for GET /v1/me. */
export async function planSummary(userId: string) {
  const ent = await entitlement(userId);
  return { plan: ent.plan, proUntil: ent.proUntil };
}

async function planChanged(userId: string) {
  emitEphemeral({ userId, type: 'plan.updated', payload: await getPlan(userId) });
}

// ---------------------------------------------------------------- limits

type UsageMetric = 'messages' | 'sessions';
const METRIC_LIMIT = { messages: 'phoneMessagesPerDay', sessions: 'phoneSessionsPerDay' } as const;

/**
 * Counts one phone/web message or new session against today's allowance, atomically.
 * Throws 402 PLAN_LIMIT when the free allowance is used up. Command records are deleted after
 * minutes, so usage has its own per-day counter.
 */
export async function consumeDailyQuota(userId: string, metric: UsageMetric) {
  const ent = await entitlement(userId);
  const at = new Date();
  const day = localDay(at, ent.tz);
  const limitKey = METRIC_LIMIT[metric];
  const max = PLAN_LIMITS[ent.plan][limitKey];
  const created = await db.run('INSERT INTO plan_usage (user_id, day, metric, used) VALUES (?, ?, ?, 0) ON CONFLICT (user_id, day, metric) DO NOTHING', userId, day, metric);
  if (created.changes) await db.run('DELETE FROM plan_usage WHERE user_id = ? AND day < ?', userId, localDay(new Date(at.getTime() - 3 * 86_400_000), 'UTC'));
  if (max === null) {
    await db.run('UPDATE plan_usage SET used = used + 1 WHERE user_id = ? AND day = ? AND metric = ?', userId, day, metric);
    return;
  }
  const taken = await db.run('UPDATE plan_usage SET used = used + 1 WHERE user_id = ? AND day = ? AND metric = ? AND used < ?', userId, day, metric, max);
  if (taken.changes !== 1) {
    throw new HttpError(402, 'PLAN_LIMIT', 'Free plan limit reached for today.', {
      limit: limitKey,
      max,
      used: await usageOf(userId, day, metric),
      resetsAt: nextLocalMidnight(at, ent.tz),
      upgradeUrl: UPGRADE_URL,
    });
  }
}

/** Free accounts created after the cutoff may register one PC (Pro: 5). Re-registering is never blocked. */
export async function assertDesktopAllowed(userId: string) {
  const ent = await entitlement(userId);
  if (ent.admin) return;
  if (!ent.createdAt || Date.parse(ent.createdAt) < Date.parse(planPolicy.desktopLimitSince)) return;
  const max = PLAN_LIMITS[ent.plan].desktops;
  const used = await activeDesktops(userId);
  if (used >= max) {
    throw new HttpError(402, 'PLAN_LIMIT', ent.plan === 'free' ? 'The free plan includes one PC. Upgrade to Pro to add more.' : `Your plan includes up to ${max} PCs.`, {
      limit: 'desktops',
      max,
      used,
      resetsAt: null,
      upgradeUrl: UPGRADE_URL,
    });
  }
}

// ---------------------------------------------------------------- granting

/** Extends Pro by `ms` from max(now, current pro_until). Call inside a transaction. */
async function extendPro(q: Queryable, userId: string, ms: number, source: 'payment' | 'reward') {
  const row = await q.get<{ pro_until: string | null; pro_source: string | null }>('SELECT pro_until, pro_source FROM users WHERE id = ?', userId);
  const current = row?.pro_until ? Date.parse(row.pro_until) : 0;
  const active = current > Date.now();
  const until = new Date(Math.max(Date.now(), current) + ms).toISOString();
  // A paid subscription stays labelled as paid while it runs, even when an ad adds time.
  const nextSource = active && row?.pro_source === 'payment' ? 'payment' : source;
  await q.run('UPDATE users SET pro_until = ?, pro_source = ? WHERE id = ?', until, nextSource, userId);
  return until;
}

type PaymentListener = (p: { amount: number; currency: string; productId: string; productName: string; email: string | null; environment: string }) => void;
let onPayment: PaymentListener | null = null;
/** Set by the Telegram bot to announce successful payments. */
export function setPaymentListener(fn: PaymentListener | null) {
  onPayment = fn;
}

interface OrderRow {
  id: string;
  user_id: string;
  product_id: ProductId;
  amount_paise: number;
  currency: string;
  status: 'PENDING' | 'PAID' | 'FAILED' | 'EXPIRED';
  cf_order_id: string | null;
  payment_id: string | null;
  created_at: string;
  paid_at: string | null;
}

const getOrder = (id: string) => db.get<OrderRow>('SELECT * FROM billing_orders WHERE id = ?', id);
const paise = (amount: unknown) => Math.round(Number(amount) * 100);

/** Marks an order paid exactly once and grants its Pro time. Returns true when this call granted it. */
export async function grantOrder(orderId: string, paymentId: string | null): Promise<boolean> {
  const order = await getOrder(orderId);
  if (!order) return false;
  const product = PRODUCTS[order.product_id];
  if (!product) return false;
  const granted = await db.tx(async (q) => {
    const claimed = await q.run("UPDATE billing_orders SET status = 'PAID', paid_at = ?, payment_id = ? WHERE id = ? AND status <> 'PAID'", now(), paymentId, orderId);
    if (claimed.changes !== 1) return false;
    await extendPro(q, order.user_id, product.days * 86_400_000, 'payment');
    return true;
  });
  if (!granted) return false;
  logger.info('payment granted', { orderId, productId: product.id, userId: order.user_id });
  await planChanged(order.user_id);
  const email = (await db.get<{ email: string | null }>('SELECT email FROM users WHERE id = ?', order.user_id))?.email ?? null;
  onPayment?.({ amount: order.amount_paise / 100, currency: order.currency, productId: product.id, productName: product.name, email, environment: cashfreeEnvironment() });
  return true;
}

function serializeOrder(o: OrderRow) {
  return { id: o.id, status: o.status, productId: o.product_id, amount: Number(o.amount_paise) / 100, currency: o.currency, createdAt: o.created_at, paidAt: o.paid_at ?? null };
}

// ---------------------------------------------------------------- reward tokens

let ephemeralRewardKey: Buffer | null = null;
/**
 * HMAC key for rewarded-ad custom data: REWARD_SIGNING_SECRET, else derived from a server secret that
 * is already configured, else a random per-process key (tokens then last until the next restart).
 */
function rewardKey(): Buffer {
  const base = env.REWARD_SIGNING_SECRET?.trim() || env.SUPABASE_SERVICE_ROLE_KEY?.trim() || env.SUPABASE_JWT_SECRET?.trim() || env.CASHFREE_SECRET_KEY?.trim() || env.TELEGRAM_BOT_TOKEN?.trim();
  if (base) return createHash('sha256').update(`bambookit-reward-token:v1:${base}`).digest();
  if (!ephemeralRewardKey) {
    ephemeralRewardKey = randomBytes(32);
    logger.warn('REWARD_SIGNING_SECRET not set: using a per-process key for rewarded-ad tokens');
  }
  return ephemeralRewardKey;
}

const mac = (payload: string) => createHmac('sha256', rewardKey()).update(`reward:${payload}`).digest('base64url').slice(0, 22);

export function issueRewardToken(userId: string): string {
  const payload = Buffer.from(JSON.stringify({ u: userId, n: randomBytes(8).toString('base64url'), e: Math.floor(Date.now() / 1000) + REWARD_TOKEN_SECONDS })).toString('base64url');
  return `${payload}.${mac(payload)}`;
}

/** Returns the user id when the token is authentic and was valid at `at` (ms). */
export function readRewardToken(token: string, at: number): string | null {
  const [payload, sig, extra] = token.split('.');
  if (!payload || !sig || extra !== undefined) return null;
  const want = Buffer.from(mac(payload));
  const got = Buffer.from(sig);
  if (got.length !== want.length || !timingSafeEqual(got, want)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof data?.u !== 'string' || typeof data?.e !== 'number') return null;
    // The ad must have been rewarded while the token was valid; Google may retry the callback later.
    if (at > data.e * 1000 || Date.now() > data.e * 1000 + 24 * 3600_000) return null;
    return data.u;
  } catch {
    return null;
  }
}

async function grantReward(userId: string, transactionId: string, adNetwork: string | null): Promise<{ granted: boolean; reason?: string }> {
  const ent = await entitlement(userId);
  const day = localDay(new Date(), ent.tz);
  const result = await db.tx(async (q) => {
    const inserted = await q.run('INSERT INTO reward_grants (transaction_id, user_id, day, granted, ad_network, created_at) VALUES (?, ?, ?, 0, ?, ?) ON CONFLICT (transaction_id) DO NOTHING', transactionId, userId, day, adNetwork, now());
    if (inserted.changes !== 1) return { granted: false, reason: 'DUPLICATE' };
    const today = Number((await q.get<{ n: number }>('SELECT COUNT(*) AS n FROM reward_grants WHERE user_id = ? AND day = ? AND granted = 1', userId, day))?.n ?? 0);
    if (today >= REWARDS_PER_DAY) return { granted: false, reason: 'DAILY_LIMIT' };
    await q.run('UPDATE reward_grants SET granted = 1 WHERE transaction_id = ?', transactionId);
    await extendPro(q, userId, REWARD_HOURS * 3600_000, 'reward');
    return { granted: true };
  });
  if (result.granted) {
    logger.info('reward granted', { userId });
    await planChanged(userId);
  }
  return result;
}

// ---------------------------------------------------------------- admin

export async function billingSnapshot() {
  const since = (ms: number) => new Date(Date.now() - ms).toISOString();
  return {
    configured: !!cashfreeConfig(),
    environment: cashfreeEnvironment(),
    activePro: await count('SELECT COUNT(*) AS n FROM users WHERE pro_until > ?', now()),
    paidOrders30d: await count("SELECT COUNT(*) AS n FROM billing_orders WHERE status = 'PAID' AND paid_at >= ?", since(30 * 86_400_000)),
    revenue30d: (await count("SELECT COALESCE(SUM(amount_paise), 0) AS n FROM billing_orders WHERE status = 'PAID' AND paid_at >= ?", since(30 * 86_400_000))) / 100,
    rewards24h: await count('SELECT COUNT(*) AS n FROM reward_grants WHERE granted = 1 AND created_at >= ?', since(86_400_000)),
  };
}

// ---------------------------------------------------------------- routes

/** Mounted at /v1 before routers that require sign-in for every path (some routes here are public). */
export const billingRouter = new Hono<AppEnv>();

// GET /v1/billing/plans — public price list and limits
billingRouter.get('/billing/plans', (c) =>
  c.json({
    data: {
      products: Object.values(PRODUCTS).map((p) => ({ id: p.id, name: p.name, amount: p.amountPaise / 100, currency: p.currency, period: p.period, days: p.days })),
      limits: PLAN_LIMITS,
      payments: { configured: !!cashfreeConfig(), environment: cashfreeEnvironment() },
      rewards: { hours: REWARD_HOURS, maxPerDay: REWARDS_PER_DAY },
    },
  }),
);

// GET /v1/me/plan
billingRouter.get('/me/plan', requireUser, async (c) => c.json({ data: await getPlan(c.get('user').id) }));

const publicApiUrl = () => (process.env.PUBLIC_API_URL ?? process.env.RENDER_EXTERNAL_URL ?? '').replace(/\/+$/, '') || null;

// POST /v1/billing/checkout { productId } → Cashfree payment session for the web/Android checkout
billingRouter.post('/billing/checkout', requireUser, async (c) => {
  const user = c.get('user');
  const { productId } = z.object({ productId: z.enum(Object.keys(PRODUCTS) as [ProductId, ...ProductId[]]) }).parse(await c.req.json());
  if (!cashfreeConfig()) throw new HttpError(503, 'PAYMENTS_NOT_CONFIGURED', 'Payments are not configured on this server yet.');
  const product = PRODUCTS[productId];
  const orderId = newId('ord');
  const base = env.BILLING_RETURN_URL?.trim() || DEFAULT_RETURN_URL;
  const api = publicApiUrl();
  await db.run(
    "INSERT INTO billing_orders (id, user_id, product_id, amount_paise, currency, status, created_at) VALUES (?, ?, ?, ?, ?, 'PENDING', ?)",
    orderId,
    user.id,
    product.id,
    product.amountPaise,
    product.currency,
    now(),
  );
  let created;
  try {
    created = await createCashfreeOrder({
      orderId,
      amount: product.amountPaise / 100,
      currency: product.currency,
      customerId: cashfreeCustomerId(user.id),
      email: user.email,
      phone: PLACEHOLDER_PHONE,
      returnUrl: `${base}${base.includes('?') ? '&' : '?'}order_id={order_id}`,
      // Cashfree only calls https URLs; without a public URL, GET /v1/billing/orders/:id confirms payment.
      notifyUrl: api?.startsWith('https://') ? `${api}/v1/billing/cashfree/webhook` : null,
      note: product.name,
    });
  } catch (err) {
    await db.run('DELETE FROM billing_orders WHERE id = ?', orderId);
    throw err;
  }
  await db.run('UPDATE billing_orders SET cf_order_id = ? WHERE id = ?', created.cfOrderId, orderId);
  logger.info('checkout started', { orderId, productId: product.id, userId: user.id });
  return c.json({ data: { orderId, paymentSessionId: created.paymentSessionId, environment: cashfreeEnvironment(), amount: product.amountPaise / 100, currency: product.currency, productId: product.id } });
});

// GET /v1/billing/orders/:id — status of one of the caller's orders; confirms with Cashfree while pending
billingRouter.get('/billing/orders/:id', requireUser, async (c) => {
  const user = c.get('user');
  let order = await getOrder(c.req.param('id'));
  if (!order || order.user_id !== user.id) throw notFound('Order');
  if ((order.status === 'PENDING' || order.status === 'FAILED') && cashfreeConfig()) {
    try {
      const remote = await getCashfreeOrder(order.id);
      if (remote.orderStatus === 'PAID') {
        if (paise(remote.orderAmount) === Number(order.amount_paise)) await grantOrder(order.id, order.payment_id ?? null);
        else logger.warn('order amount mismatch', { orderId: order.id });
      } else if (remote.orderStatus === 'EXPIRED' || remote.orderStatus === 'TERMINATED') {
        await db.run("UPDATE billing_orders SET status = 'EXPIRED' WHERE id = ? AND status <> 'PAID'", order.id);
      }
      order = (await getOrder(order.id))!;
    } catch (err: any) {
      logger.warn('order status check failed', { orderId: order.id, code: err?.code ?? null });
    }
  }
  return c.json({ data: serializeOrder(order) });
});

// GET /v1/billing/history — the caller's orders, newest first
billingRouter.get('/billing/history', requireUser, async (c) => {
  const rows = await db.all<OrderRow>('SELECT * FROM billing_orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 100', c.get('user').id);
  return c.json({ data: rows.map(serializeOrder) });
});

// POST /v1/billing/cashfree/webhook — Cashfree payment notifications (signature over the raw body)
billingRouter.post('/billing/cashfree/webhook', async (c) => {
  const raw = await c.req.text();
  if (!verifyCashfreeSignature(raw, c.req.header('x-webhook-timestamp'), c.req.header('x-webhook-signature'))) {
    throw new HttpError(401, 'INVALID_SIGNATURE', 'Webhook signature is invalid.');
  }
  let event: any;
  try {
    event = JSON.parse(raw);
  } catch {
    return c.json({ ok: true });
  }
  const orderId = String(event?.data?.order?.order_id ?? '');
  const order = orderId ? await getOrder(orderId) : undefined;
  if (!order) return c.json({ ok: true, ignored: 'unknown order' });
  const payment = event?.data?.payment ?? {};
  const paymentId = payment.cf_payment_id != null ? String(payment.cf_payment_id) : null;

  if (event.type === 'PAYMENT_SUCCESS_WEBHOOK') {
    const amountOk = paise(event.data.order.order_amount) === Number(order.amount_paise);
    const currencyOk = !event.data.order.order_currency || event.data.order.order_currency === order.currency;
    if (payment.payment_status !== 'SUCCESS' || !amountOk || !currencyOk) {
      logger.warn('payment webhook not granted', { orderId: order.id, status: String(payment.payment_status ?? ''), amountOk, currencyOk });
      return c.json({ ok: true, granted: false });
    }
    const granted = await grantOrder(order.id, paymentId);
    return c.json({ ok: true, granted });
  }
  if (event.type === 'PAYMENT_FAILED_WEBHOOK' || event.type === 'PAYMENT_USER_DROPPED_WEBHOOK') {
    // The customer may still retry the same order; a later success replaces FAILED with PAID.
    await db.run("UPDATE billing_orders SET status = 'FAILED' WHERE id = ? AND status = 'PENDING'", order.id);
  }
  return c.json({ ok: true });
});

// POST /v1/rewards/token → custom data for the rewarded ad (setServerSideVerificationOptions)
billingRouter.post('/rewards/token', requireUser, (c) => {
  const user = c.get('user');
  return c.json({ data: { customData: issueRewardToken(user.id), userId: user.id } });
});

const rewardedUnitNumber = () => (env.ADMOB_REWARDED_UNIT?.trim() || DEFAULT_REWARDED_UNIT).split('/').pop()!;

// GET /v1/rewards/admob-ssv — AdMob server-side verification callback (called by Google)
billingRouter.get('/rewards/admob-ssv', async (c) => {
  const url = c.req.url;
  const raw = url.includes('?') ? url.slice(url.indexOf('?') + 1) : '';
  const params = await verifySsvQuery(raw);
  if (!params) throw new HttpError(400, 'INVALID_SIGNATURE', 'Reward callback signature is invalid.');
  const ignore = (reason: string) => c.json({ data: { granted: false, reason } });
  if ((params.get('ad_unit') ?? '').split('/').pop() !== rewardedUnitNumber()) return ignore('AD_UNIT');
  const transactionId = params.get('transaction_id');
  if (!transactionId || transactionId.length > 200) return ignore('TRANSACTION');
  const ts = Number(params.get('timestamp'));
  const userId = readRewardToken(params.get('custom_data') ?? '', Number.isFinite(ts) && ts > 0 ? ts : Date.now());
  if (!userId || !(await db.get('SELECT 1 AS ok FROM users WHERE id = ?', userId))) return ignore('CUSTOM_DATA');
  const result = await grantReward(userId, transactionId, params.get('ad_network'));
  return c.json({ data: result });
});
