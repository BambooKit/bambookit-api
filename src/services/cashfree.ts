import { createHmac, timingSafeEqual } from 'node:crypto';
import { env } from '../config/env.js';
import { HttpError } from '../lib/http.js';
import { logger } from '../lib/logger.js';

/**
 * Cashfree Payment Gateway (PG Orders API).
 * - Credentials come from CASHFREE_APP_ID / CASHFREE_SECRET_KEY and are read on every call, so the
 *   feature switches on as soon as they are set. They are never logged or returned.
 * - CASHFREE_ENV picks sandbox or production. When unset it follows the App ID: Cashfree's test App IDs
 *   start with "TEST" (sandbox), every other App ID is a production key.
 * Docs: https://www.cashfree.com/docs/api-reference/payments/latest/orders/create
 */
export const CASHFREE_API_VERSION = '2023-08-01';

export function cashfreeConfig() {
  const appId = env.CASHFREE_APP_ID?.trim();
  const secret = env.CASHFREE_SECRET_KEY?.trim();
  if (!appId || !secret) return null;
  const environment = cashfreeEnvironment();
  return { appId, secret, environment, base: environment === 'production' ? 'https://api.cashfree.com' : 'https://sandbox.cashfree.com' };
}

/** The configured environment, or the one the App ID belongs to when CASHFREE_ENV is unset. */
export const cashfreeEnvironment = (): 'sandbox' | 'production' =>
  env.CASHFREE_ENV ?? (!env.CASHFREE_APP_ID?.trim() || /^TEST/i.test(env.CASHFREE_APP_ID.trim()) ? 'sandbox' : 'production');

/** A production App ID sent to the sandbox server (or the reverse) is the most common setup mistake. */
function keyMismatch(appId: string, environment: string) {
  const testKey = /^TEST/i.test(appId);
  if (testKey && environment === 'production') return 'The Cashfree App ID is a test (sandbox) key but CASHFREE_ENV is production.';
  if (!testKey && environment === 'sandbox') return 'The Cashfree App ID is a production key but CASHFREE_ENV is sandbox.';
  return null;
}

function requireConfig() {
  const cfg = cashfreeConfig();
  if (!cfg) throw new HttpError(503, 'PAYMENTS_NOT_CONFIGURED', 'Payments are not configured on this server yet.');
  return cfg;
}

async function request(method: 'GET' | 'POST', path: string, body?: unknown): Promise<any> {
  const cfg = requireConfig();
  let res: Response;
  try {
    res = await fetch(`${cfg.base}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'x-client-id': cfg.appId,
        'x-client-secret': cfg.secret,
        'x-api-version': CASHFREE_API_VERSION,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
  } catch (err: any) {
    logger.warn('cashfree request failed', { path: path.split('/').slice(0, 3).join('/'), error: String(err?.name ?? 'network') });
    throw new HttpError(502, 'PAYMENT_PROVIDER_ERROR', 'The payment provider could not be reached. Try again.');
  }
  const json: any = await res.json().catch(() => null);
  if (!res.ok) {
    // Cashfree errors carry { code, type, message } — safe to log (no credentials or session ids).
    logger.warn('cashfree request rejected', { status: res.status, code: String(json?.code ?? ''), type: String(json?.type ?? ''), message: String(json?.message ?? '').slice(0, 200) });
    const providerMessage = String(json?.message ?? '').slice(0, 300) || null;
    const hint =
      (res.status === 401 || res.status === 403 ? keyMismatch(cfg.appId, cfg.environment) : null) ??
      (res.status === 401 ? 'Cashfree did not accept the App ID and Secret Key. Check both on the server.' : null);
    throw new HttpError(502, 'PAYMENT_PROVIDER_ERROR', `The payment provider rejected the request${providerMessage ? `: ${providerMessage}` : '.'}`, {
      providerStatus: res.status,
      providerCode: json?.code ?? null,
      providerType: json?.type ?? null,
      providerMessage,
      environment: cfg.environment,
      hint,
    });
  }
  return json;
}

/** Cashfree allows only letters and digits in customer_id (3–50 characters). */
export function cashfreeCustomerId(userId: string): string {
  const clean = userId.replace(/[^A-Za-z0-9]/g, '').slice(0, 50);
  return clean.length >= 3 ? clean : `u${clean}`.padEnd(3, '0');
}

export interface CreatedOrder {
  cfOrderId: string | null;
  paymentSessionId: string;
  orderStatus: string;
}

export async function createCashfreeOrder(input: {
  orderId: string;
  amount: number;
  currency: 'INR';
  customerId: string;
  email: string | null;
  phone: string;
  returnUrl: string;
  notifyUrl: string | null;
  note: string;
}): Promise<CreatedOrder> {
  const json = await request('POST', '/pg/orders', {
    order_id: input.orderId,
    order_amount: input.amount,
    order_currency: input.currency,
    customer_details: {
      customer_id: input.customerId,
      customer_phone: input.phone,
      ...(input.email ? { customer_email: input.email } : {}),
    },
    order_meta: {
      return_url: input.returnUrl,
      ...(input.notifyUrl ? { notify_url: input.notifyUrl } : {}),
    },
    order_note: input.note,
  });
  if (!json?.payment_session_id) throw new HttpError(502, 'PAYMENT_PROVIDER_ERROR', 'The payment provider did not start a payment session.');
  return { cfOrderId: json.cf_order_id != null ? String(json.cf_order_id) : null, paymentSessionId: String(json.payment_session_id), orderStatus: String(json.order_status ?? 'ACTIVE') };
}

/** GET /pg/orders/{order_id} → order_status is ACTIVE, PAID, EXPIRED, TERMINATED or TERMINATION_REQUESTED. */
export async function getCashfreeOrder(orderId: string): Promise<{ orderStatus: string; orderAmount: number; cfOrderId: string | null }> {
  const json = await request('GET', `/pg/orders/${encodeURIComponent(orderId)}`);
  return { orderStatus: String(json?.order_status ?? ''), orderAmount: Number(json?.order_amount), cfOrderId: json?.cf_order_id != null ? String(json.cf_order_id) : null };
}

/** x-webhook-signature = base64(HMAC-SHA256(x-webhook-timestamp + rawBody, secret key)). */
export function verifyCashfreeSignature(rawBody: string, timestamp: string | undefined, signature: string | undefined): boolean {
  const cfg = cashfreeConfig();
  if (!cfg || !timestamp || !signature) return false;
  const expected = Buffer.from(createHmac('sha256', cfg.secret).update(timestamp + rawBody).digest('base64'));
  const given = Buffer.from(signature);
  return given.length === expected.length && timingSafeEqual(given, expected);
}
