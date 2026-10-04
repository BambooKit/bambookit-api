import { createMiddleware } from 'hono/factory';
import { verify as edVerify, createPublicKey } from 'node:crypto';
import { env } from '../config/env.js';
import { verifySupabaseToken, type AuthUser } from '../auth/supabase.js';
import { db, now } from '../db/database.js';
import { forbidden, sha256, unauthorized } from '../lib/http.js';

export interface DeviceRow {
  id: string;
  user_id: string;
  kind: 'desktop' | 'mobile';
  name: string;
  platform: string;
  app_version: string | null;
  public_key: string | null;
  encryption_key?: string | null;
  protocol?: number | null;
  capabilities?: string | null;
  push_token: string | null;
  last_seen_at: string | null;
  created_at: string;
  revoked_at: string | null;
}

export type AppEnv = {
  Variables: {
    requestId: string;
    user: AuthUser;
    device: DeviceRow | null;
  };
};

const UPSERT_USER = `
  INSERT INTO users (id, email, name, avatar_url, provider, email_verified, created_at, last_seen_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(id) DO UPDATE SET
    email = excluded.email,
    name = COALESCE(excluded.name, users.name),
    avatar_url = COALESCE(excluded.avatar_url, users.avatar_url),
    provider = excluded.provider,
    email_verified = COALESCE(excluded.email_verified, users.email_verified),
    last_seen_at = excluded.last_seen_at
`;

const lastUpsert = new Map<string, number>();

/** Requires a valid Supabase access token. Mirrors the user into the local users table. */
export const requireUser = createMiddleware<AppEnv>(async (c, next) => {
  const header = c.req.header('Authorization');
  const queryToken = c.req.query('access_token'); // only for clients that cannot set headers on SSE
  const token = header?.startsWith('Bearer ') ? header.slice(7) : queryToken;
  if (!token) throw unauthorized();

  const user = await verifySupabaseToken(token);
  const last = lastUpsert.get(user.id) ?? 0;
  if (Date.now() - last > 30_000) {
    const ts = now();
    const verified = user.emailVerified === null ? null : user.emailVerified ? 1 : 0;
    await db.run(UPSERT_USER, user.id, user.email, user.name, user.avatarUrl, user.provider, verified, ts, ts);
    lastUpsert.set(user.id, Date.now());
  }
  c.set('user', user);
  c.set('device', null);
  await next();
});



/** Builds the canonical string a device signs. Shared with clients (see bambookit-sdk). */
export function signingPayload(method: string, pathWithQuery: string, timestamp: string, body: string): string {
  return `${method.toUpperCase()}\n${pathWithQuery}\n${timestamp}\n${sha256(body)}`;
}

export function verifyDeviceSignature(publicKeyPem: string, payload: string, signatureB64: string): boolean {
  try {
    return edVerify(null, Buffer.from(payload), createPublicKey(publicKeyPem), Buffer.from(signatureB64, 'base64'));
  } catch {
    return false;
  }
}

/**
 * Resolves the calling device from X-BK-Device-Id and checks the user owns it.
 * Desktop devices must additionally sign every request with their Ed25519 key.
 * Use after requireUser.
 */
export function requireDevice(kind?: 'desktop' | 'mobile') {
  return createMiddleware<AppEnv>(async (c, next) => {
    const user = c.get('user');
    const deviceId = c.req.header('X-BK-Device-Id');
    if (!deviceId) throw unauthorized('Device identification required', 'DEVICE_REQUIRED');

    const device = await db.get<DeviceRow>('SELECT * FROM devices WHERE id = ?', deviceId);
    if (!device || device.user_id !== user.id) throw forbidden('Device not registered to this account', 'DEVICE_NOT_OWNED');
    if (device.revoked_at) throw forbidden('Device has been revoked', 'DEVICE_REVOKED');
    if (kind && device.kind !== kind) throw forbidden(`This operation requires a ${kind} device`, 'WRONG_DEVICE_KIND');

    if (device.kind === 'desktop') {
      if (!device.public_key) throw forbidden('Device has no public key', 'DEVICE_KEY_MISSING');
      await requireSignature(c, device.public_key);
    }

    await db.run('UPDATE devices SET last_seen_at = ? WHERE id = ?', now(), device.id);
    c.set('device', device);
    await next();
  });
}

/** Verifies X-BK-Timestamp / X-BK-Signature against the given public key. */
export async function requireSignature(c: any, publicKeyPem: string): Promise<void> {
  const timestamp = c.req.header('X-BK-Timestamp');
  const signature = c.req.header('X-BK-Signature');
  if (!timestamp || !signature) throw unauthorized('Device signature required', 'SIGNATURE_REQUIRED');

  const skew = Math.abs(Date.now() - Number(timestamp));
  if (!Number.isFinite(skew) || skew > env.DEVICE_SIGNATURE_MAX_SKEW_SECONDS * 1000) {
    throw unauthorized('Device signature timestamp out of range', 'SIGNATURE_EXPIRED');
  }

  const url = new URL(c.req.url);
  const body = ['GET', 'HEAD'].includes(c.req.method) ? '' : await c.req.text();
  const payload = signingPayload(c.req.method, url.pathname + url.search, timestamp, body);
  if (!verifyDeviceSignature(publicKeyPem, payload, signature)) {
    throw unauthorized('Invalid device signature', 'SIGNATURE_INVALID');
  }
}
