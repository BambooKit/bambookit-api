import { Hono } from 'hono';
import { z } from 'zod';
import { randomBytes } from 'node:crypto';
import { env } from '../config/env.js';
import { db, now, tx } from '../db/database.js';
import { requireDevice, requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { HttpError, forbidden, newId, sha256, stableId } from '../lib/http.js';
import { publish } from '../realtime/bus.js';
import { serializeDevice } from './serializers.js';

export const pairingRouter = new Hono<AppEnv>();
pairingRouter.use('*', requireUser);

/**
 * POST /v1/pairing/tokens  (signed desktop request)
 * Issues a short-lived, single-use pairing token for display as a QR code.
 * Only the SHA-256 of the token is stored. Any earlier unused token for this desktop is invalidated.
 */
pairingRouter.post('/tokens', requireDevice('desktop'), (c) => {
  const user = c.get('user');
  const desktop = c.get('device')!;
  const token = randomBytes(32).toString('base64url');
  const ts = now();
  const expiresAt = new Date(Date.now() + env.PAIRING_TOKEN_TTL_SECONDS * 1000).toISOString();

  tx(() => {
    db.prepare('UPDATE pairing_tokens SET used_at = ? WHERE desktop_id = ? AND used_at IS NULL').run(ts, desktop.id);
    db.prepare(
      'INSERT INTO pairing_tokens (id, token_hash, user_id, desktop_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    ).run(newId('pair'), sha256(token), user.id, desktop.id, expiresAt, ts);
  });

  return c.json(
    {
      data: {
        token,
        expiresAt,
        ttlSeconds: env.PAIRING_TOKEN_TTL_SECONDS,
        uri: `bambookit://pair?t=${token}`,
      },
    },
    201,
  );
});

const claimSchema = z.object({
  token: z.string().min(20).max(200),
  mobile: z.object({
    installationId: z.string().min(16).max(100),
    name: z.string().min(1).max(100),
    platform: z.string().min(1).max(40),
    appVersion: z.string().max(40).optional(),
    pushToken: z.string().max(4096).optional(),
  }),
});

/**
 * POST /v1/pairing/claim  (authenticated mobile user)
 * Validates the scanned token, binds the phone to the desktop, and invalidates the token.
 */
pairingRouter.post('/claim', async (c) => {
  const user = c.get('user');
  const body = claimSchema.parse(await c.req.json());
  const ts = now();

  const result = tx(() => {
    const row = db.prepare('SELECT * FROM pairing_tokens WHERE token_hash = ?').get(sha256(body.token)) as any;
    if (!row) throw new HttpError(404, 'PAIRING_TOKEN_INVALID', 'This QR code is not valid. Generate a new one on the desktop.');
    if (row.used_at) throw new HttpError(410, 'PAIRING_TOKEN_USED', 'This QR code was already used. Generate a new one on the desktop.');
    if (Date.parse(row.expires_at) < Date.now()) throw new HttpError(410, 'PAIRING_TOKEN_EXPIRED', 'This QR code has expired. Generate a new one on the desktop.');
    if (row.user_id !== user.id) {
      throw forbidden('This desktop is signed in to a different BambooKit account.', 'ACCOUNT_MISMATCH');
    }

    const desktop = db.prepare('SELECT * FROM devices WHERE id = ?').get(row.desktop_id) as unknown as DeviceRow;
    if (!desktop || desktop.revoked_at) throw forbidden('The desktop device has been revoked', 'DEVICE_REVOKED');

    const mobileId = stableId('mob', user.id, body.mobile.installationId);
    const existing = db.prepare('SELECT * FROM devices WHERE id = ?').get(mobileId) as unknown as DeviceRow | undefined;
    if (existing?.revoked_at) throw forbidden('This phone was revoked. Reinstall the app to pair again.', 'DEVICE_REVOKED');

    db.prepare(`
      INSERT INTO devices (id, user_id, kind, name, platform, app_version, push_token, last_seen_at, created_at)
      VALUES (?, ?, 'mobile', ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET name = excluded.name, platform = excluded.platform,
        app_version = excluded.app_version, push_token = COALESCE(excluded.push_token, devices.push_token),
        last_seen_at = excluded.last_seen_at
    `).run(mobileId, user.id, body.mobile.name, body.mobile.platform, body.mobile.appVersion ?? null, body.mobile.pushToken ?? null, ts, ts);

    // Single use: the WHERE clause guarantees only one concurrent claim can succeed.
    const consumed = db
      .prepare('UPDATE pairing_tokens SET used_at = ?, used_by_device_id = ? WHERE id = ? AND used_at IS NULL')
      .run(ts, mobileId, row.id);
    if (consumed.changes !== 1) throw new HttpError(410, 'PAIRING_TOKEN_USED', 'This QR code was already used.');

    db.prepare('INSERT OR IGNORE INTO device_links (desktop_id, mobile_id, user_id, created_at) VALUES (?, ?, ?, ?)').run(
      desktop.id,
      mobileId,
      user.id,
      ts,
    );

    return {
      desktop: db.prepare('SELECT * FROM devices WHERE id = ?').get(desktop.id) as unknown as DeviceRow,
      mobile: db.prepare('SELECT * FROM devices WHERE id = ?').get(mobileId) as unknown as DeviceRow,
    };
  });

  const payload = { desktop: serializeDevice(result.desktop), mobile: serializeDevice(result.mobile) };
  publish({ userId: user.id, deviceId: result.desktop.id, type: 'pairing.completed', payload });
  return c.json({ data: payload });
});
