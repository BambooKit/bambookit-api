import { Hono } from 'hono';
import { z } from 'zod';
import { createPublicKey } from 'node:crypto';
import { db, now, tx } from '../db/database.js';
import { requireDevice, requireSignature, requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { badRequest, forbidden, notFound, stableId } from '../lib/http.js';
import { publish } from '../realtime/bus.js';
import { COMMAND_SELECT, serializeCommand, serializeDevice } from './serializers.js';
import { expireStaleCommands } from './commands.js';

export const devicesRouter = new Hono<AppEnv>();
devicesRouter.use('*', requireUser);

const registerSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('desktop'),
    name: z.string().min(1).max(100),
    platform: z.string().min(1).max(40),
    appVersion: z.string().max(40).optional(),
    publicKey: z.string().min(40).max(1000),
  }),
  z.object({
    kind: z.literal('mobile'),
    name: z.string().min(1).max(100),
    platform: z.string().min(1).max(40),
    appVersion: z.string().max(40).optional(),
    installationId: z.string().min(16).max(100),
    pushToken: z.string().max(4096).optional(),
  }),
]);

const getDevice = db.prepare('SELECT * FROM devices WHERE id = ?');

/**
 * POST /v1/devices/register
 * Desktop: must sign the request with the private key matching publicKey (proof of possession).
 * The device id is derived from (user, key) so the same PC gets one device per account.
 */
devicesRouter.post('/register', async (c) => {
  const user = c.get('user');
  const body = registerSchema.parse(await c.req.json());
  const ts = now();
  let id: string;

  if (body.kind === 'desktop') {
    try {
      const key = createPublicKey(body.publicKey);
      if (key.asymmetricKeyType !== 'ed25519') throw new Error();
    } catch {
      throw badRequest('publicKey must be an Ed25519 SPKI PEM', 'INVALID_PUBLIC_KEY');
    }
    await requireSignature(c, body.publicKey);
    id = stableId('dsk', user.id, body.publicKey);
  } else {
    id = stableId('mob', user.id, body.installationId);
  }

  const existing = getDevice.get(id) as unknown as DeviceRow | undefined;
  if (existing?.revoked_at) throw forbidden('This device was revoked. Reset the device identity to register again.', 'DEVICE_REVOKED');

  db.prepare(`
    INSERT INTO devices (id, user_id, kind, name, platform, app_version, public_key, push_token, last_seen_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET name = excluded.name, platform = excluded.platform,
      app_version = excluded.app_version, push_token = COALESCE(excluded.push_token, devices.push_token),
      last_seen_at = excluded.last_seen_at
  `).run(
    id,
    user.id,
    body.kind,
    body.name,
    body.platform,
    body.appVersion ?? null,
    body.kind === 'desktop' ? body.publicKey : null,
    body.kind === 'mobile' ? body.pushToken ?? null : null,
    ts,
    ts,
  );

  const device = getDevice.get(id) as unknown as DeviceRow;
  if (!existing) publish({ userId: user.id, deviceId: id, type: 'device.registered', payload: serializeDevice(device) });
  return c.json({ data: serializeDevice(device) }, existing ? 200 : 201);
});

// GET /v1/devices
devicesRouter.get('/', (c) => {
  const user = c.get('user');
  const rows = db
    .prepare('SELECT * FROM devices WHERE user_id = ? AND revoked_at IS NULL ORDER BY kind, created_at')
    .all(user.id) as unknown as DeviceRow[];
  return c.json({ data: rows.map(serializeDevice) });
});

function ownedDevice(userId: string, id: string): DeviceRow {
  const row = getDevice.get(id) as unknown as DeviceRow | undefined;
  if (!row || row.user_id !== userId) throw notFound('Device');
  return row;
}

// GET /v1/devices/:id
devicesRouter.get('/:id', (c) => {
  return c.json({ data: serializeDevice(ownedDevice(c.get('user').id, c.req.param('id'))) });
});

// PATCH /v1/devices/:id  { name?, pushToken? }
devicesRouter.patch('/:id', async (c) => {
  const user = c.get('user');
  const device = ownedDevice(user.id, c.req.param('id'));
  const body = z.object({ name: z.string().min(1).max(100).optional(), pushToken: z.string().max(4096).optional() }).parse(await c.req.json());
  db.prepare('UPDATE devices SET name = COALESCE(?, name), push_token = COALESCE(?, push_token) WHERE id = ?').run(
    body.name ?? null,
    body.pushToken ?? null,
    device.id,
  );
  const updated = getDevice.get(device.id) as unknown as DeviceRow;
  publish({ userId: user.id, deviceId: device.id, type: 'device.updated', payload: serializeDevice(updated) });
  return c.json({ data: serializeDevice(updated) });
});

// POST /v1/devices/:id/revoke — permanently revoke a device and remove its links
devicesRouter.post('/:id/revoke', (c) => {
  const user = c.get('user');
  const device = ownedDevice(user.id, c.req.param('id'));
  tx(() => {
    db.prepare('UPDATE devices SET revoked_at = ? WHERE id = ?').run(now(), device.id);
    db.prepare('DELETE FROM device_links WHERE desktop_id = ? OR mobile_id = ?').run(device.id, device.id);
    db.prepare("UPDATE commands SET status = 'FAILED', error = 'Device revoked', updated_at = ? WHERE device_id = ? AND status = 'PENDING'").run(now(), device.id);
  });
  publish({ userId: user.id, deviceId: device.id, type: 'device.revoked', payload: { id: device.id } });
  return c.json({ data: { id: device.id, revoked: true } });
});

// POST /v1/devices/:id/unlink { otherDeviceId } — disconnect a phone from a desktop
devicesRouter.post('/:id/unlink', async (c) => {
  const user = c.get('user');
  const device = ownedDevice(user.id, c.req.param('id'));
  const { otherDeviceId } = z.object({ otherDeviceId: z.string() }).parse(await c.req.json());
  ownedDevice(user.id, otherDeviceId);
  const result = db
    .prepare('DELETE FROM device_links WHERE (desktop_id = ? AND mobile_id = ?) OR (desktop_id = ? AND mobile_id = ?)')
    .run(device.id, otherDeviceId, otherDeviceId, device.id);
  if (result.changes === 0) throw notFound('Device link');
  publish({ userId: user.id, deviceId: device.id, type: 'device.unlinked', payload: { a: device.id, b: otherDeviceId } });
  return c.json({ data: { unlinked: true } });
});

// GET /v1/devices/:id/commands — pending commands for the calling desktop (signed)
devicesRouter.get('/:id/commands', requireDevice('desktop'), (c) => {
  const device = c.get('device')!;
  if (device.id !== c.req.param('id')) throw forbidden('Devices can only read their own commands');
  expireStaleCommands(device.id);
  const rows = db
    .prepare(`${COMMAND_SELECT} WHERE c.device_id = ? AND c.status = 'PENDING' ORDER BY c.created_at ASC LIMIT 100`)
    .all(device.id) as any[];
  return c.json({ data: rows.map(serializeCommand) });
});
