import { Hono } from 'hono';
import { z } from 'zod';
import { createPublicKey } from 'node:crypto';
import { db, now } from '../db/database.js';
import { requireDevice, requireSignature, requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { HttpError, badRequest, forbidden, notFound, stableId } from '../lib/http.js';
import { emitEphemeral, publish } from '../realtime/bus.js';
import { COMMAND_SELECT, deviceSettings, serializeCommand, serializeDevice } from './serializers.js';
import { createCommand, expireStaleCommands, resolveIssuer } from './commands.js';
import { relay } from './relay.js';
import { requireCapability } from '../lib/compat.js';
import { assertDesktopAllowed } from './billing.js';

export const devicesRouter = new Hono<AppEnv>();
devicesRouter.use('*', requireUser);

const registerSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('desktop'),
    name: z.string().min(1).max(100),
    platform: z.string().min(1).max(40),
    appVersion: z.string().max(40).optional(),
    publicKey: z.string().min(40).max(1000),
    // RSA (≥ 2048-bit) SPKI PEM for end-to-end encrypted provider keys; the private key never leaves the PC.
    encryptionKey: z.string().min(200).max(4000).optional(),
    protocol: z.number().int().min(1).max(1000).optional(),
    capabilities: z.array(z.string().max(60)).max(100).optional(),
    // API 1.3: the PC's approval mode, keep-awake state and remote-control switch (missing fields keep what was
    // reported before). allowRemoteControl can only be turned on physically at the PC, so it is reported, never set remotely.
    settings: z.object({ approvalMode: z.enum(['ask', 'edits', 'all']), keepAwake: z.boolean(), allowRemoteControl: z.boolean() }).partial().optional(),
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

const getDevice = (id: string) => db.get<DeviceRow>('SELECT * FROM devices WHERE id = ?', id);

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

  if (body.kind === 'desktop' && body.encryptionKey) {
    let ok = false;
    try {
      const k = createPublicKey(body.encryptionKey);
      ok = k.asymmetricKeyType === 'rsa' && (k.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048;
    } catch {}
    if (!ok) throw badRequest('encryptionKey must be an RSA (2048-bit or larger) SPKI PEM', 'INVALID_ENCRYPTION_KEY');
  }

  const existing = await getDevice(id);
  if (existing?.revoked_at) throw forbidden('This device was revoked. Reset the device identity to register again.', 'DEVICE_REVOKED');
  // Plan PC limit for new devices only (re-registering an existing PC is never blocked).
  if (body.kind === 'desktop' && !existing) await assertDesktopAllowed(user.id);

  await db.run(
    `INSERT INTO devices (id, user_id, kind, name, platform, app_version, public_key, push_token, encryption_key, protocol, capabilities, last_seen_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET name = excluded.name, platform = excluded.platform,
       app_version = excluded.app_version, push_token = COALESCE(excluded.push_token, devices.push_token),
       encryption_key = COALESCE(excluded.encryption_key, devices.encryption_key),
       protocol = excluded.protocol, capabilities = excluded.capabilities,
       last_seen_at = excluded.last_seen_at`,
    id,
    user.id,
    body.kind,
    body.name,
    body.platform,
    body.appVersion ?? null,
    body.kind === 'desktop' ? body.publicKey : null,
    body.kind === 'mobile' ? body.pushToken ?? null : null,
    body.kind === 'desktop' ? body.encryptionKey ?? null : null,
    body.kind === 'desktop' ? body.protocol ?? null : null,
    body.kind === 'desktop' && body.capabilities ? JSON.stringify(body.capabilities) : null,
    ts,
    ts,
  );

  if (body.kind === 'desktop' && body.settings) {
    const before = existing ? deviceSettings(existing) : null;
    const settings = { ...(before ?? { approvalMode: 'ask', keepAwake: false, allowRemoteControl: false }), ...body.settings };
    await db.run('UPDATE devices SET settings = ? WHERE id = ?', JSON.stringify(settings), id);
    // Live only: phones and the website update the PC card (the device list carries the stored value).
    if (existing && JSON.stringify(before) !== JSON.stringify(settings)) {
      emitEphemeral({ userId: user.id, deviceId: id, type: 'device.updated', payload: { deviceId: id, settings } });
    }
  }

  const device = await serializeDevice((await getDevice(id))!);
  if (!existing) await publish({ userId: user.id, deviceId: id, type: 'device.registered', payload: device });
  return c.json({ data: device }, existing ? 200 : 201);
});

// GET /v1/devices
devicesRouter.get('/', async (c) => {
  const rows = await db.all<DeviceRow>('SELECT * FROM devices WHERE user_id = ? AND revoked_at IS NULL ORDER BY kind, created_at', c.get('user').id);
  return c.json({ data: await Promise.all(rows.map(serializeDevice)) });
});

async function ownedDevice(userId: string, id: string): Promise<DeviceRow> {
  const row = await getDevice(id);
  if (!row || row.user_id !== userId) throw notFound('Device');
  return row;
}

// GET /v1/devices/:id
devicesRouter.get('/:id', async (c) => {
  return c.json({ data: await serializeDevice(await ownedDevice(c.get('user').id, c.req.param('id'))) });
});

// PATCH /v1/devices/:id  { name?, pushToken? }
devicesRouter.patch('/:id', async (c) => {
  const user = c.get('user');
  const device = await ownedDevice(user.id, c.req.param('id'));
  const body = z.object({ name: z.string().min(1).max(100).optional(), pushToken: z.string().max(4096).optional() }).parse(await c.req.json());
  await db.run('UPDATE devices SET name = COALESCE(?, name), push_token = COALESCE(?, push_token) WHERE id = ?', body.name ?? null, body.pushToken ?? null, device.id);
  const updated = await serializeDevice((await getDevice(device.id))!);
  await publish({ userId: user.id, deviceId: device.id, type: 'device.updated', payload: updated });
  return c.json({ data: updated });
});

// POST /v1/devices/:id/revoke — permanently revoke a device and remove its links
devicesRouter.post('/:id/revoke', async (c) => {
  const user = c.get('user');
  const device = await ownedDevice(user.id, c.req.param('id'));
  await db.tx(async (q) => {
    await q.run('UPDATE devices SET revoked_at = ? WHERE id = ?', now(), device.id);
    await q.run('DELETE FROM device_links WHERE desktop_id = ? OR mobile_id = ?', device.id, device.id);
    await q.run("UPDATE commands SET status = 'FAILED', error = 'Device revoked', updated_at = ? WHERE device_id = ? AND status = 'PENDING'", now(), device.id);
  });
  await publish({ userId: user.id, deviceId: device.id, type: 'device.revoked', payload: { id: device.id } });
  return c.json({ data: { id: device.id, revoked: true } });
});

// POST /v1/devices/:id/unlink { otherDeviceId } — disconnect a phone from a desktop
devicesRouter.post('/:id/unlink', async (c) => {
  const user = c.get('user');
  const device = await ownedDevice(user.id, c.req.param('id'));
  const { otherDeviceId } = z.object({ otherDeviceId: z.string() }).parse(await c.req.json());
  await ownedDevice(user.id, otherDeviceId);
  const result = await db.run(
    'DELETE FROM device_links WHERE (desktop_id = ? AND mobile_id = ?) OR (desktop_id = ? AND mobile_id = ?)',
    device.id,
    otherDeviceId,
    otherDeviceId,
    device.id,
  );
  if (result.changes === 0) throw notFound('Device link');
  await publish({ userId: user.id, deviceId: device.id, type: 'device.unlinked', payload: { a: device.id, b: otherDeviceId } });
  return c.json({ data: { unlinked: true } });
});

// Commands about the PC itself rather than one session (provider keys, developer-tools relay).
const deviceCommandTypes = [
  'SET_PROVIDER_KEY', 'REMOVE_PROVIDER_KEY', 'SET_APPROVAL_MODE', 'SET_KEEP_AWAKE',
  'POWER', 'TERMINAL_OPEN', 'TERMINAL_INPUT', 'TERMINAL_RESIZE', 'TERMINAL_CLOSE',
] as const;

// Developer tools that remote-control the owner's own PC: gated by a capability AND by the PC's own switch.
const TERMINAL_COMMANDS = new Set(['TERMINAL_OPEN', 'TERMINAL_INPUT', 'TERMINAL_RESIZE', 'TERMINAL_CLOSE']);

// POST /v1/devices/:id/commands { type, payload } — from a paired phone or the website
devicesRouter.post('/:id/commands', async (c) => {
  const user = c.get('user');
  const desktop = await ownedDevice(user.id, c.req.param('id'));
  if (desktop.kind !== 'desktop') throw badRequest('Commands go to a PC');
  const body = z.object({ type: z.enum(deviceCommandTypes), payload: z.unknown().optional() }).parse(await c.req.json());
  // Never send encrypted credentials to a PC that cannot read them.
  if (body.type === 'SET_PROVIDER_KEY') requireCapability(desktop, 'providerKeys');
  if (body.type === 'SET_APPROVAL_MODE') requireCapability(desktop, 'approvalMode');
  if (body.type === 'SET_KEEP_AWAKE') requireCapability(desktop, 'keepAwake');
  // Power and terminal only reach a desktop new enough (426) that the owner has switched on for remote control (403).
  if (body.type === 'POWER') requireCapability(desktop, 'remotePower');
  if (TERMINAL_COMMANDS.has(body.type)) requireCapability(desktop, 'remoteTerminal');
  if (body.type === 'POWER' || TERMINAL_COMMANDS.has(body.type)) {
    if (deviceSettings(desktop)?.allowRemoteControl !== true) {
      throw new HttpError(403, 'REMOTE_CONTROL_DISABLED', `Turn on remote control on ${desktop.name} first.`, { device: desktop.name });
    }
  }
  // A per-session approval mode names one of this PC's sessions; the command then carries its target.
  let sessionId: string | null = null;
  if (body.type === 'SET_APPROVAL_MODE') {
    const named = (body.payload as any)?.sessionId;
    if (typeof named === 'string' && named) {
      const session = await db.get<{ id: string; device_id: string }>('SELECT id, device_id FROM sessions WHERE id = ? AND user_id = ?', named, user.id);
      if (!session) throw notFound('Session');
      if (session.device_id !== desktop.id) throw badRequest('That session is on another PC', 'SESSION_ON_OTHER_DEVICE');
      sessionId = session.id;
    }
  }
  const res = await createCommand({ userId: user.id, desktop, sessionId, issuer: await resolveIssuer(user.id, c.req.header('X-BK-Device-Id')), type: body.type, payload: body.payload ?? {} });
  return c.json({ data: res.command, deviceOnline: res.deviceOnline }, 202);
});

// GET /v1/devices/:id/providers — the PC's configured AI providers and models (relayed live; never includes keys)
devicesRouter.get('/:id/providers', async (c) => {
  const user = c.get('user');
  const desktop = await ownedDevice(user.id, c.req.param('id'));
  if (desktop.kind !== 'desktop') throw badRequest('Providers live on a PC');
  return c.json({ data: await relay(user.id, desktop, 'providers', {}) });
});

// GET /v1/devices/:id/commands — pending commands for the calling desktop (signed)
devicesRouter.get('/:id/commands', requireDevice('desktop'), async (c) => {
  const device = c.get('device')!;
  if (device.id !== c.req.param('id')) throw forbidden('Devices can only read their own commands');
  await expireStaleCommands(device.id);
  const rows = await db.all(`${COMMAND_SELECT} WHERE c.device_id = ? AND c.status = 'PENDING' ORDER BY c.created_at ASC LIMIT 100`, device.id);
  return c.json({ data: rows.map(serializeCommand) });
});

// POST /v1/devices/:id/terminal — the PC streams terminal output back to the owner's phone/web (signed).
// Ephemeral device → user channel 'terminal.data' (seq -1): never written to the events table and never logged.
devicesRouter.post('/:id/terminal', requireDevice('desktop'), async (c) => {
  const device = c.get('device')!;
  if (device.id !== c.req.param('id')) throw forbidden('Devices can only stream their own terminal');
  const { termId, data } = z.object({ termId: z.string().min(1).max(200), data: z.string().max(500_000) }).parse(JSON.parse(await c.req.text()));
  emitEphemeral({ userId: device.user_id, deviceId: device.id, type: 'terminal.data', payload: { termId, data } });
  return c.json({ data: { delivered: true } });
});
