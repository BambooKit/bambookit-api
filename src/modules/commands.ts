import { Hono } from 'hono';
import { z } from 'zod';
import { db, now } from '../db/database.js';
import { requireDevice, requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { HttpError, forbidden, newId, notFound } from '../lib/http.js';
import { emitEphemeral, isConnected, publish } from '../realtime/bus.js';
import { commandRow, COMMAND_SELECT, serializeCommand } from './serializers.js';
import { consumeDailyQuota } from './billing.js';

/** Commands older than this are never delivered — a stale remote action must not run hours later. */
export const COMMAND_TTL_MS = 5 * 60_000;
/** Finished command records (and their results) are deleted after this long. */
export const COMMAND_RETENTION_MS = 15 * 60_000;

export const commandPayloads = {
  SEND_MESSAGE: z.object({ text: z.string().min(1).max(20_000), model: z.object({ providerID: z.string().min(1).max(200), modelID: z.string().min(1).max(300) }).optional(), agent: z.string().min(1).max(100).optional() }),
  ABORT: z.object({}).strict(),
  CONTINUE: z.object({}).strict(),
  RETRY: z.object({}).strict(),
  GET_DIFF: z.object({ file: z.string().max(1000).optional() }),
  REFRESH: z.object({}).strict(),
  PERMISSION_REPLY: z.object({ requestId: z.string(), reply: z.enum(['once', 'always', 'reject']) }),
  // Answer or dismiss a question the agent asked (one list of chosen labels / typed text per question).
  QUESTION_REPLY: z.object({ requestId: z.string(), answers: z.array(z.array(z.string().max(2000)).max(50)).max(10) }),
  QUESTION_REJECT: z.object({ requestId: z.string() }),
  // Open the session in BambooKit on the PC; after that, phones may chat in it.
  CONTINUE_ON_PC: z.object({}).strict(),
  // Rename the session on the PC (the engine owns the title; the index updates on the next sync).
  RENAME_SESSION: z.object({ title: z.string().trim().min(1).max(200) }),
  CREATE_SESSION: z.object({ directory: z.string().min(1).max(1000), text: z.string().min(1).max(20_000), model: z.object({ providerID: z.string().min(1).max(200), modelID: z.string().min(1).max(300) }).optional(), agent: z.string().min(1).max(100).optional() }),
  // Provider API keys travel end-to-end encrypted to the PC's RSA key (RSA-OAEP-SHA256 wrapping an AES-256-GCM key);
  // this server only ever sees ciphertext and deletes it as soon as the PC answers.
  SET_PROVIDER_KEY: z.object({
    providerID: z.string().min(1).max(200),
    envelope: z.object({ alg: z.literal('RSA-OAEP-256+A256GCM'), key: z.string().min(16).max(2000), iv: z.string().min(8).max(100), data: z.string().min(8).max(20_000) }),
  }),
  REMOVE_PROVIDER_KEY: z.object({ providerID: z.string().min(1).max(200) }),
  // Rewind the conversation (and, where the engine has snapshots, the files) to before a message.
  REVERT: z.object({ messageId: z.string().min(1).max(200) }),
  UNREVERT: z.object({}).strict(),
  // Publish / unpublish the session through the BambooKit share service.
  SHARE: z.object({}).strict(),
  UNSHARE: z.object({}).strict(),
  // Read or edit a file inside the session's project folder (the desktop enforces the folder boundary).
  READ_FILE: z.object({ path: z.string().min(1).max(1000) }),
  WRITE_FILE: z.object({ path: z.string().min(1).max(1000), content: z.string().max(1_000_000), baseSha256: z.string().max(64).nullable() }),
} as const;

export type CommandType = keyof typeof commandPayloads;

/**
 * Queue a command for a desktop after all authorization checks.
 * - target desktop must belong to the user and not be revoked
 * - a mobile issuer must be paired (linked) with that desktop
 */
export async function createCommand(input: {
  userId: string;
  desktop: DeviceRow | undefined;
  sessionId: string | null;
  issuer: DeviceRow | null;
  type: CommandType;
  payload: unknown;
}) {
  const desktop = input.desktop;
  if (!desktop || desktop.user_id !== input.userId || desktop.kind !== 'desktop') throw notFound('Device');
  if (desktop.revoked_at) throw forbidden('Target desktop has been revoked', 'DEVICE_REVOKED');
  if (input.issuer?.kind === 'mobile') {
    const linked = await db.get('SELECT 1 AS ok FROM device_links WHERE desktop_id = ? AND mobile_id = ?', desktop.id, input.issuer.id);
    if (!linked) throw forbidden('This phone is not paired with that desktop', 'DEVICE_NOT_PAIRED');
  }
  const payload = commandPayloads[input.type].parse(input.payload ?? {});
  // Plan limits: chatting and starting sessions from a phone or the website count toward the daily
  // allowance (desktops do not). Approvals, answers, continue-on-PC, renames and keys are never limited.
  if (input.issuer?.kind !== 'desktop') {
    if (input.type === 'SEND_MESSAGE') await consumeDailyQuota(input.userId, 'messages');
    else if (input.type === 'CREATE_SESSION') await consumeDailyQuota(input.userId, 'sessions');
  }
  const id = newId('cmd');
  const ts = now();
  await db.run(
    `INSERT INTO commands (id, user_id, device_id, session_id, issued_by_device_id, type, payload, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)`,
    id,
    input.userId,
    desktop.id,
    input.sessionId,
    input.issuer?.id ?? null,
    input.type,
    JSON.stringify(payload),
    ts,
    ts,
  );
  const command = serializeCommand(await commandRow(id));
  const event = { userId: input.userId, deviceId: desktop.id, sessionId: input.sessionId, type: 'command.created', payload: command };
  // Encrypted provider keys are never written to the event log; an offline PC picks them up from its pending commands.
  if (input.type === 'SET_PROVIDER_KEY') emitEphemeral(event);
  else await publish(event);
  return { command, deviceOnline: isConnected(desktop.id) };
}

/** Optional issuer identification for user-initiated requests (phones send X-BK-Device-Id). */
export async function resolveIssuer(userId: string, deviceId: string | undefined): Promise<DeviceRow | null> {
  if (!deviceId) return null;
  const row = await db.get<DeviceRow>('SELECT * FROM devices WHERE id = ?', deviceId);
  if (!row || row.user_id !== userId) throw forbidden('Device not registered to this account', 'DEVICE_NOT_OWNED');
  if (row.revoked_at) throw forbidden('Device has been revoked', 'DEVICE_REVOKED');
  await db.run('UPDATE devices SET last_seen_at = ? WHERE id = ?', now(), row.id);
  return row;
}

export async function expireStaleCommands(deviceId: string) {
  const cutoff = new Date(Date.now() - COMMAND_TTL_MS).toISOString();
  const stale = await db.all("SELECT * FROM commands WHERE device_id = ? AND status = 'PENDING' AND created_at < ?", deviceId, cutoff);
  for (const row of stale) {
    await db.run("UPDATE commands SET status = 'FAILED', error = 'Expired before the desktop received it', updated_at = ? WHERE id = ?", now(), row.id);
    await publish({ userId: row.user_id, deviceId, sessionId: row.session_id, type: 'command.updated', payload: serializeCommand(await commandRow(row.id)) });
  }
}

export const commandsRouter = new Hono<AppEnv>();
commandsRouter.use('*', requireUser);

// GET /v1/commands/:id — the issuer polls/reads the result (e.g. a diff)
commandsRouter.get('/:id', async (c) => {
  const row = await db.get(`${COMMAND_SELECT} WHERE c.id = ? AND c.user_id = ?`, c.req.param('id'), c.get('user').id);
  if (!row) throw notFound('Command');
  return c.json({ data: serializeCommand(row) });
});

const resultSchema = z.object({
  status: z.enum(['SUCCEEDED', 'FAILED']),
  result: z.unknown().optional(),
  error: z.string().max(2000).optional(),
});

// POST /v1/commands/:id/result — the target desktop reports the outcome (signed)
commandsRouter.post('/:id/result', requireDevice('desktop'), async (c) => {
  const device = c.get('device')!;
  const body = resultSchema.parse(JSON.parse(await c.req.text()));
  const row = await db.get('SELECT * FROM commands WHERE id = ?', c.req.param('id'));
  if (!row || row.device_id !== device.id) throw notFound('Command');
  if (row.status !== 'PENDING') throw new HttpError(409, 'COMMAND_FINISHED', 'Command already has a result');

  const result = body.result === undefined ? null : JSON.stringify(body.result);
  if (result && result.length > 2_000_000) throw new HttpError(422, 'RESULT_TOO_LARGE', 'Command result too large');
  await db.run('UPDATE commands SET status = ?, result = ?, error = ?, updated_at = ? WHERE id = ?', body.status, result, body.error ?? null, now(), row.id);
  if (body.status === 'SUCCEEDED' && (row.type === 'SET_PROVIDER_KEY' || row.type === 'REMOVE_PROVIDER_KEY')) {
    await db.run('UPDATE users SET key_changes = COALESCE(key_changes, 0) + 1 WHERE id = ?', row.user_id);
  }
  // Session content belongs on the PC: drop message text and file contents from finished commands,
  // and delete command records (including results such as file reads) once they are no longer needed.
  if (['SEND_MESSAGE', 'WRITE_FILE', 'CREATE_SESSION', 'QUESTION_REPLY', 'SET_PROVIDER_KEY'].includes(row.type)) await db.run("UPDATE commands SET payload = '{}' WHERE id = ?", row.id);
  await db.run('DELETE FROM commands WHERE created_at < ?', new Date(Date.now() - COMMAND_RETENTION_MS).toISOString());

  if (['PERMISSION_REPLY', 'QUESTION_REPLY', 'QUESTION_REJECT'].includes(row.type) && body.status === 'FAILED') {
    // Let the user try again.
    await db.run(
      "UPDATE approvals SET status = 'PENDING' WHERE device_id = ? AND opencode_request_id = ? AND status = 'RESPONDING'",
      device.id,
      JSON.parse(row.payload).requestId,
    );
  }

  const command = serializeCommand(await commandRow(row.id));
  // Large results (diffs) are fetched on demand via GET /v1/commands/:id instead of broadcast.
  const { result: _omit, ...summary } = command;
  await publish({ userId: row.user_id, deviceId: device.id, sessionId: row.session_id, type: 'command.updated', payload: { ...summary, hasResult: command.result !== null } });
  return c.json({ data: command });
});
