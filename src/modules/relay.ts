import { Hono } from 'hono';
import { z } from 'zod';
import { requireDevice, requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { HttpError, newId } from '../lib/http.js';
import { emitEphemeral, isConnected } from '../realtime/bus.js';

/**
 * Live relay between a phone/browser and a PC. Session chats, diffs and files are stored only on
 * the PC: the API forwards a request over the PC's realtime stream and hands the PC's answer back
 * to the caller. Nothing passing through here is written to the database.
 */
export const RELAY_TIMEOUT_MS = 20_000;
/** Whole-project walks (diagram, folder tree) can take longer on large repositories. */
export const RELAY_SLOW_TIMEOUT_MS = 60_000;
const SLOW_KINDS = new Set<RelayKind>(['diagram', 'tree']);

type Pending = { userId: string; deviceId: string; resolve: (data: unknown) => void; reject: (err: Error) => void; timer: NodeJS.Timeout };
const pending = new Map<string, Pending>();

export type RelayKind = 'transcript' | 'changes' | 'filemap' | 'diagram' | 'tree' | 'file' | 'history' | 'fileversions';

export async function relay(userId: string, desktop: DeviceRow, kind: RelayKind, params: Record<string, unknown>): Promise<unknown> {
  if (!isConnected(desktop.id)) throw new HttpError(503, 'DESKTOP_OFFLINE', `${desktop.name} is offline. Session chats are stored on that PC; open BambooKit Desktop there to see them.`);
  const id = newId('rly');
  const result = new Promise<unknown>((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new HttpError(503, 'DESKTOP_TIMEOUT', `${desktop.name} did not answer in time. Try again.`));
    }, SLOW_KINDS.has(kind) ? RELAY_SLOW_TIMEOUT_MS : RELAY_TIMEOUT_MS);
    pending.set(id, { userId, deviceId: desktop.id, resolve, reject, timer });
  });
  emitEphemeral({ userId, deviceId: desktop.id, type: 'relay.request', payload: { id, kind, params } });
  return result;
}

export const relayRouter = new Hono<AppEnv>();
relayRouter.use('*', requireUser, requireDevice('desktop'));

// POST /v1/relay/:id/response { data } | { error }  (signed, from the PC that was asked)
relayRouter.post('/:id/response', async (c) => {
  const device = c.get('device')!;
  const entry = pending.get(c.req.param('id'));
  // Unknown or expired requests are ignored: the caller has already been told it timed out.
  if (!entry || entry.deviceId !== device.id || entry.userId !== c.get('user').id) return c.json({ data: { delivered: false } });
  const body = z.object({ data: z.unknown().optional(), error: z.string().max(1000).optional() }).parse(JSON.parse(await c.req.text()));
  pending.delete(c.req.param('id'));
  clearTimeout(entry.timer);
  if (body.error) entry.reject(new HttpError(422, 'DESKTOP_ERROR', body.error));
  else entry.resolve(body.data ?? null);
  return c.json({ data: { delivered: true } });
});
