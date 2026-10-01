import { Hono } from 'hono';
import { streamSSE } from 'hono/streaming';
import { db } from '../db/database.js';
import { requireDevice, requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { currentSeq, eventsAfter, markConnected, markDisconnected, publish, subscribe, type BambooEvent } from '../realtime/bus.js';
import { serializeDevice } from './serializers.js';
import { expireStaleCommands } from './commands.js';

export const realtimeRouter = new Hono<AppEnv>();

const DESKTOP_EVENTS = new Set(['command.created', 'pairing.completed', 'device.revoked', 'device.unlinked', 'device.updated']);

/** Which events a stream receives. Desktops only get what they must act on. */
function visibleTo(device: DeviceRow | null, event: BambooEvent): boolean {
  if (!device || device.kind === 'mobile') return true;
  if (!DESKTOP_EVENTS.has(event.type)) return false;
  return event.deviceId === device.id || event.type === 'device.unlinked';
}

/**
 * GET /v1/realtime/stream?after=<seq>
 * Server-Sent Events. Each event's SSE id is its sequence number, so clients resume with
 * ?after=<last seq> (or Last-Event-ID) and replay anything they missed while disconnected.
 * Desktops identify with signed X-BK-Device-Id headers; their open stream defines "online".
 */
realtimeRouter.get(
  '/stream',
  requireUser,
  async (c, next) => (c.req.header('X-BK-Device-Id') ? requireDevice()(c, next) : next()),
  (c) => {
    const user = c.get('user');
    const device = c.get('device') ?? null;
    const afterParam = c.req.query('after') ?? c.req.header('Last-Event-ID');
    const after = afterParam !== undefined && afterParam !== '' ? Number(afterParam) : null;

    return streamSSE(c, async (stream) => {
      let lastSent = after ?? currentSeq(user.id);
      const queue: BambooEvent[] = [];
      let draining = false;
      let closed = false;

      const send = async (event: BambooEvent) => {
        if (event.seq <= lastSent) return;
        lastSent = event.seq;
        if (!visibleTo(device, event)) return;
        await stream.writeSSE({ id: String(event.seq), event: event.type, data: JSON.stringify(event) });
      };
      const drain = async () => {
        if (draining) return;
        draining = true;
        try {
          while (queue.length && !closed) await send(queue.shift()!);
        } catch {
          closed = true;
        } finally {
          draining = false;
        }
      };

      // Subscribe before replaying so nothing published during replay is lost.
      const unsubscribe = subscribe(user.id, (event) => {
        queue.push(event);
        void drain();
      });

      const isDesktop = device?.kind === 'desktop';
      if (isDesktop && markConnected(device.id)) {
        publish({ userId: user.id, deviceId: device.id, type: 'device.status', payload: serializeDevice(db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id) as unknown as DeviceRow) });
      }

      stream.onAbort(() => {
        closed = true;
        unsubscribe();
        if (isDesktop && markDisconnected(device.id)) {
          const row = db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id) as unknown as DeviceRow;
          publish({ userId: user.id, deviceId: device.id, type: 'device.status', payload: serializeDevice(row) });
        }
      });

      await stream.writeSSE({ event: 'ready', data: JSON.stringify({ seq: currentSeq(user.id), deviceId: device?.id ?? null }) });

      if (after !== null) {
        let batch: BambooEvent[];
        do {
          batch = eventsAfter(user.id, lastSent, 500);
          for (const e of batch) await send(e);
        } while (batch.length === 500 && !closed);
      }
      if (isDesktop) expireStaleCommands(device.id);
      await drain();

      while (!closed) {
        await stream.sleep(20_000);
        if (closed) break;
        try {
          await stream.writeSSE({ event: 'ping', data: String(Date.now()) });
        } catch {
          closed = true;
        }
      }
    });
  },
);
