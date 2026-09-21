import { Hono } from 'hono';
import { streamSSE } from 'hono/streaming';
import { authMiddleware } from '../middleware/auth.js';
import { realtimeHub, RealtimeEvent } from '../realtime/events.js';

export const realtimeRouter = new Hono();

realtimeRouter.use('*', authMiddleware);

// GET /v1/realtime/stream?channel=workspace:xyz
realtimeRouter.get('/stream', async (c) => {
  const auth = c.get('auth');
  const requestedChannel = c.req.query('channel') || `workspace:${auth.workspaceId}`;

  // Security check: ensure channel belongs to user's authorized workspace
  if (!requestedChannel.includes(auth.workspaceId) && !requestedChannel.startsWith('task:')) {
    return c.json({ error: { code: 'FORBIDDEN_CHANNEL', message: 'Unauthorized channel access' } }, 403);
  }

  return streamSSE(c, async (stream) => {
    // Send initial connected handshake
    await stream.writeSSE({
      event: 'connected',
      data: JSON.stringify({
        status: 'connected',
        channel: requestedChannel,
        userId: auth.userId,
        timestamp: new Date().toISOString(),
      }),
    });

    const listener = async (event: RealtimeEvent) => {
      try {
        await stream.writeSSE({
          event: event.type,
          data: JSON.stringify(event.data),
        });
      } catch {
        realtimeHub.off(requestedChannel, listener);
      }
    };

    realtimeHub.on(requestedChannel, listener);

    stream.onAbort(() => {
      realtimeHub.off(requestedChannel, listener);
    });

    // Keepalive ping loop
    while (true) {
      await stream.sleep(25000);
      try {
        await stream.writeSSE({ event: 'ping', data: 'heartbeat' });
      } catch {
        break;
      }
    }
  });
});
