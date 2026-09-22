import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';
import { generateId } from '../../lib/crypto.js';

export const devicesRouter = new Hono();

devicesRouter.use('*', authMiddleware);

const registerDeviceSchema = z.object({
  name: z.string().min(2),
  type: z.enum(['WEB', 'WINDOWS_DESKTOP', 'ANDROID', 'CLI']),
  version: z.string(),
  publicKey: z.string().optional(),
});

// GET /v1/devices
devicesRouter.get('/', (c) => {
  const auth = c.get('auth');
  const devices = memoryDb.data.devices.filter((d) => d.workspaceId === auth.workspaceId);

  return c.json({ data: devices, requestId: c.get('requestId') });
});

// POST /v1/devices
devicesRouter.post('/', zValidator('json', registerDeviceSchema), (c) => {
  const auth = c.get('auth');
  const body = c.req.valid('json');

  const newDevice = {
    id: generateId('dev'),
    workspaceId: auth.workspaceId,
    userId: auth.userId,
    name: body.name,
    type: body.type,
    status: 'ONLINE' as const,
    version: body.version,
    publicKey: body.publicKey || null,
    lastSeenAt: new Date(),
    ipAddressMasked: '127.0.0.1',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  memoryDb.data.devices.unshift(newDevice);

  return c.json({ data: newDevice, requestId: c.get('requestId') }, 201);
});

// POST /v1/devices/:id/revoke
devicesRouter.post('/:id/revoke', (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');

  const index = memoryDb.data.devices.findIndex((d) => d.id === id && d.workspaceId === auth.workspaceId);
  if (index === -1) {
    return c.json({ error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found' } }, 404);
  }

  const [revoked] = memoryDb.data.devices.splice(index, 1);

  return c.json({ data: revoked, message: 'Device authorization revoked', requestId: c.get('requestId') });
});

// GET /v1/devices/:id/commands (Desktop polls remote commands)
devicesRouter.get('/:id/commands', (c) => {
  const deviceId = c.req.param('id');
  memoryDb.data.deviceCommands = memoryDb.data.deviceCommands || [];
  const pending = memoryDb.data.deviceCommands.filter((cmd) => cmd.deviceId === deviceId && cmd.status === 'QUEUED');

  return c.json({ data: pending, requestId: c.get('requestId') });
});

// POST /v1/devices/:id/commands/:cmdId/ack (Desktop acknowledges command execution)
devicesRouter.post('/:id/commands/:cmdId/ack', (c) => {
  const { id: deviceId, cmdId } = c.req.param();
  memoryDb.data.deviceCommands = memoryDb.data.deviceCommands || [];
  const cmd = memoryDb.data.deviceCommands.find((c) => c.id === cmdId && c.deviceId === deviceId);
  if (cmd) {
    cmd.status = 'COMPLETED';
    cmd.completedAt = new Date().toISOString();
  }

  return c.json({ success: true, requestId: c.get('requestId') });
});

