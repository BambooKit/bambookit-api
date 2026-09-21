import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { authMiddleware } from '../../middleware/auth.js';
import { memoryDb } from '../../db/memoryDb.js';
import { encryptSecret, maskSecret } from '../../lib/crypto.js';

export const providersRouter = new Hono();

providersRouter.use('*', authMiddleware);

const updateProviderSchema = z.object({
  apiKey: z.string().optional(),
  defaultModel: z.string().optional(),
  baseUrl: z.string().optional(),
  enabled: z.boolean().optional(),
});

// GET /v1/providers
providersRouter.get('/', (c) => {
  const auth = c.get('auth');
  const providers = memoryDb.data.providers.filter((p) => p.workspaceId === auth.workspaceId);

  // Redact encryption keys before outputting
  const safeProviders = providers.map((p) => ({
    id: p.id,
    provider: p.provider,
    name: p.name,
    baseUrl: p.baseUrl,
    defaultModel: p.defaultModel,
    hasApiKey: !!p.encryptedApiKey,
    enabled: p.enabled,
    createdAt: p.createdAt,
    updatedAt: p.updatedAt,
  }));

  return c.json({ data: safeProviders, requestId: c.get('requestId') });
});

// PATCH /v1/providers/:id
providersRouter.patch('/:id', zValidator('json', updateProviderSchema), (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');
  const body = c.req.valid('json');

  const provider = memoryDb.data.providers.find((p) => p.id === id && p.workspaceId === auth.workspaceId);
  if (!provider) {
    return c.json({ error: { code: 'PROVIDER_NOT_FOUND', message: 'Provider configuration not found' } }, 404);
  }

  if (body.apiKey) {
    const encrypted = encryptSecret(body.apiKey);
    provider.encryptedApiKey = encrypted.ciphertext;
    provider.keyIv = encrypted.iv;
    provider.keyTag = encrypted.tag;
  }

  if (body.defaultModel) provider.defaultModel = body.defaultModel;
  if (body.baseUrl) provider.baseUrl = body.baseUrl;
  if (body.enabled !== undefined) provider.enabled = body.enabled;
  provider.updatedAt = new Date();

  return c.json({
    data: {
      id: provider.id,
      provider: provider.provider,
      name: provider.name,
      defaultModel: provider.defaultModel,
      hasApiKey: !!provider.encryptedApiKey,
      enabled: provider.enabled,
    },
    requestId: c.get('requestId'),
  });
});
