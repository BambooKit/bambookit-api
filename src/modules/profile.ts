import { Hono } from 'hono';
import { z } from 'zod';
import { env } from '../config/env.js';
import { db } from '../db/database.js';
import { HttpError, badRequest } from '../lib/http.js';
import { logger } from '../lib/logger.js';
import { requireUser, type AppEnv } from '../middleware/auth.js';
import { emitEphemeral } from '../realtime/bus.js';
import { SIGNED_URL_SECONDS, keys, storage } from '../services/storage.js';

/**
 * The signed-in user's profile, profile photo (Cloudflare R2) and account deletion.
 * Passwords never reach this API: email+password and Google sign-in are handled by Supabase Auth
 * and Firebase; this server only sees verified tokens.
 */
export const profileRouter = new Hono<AppEnv>();
profileRouter.use('*', requireUser);

const AVATAR_TYPES: Record<string, string> = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };
const AVATAR_MAX_BYTES = 2 * 1024 * 1024;

export function requireStorage() {
  if (!storage) throw new HttpError(503, 'STORAGE_NOT_CONFIGURED', 'Cloud storage is not configured on this server yet.');
  return storage;
}

const count = async (sql: string, ...args: unknown[]) => Number((await db.get(sql, ...args))?.n ?? 0);

// GET /v1/me — profile from the verified identity plus BambooKit's own records
profileRouter.get('/me', async (c) => {
  const user = c.get('user');
  const row = await db.get('SELECT * FROM users WHERE id = ?', user.id);
  const avatarUrl = row?.avatar_key && storage ? await storage.presignGet(row.avatar_key, 3600) : (row?.avatar_url ?? user.avatarUrl);
  return c.json({
    data: {
      id: user.id,
      email: user.email,
      name: row?.name ?? user.name,
      avatarUrl,
      avatarStored: !!row?.avatar_key,
      provider: user.provider,
      emailVerified: user.emailVerified,
      createdAt: row?.created_at ?? null,
      lastActiveAt: row?.last_seen_at ?? null,
      devices: await count('SELECT COUNT(*) AS n FROM devices WHERE user_id = ? AND revoked_at IS NULL', user.id),
      projects: await count('SELECT COUNT(*) AS n FROM projects WHERE user_id = ?', user.id),
      cloudStorage: !!storage,
      accountDeletion: user.provider === 'google' ? !!env.FIREBASE_API_KEY : !!env.SUPABASE_SERVICE_ROLE_KEY,
    },
  });
});

// POST /v1/me/avatar-upload { contentType, size } → short-lived signed PUT URL for a new profile photo
profileRouter.post('/me/avatar-upload', async (c) => {
  const store = requireStorage();
  const user = c.get('user');
  const { contentType, size } = z.object({ contentType: z.string(), size: z.number().int().positive() }).parse(await c.req.json());
  const ext = AVATAR_TYPES[contentType];
  if (!ext) throw badRequest('Profile photos must be JPEG, PNG or WebP', 'UNSUPPORTED_IMAGE');
  if (size > AVATAR_MAX_BYTES) throw badRequest('Profile photos must be 2 MB or smaller', 'IMAGE_TOO_LARGE');
  const key = keys.avatar(user.id, ext);
  return c.json({ data: { key, url: await store.presignPut(key, contentType, size, SIGNED_URL_SECONDS), method: 'PUT', headers: { 'Content-Type': contentType }, expiresIn: SIGNED_URL_SECONDS } });
});

// POST /v1/me/avatar { key } — use an uploaded photo (the key must be this user's)
profileRouter.post('/me/avatar', async (c) => {
  const store = requireStorage();
  const user = c.get('user');
  const { key } = z.object({ key: z.string().max(400) }).parse(await c.req.json());
  if (!key.startsWith(keys.avatarPrefix(user.id)) || key.includes('..')) throw new HttpError(403, 'FORBIDDEN', 'That photo does not belong to this account');
  const obj = await store.get(key);
  if (!obj) throw badRequest('Upload the photo first', 'AVATAR_NOT_UPLOADED');
  if (obj.body.length > AVATAR_MAX_BYTES) throw badRequest('Profile photos must be 2 MB or smaller', 'IMAGE_TOO_LARGE');
  const old = await db.get<{ avatar_key: string | null }>('SELECT avatar_key FROM users WHERE id = ?', user.id);
  await db.run('UPDATE users SET avatar_key = ? WHERE id = ?', key, user.id);
  const stale = (await store.list(keys.avatarPrefix(user.id))).map((o) => o.key).filter((k) => k !== key);
  if (stale.length) await store.deleteKeys(stale);
  if (old?.avatar_key && old.avatar_key !== key) logger.info('avatar replaced', { userId: user.id });
  return c.json({ data: { avatarUrl: await store.presignGet(key, 3600) } });
});

// DELETE /v1/me/avatar — back to the identity provider's photo (if any)
profileRouter.delete('/me/avatar', async (c) => {
  const user = c.get('user');
  if (storage) {
    const stale = (await storage.list(keys.avatarPrefix(user.id))).map((o) => o.key);
    if (stale.length) await storage.deleteKeys(stale);
  }
  await db.run('UPDATE users SET avatar_key = NULL WHERE id = ?', user.id);
  return c.json({ data: { removed: true } });
});

/**
 * DELETE /v1/me { confirm: "DELETE MY ACCOUNT" } — permanently deletes the account:
 * the sign-in identity (Supabase user, or the Firebase Google account using the caller's own token),
 * profile, devices and pairings, the session index, approvals, commands, events, notifications,
 * shared session links, and every object under users/{id}/ in R2.
 * Sessions and project files on the user's PCs are not touched.
 */
profileRouter.delete('/me', async (c) => {
  const user = c.get('user');
  z.object({ confirm: z.literal('DELETE MY ACCOUNT') }).parse(await c.req.json().catch(() => ({})));
  const token = c.req.header('Authorization')!.slice(7);

  // Check that the identity can be deleted before removing anything.
  if (user.provider === 'google' && !env.FIREBASE_API_KEY) throw new HttpError(503, 'DELETION_NOT_CONFIGURED', 'Account deletion is not configured on this server (FIREBASE_API_KEY).');
  if (user.provider !== 'google' && !env.SUPABASE_SERVICE_ROLE_KEY) throw new HttpError(503, 'DELETION_NOT_CONFIGURED', 'Account deletion is not configured on this server (SUPABASE_SERVICE_ROLE_KEY).');

  // Data first, then the sign-in identity: if the identity step fails the user can still sign in and retry.
  if (storage) {
    const objects = (await storage.list(keys.userPrefix(user.id))).map((o) => o.key);
    if (objects.length) await storage.deleteKeys(objects);
  }
  await db.tx(async (q) => {
    const sessions = await q.all<{ id: string; opencode_session_id: string }>('SELECT id, opencode_session_id FROM sessions WHERE user_id = ?', user.id);
    for (const s of sessions) {
      await q.run('DELETE FROM share_items WHERE share_id IN (SELECT id FROM shares WHERE opencode_session_id = ?)', s.opencode_session_id);
      await q.run('DELETE FROM shares WHERE opencode_session_id = ?', s.opencode_session_id);
      await q.run('DELETE FROM session_parts WHERE session_id = ?', s.id);
      await q.run('DELETE FROM session_diffs WHERE session_id = ?', s.id);
    }
    for (const table of ['commands', 'approvals', 'sessions', 'projects', 'pairing_tokens', 'device_links', 'device_state', 'notifications', 'events']) {
      await q.run(`DELETE FROM ${table} WHERE user_id = ?`, user.id);
    }
    await q.run('DELETE FROM devices WHERE user_id = ?', user.id);
    await q.run('DELETE FROM users WHERE id = ?', user.id);
  });
  await deleteIdentity(user.provider, user.id, token);
  // Connected PCs and phones learn immediately that the account is gone.
  emitEphemeral({ userId: user.id, type: 'account.deleted', payload: {} });
  logger.info('account deleted', { userId: user.id, provider: user.provider });
  return c.json({ data: { deleted: true } });
});

async function deleteIdentity(provider: string, userId: string, token: string) {
  if (provider === 'google') {
    // Firebase deletes the account for the holder of a valid ID token (the user's own session).
    const res = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:delete?key=${encodeURIComponent(env.FIREBASE_API_KEY!)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken: token }),
    });
    if (!res.ok) throw new HttpError(409, 'IDENTITY_DELETE_FAILED', 'Google sign-in account could not be deleted. Sign in again and retry.');
    return;
  }
  const res = await fetch(`${env.SUPABASE_URL.replace(/\/+$/, '')}/auth/v1/admin/users/${encodeURIComponent(userId)}`, {
    method: 'DELETE',
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY!, Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}` },
  });
  if (!res.ok && res.status !== 404) throw new HttpError(409, 'IDENTITY_DELETE_FAILED', 'The sign-in account could not be deleted. Try again later.');
}
