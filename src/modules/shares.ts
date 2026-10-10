import { Hono } from 'hono';
import { z } from 'zod';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { env } from '../config/env.js';
import { db, now } from '../db/database.js';
import { HttpError, notFound, sha256 } from '../lib/http.js';
import { renderSharePage } from './share-page.js';
import { requireUser, type AppEnv } from '../middleware/auth.js';

/**
 * Public session sharing ("Publish on web") for BambooKit Desktop.
 *
 * Implements the share protocol the OpenCode engine speaks when its `enterprise.url` points at this
 * API (BambooKit Desktop sets it), so shared sessions are stored here instead of a third-party service:
 *   POST   /api/share                {sessionID}               -> {id, secret, url}
 *   POST   /api/share/:id/sync       {secret, data: Item[]}    -> incremental upsert
 *   DELETE /api/share/:id            {secret}                  -> unpublish
 *   GET    /api/share/:id/data                                 -> Item[] (public)
 *   GET    /share/:id                                          -> HTML viewer (public)
 * Only the holder of the per-share secret (the publishing desktop) can change or delete a share.
 */
// Tables: shares, share_items (see db/database.ts).

const MAX_SYNC_BYTES = 4 * 1024 * 1024;
const MAX_ITEMS_PER_SHARE = 20_000;
const CREATE_LIMIT_PER_HOUR = 60;

const itemSchema = z.object({ type: z.enum(['session', 'message', 'part', 'session_diff', 'model']), data: z.any() });
type Item = { type: z.infer<typeof itemSchema>['type']; data?: any };

/** Mirrors the key function of the OpenCode share client so updates replace earlier versions. */
function keyOf(item: Item): string {
  switch (item.type) {
    case 'message':
      return `message/${item.data?.id}`;
    case 'part':
      return `part/${item.data?.messageID}/${item.data?.id}`;
    default:
      return item.type;
  }
}

const createdByIp = new Map<string, number[]>();
function rateLimit(ip: string) {
  const hourAgo = Date.now() - 3_600_000;
  const recent = (createdByIp.get(ip) ?? []).filter((t) => t > hourAgo);
  if (recent.length >= CREATE_LIMIT_PER_HOUR) throw new HttpError(429, 'RATE_LIMITED', 'Too many shares created; try again later');
  recent.push(Date.now());
  createdByIp.set(ip, recent);
  if (createdByIp.size > 10_000) createdByIp.clear();
}

function clientIp(c: any): string {
  return c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || c.env?.incoming?.socket?.remoteAddress || 'unknown';
}

function shareUrl(c: any, id: string) {
  const base = (env.PUBLIC_SHARE_BASE_URL || new URL(c.req.url).origin).replace(/\/+$/, '');
  return `${base}/share/${id}`;
}

async function checkSecret(id: string, secret: unknown) {
  const row = await db.get<{ secret_hash: string }>('SELECT secret_hash FROM shares WHERE id = ?', id);
  if (!row) throw notFound('Share');
  const given = Buffer.from(sha256(String(secret ?? '')), 'hex');
  const expected = Buffer.from(row.secret_hash, 'hex');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new HttpError(403, 'FORBIDDEN', 'Invalid share secret');
}

export async function shareItems(id: string): Promise<Array<{ type: string; data: any }>> {
  return (await db.all('SELECT type, data FROM share_items WHERE share_id = ? ORDER BY key', id)).map((r) => ({ type: r.type, data: JSON.parse(r.data) }));
}

export const sharesRouter = new Hono();

sharesRouter.post('/api/share', async (c) => {
  rateLimit(clientIp(c));
  const { sessionID } = z.object({ sessionID: z.string().min(1).max(200) }).parse(await c.req.json());
  const id = randomBytes(6).toString('base64url');
  const secret = randomBytes(32).toString('base64url');
  const ts = now();
  await db.run('INSERT INTO shares (id, secret_hash, opencode_session_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', id, sha256(secret), sessionID, ts, ts);
  return c.json({ id, secret, url: shareUrl(c, id) });
});

sharesRouter.post('/api/share/:id/sync', async (c) => {
  const raw = await c.req.text();
  if (raw.length > MAX_SYNC_BYTES) throw new HttpError(422, 'TOO_LARGE', 'Share update too large');
  const body = z.object({ secret: z.string(), data: z.array(itemSchema).max(5000) }).parse(JSON.parse(raw));
  const id = c.req.param('id');
  await checkSecret(id, body.secret);
  await db.tx(async (q) => {
    const count = Number((await q.get('SELECT COUNT(*) AS n FROM share_items WHERE share_id = ?', id))?.n ?? 0);
    if (count + body.data.length > MAX_ITEMS_PER_SHARE) throw new HttpError(422, 'TOO_LARGE', 'Share has too many items');
    const ts = now();
    const UPSERT = `INSERT INTO share_items (share_id, key, type, data, updated_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(share_id, key) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`;
    for (const item of body.data) await q.run(UPSERT, id, keyOf(item), item.type, JSON.stringify(item.data ?? null), ts);
    await q.run('UPDATE shares SET updated_at = ? WHERE id = ?', ts, id);
  });
  return c.json({});
});

sharesRouter.delete('/api/share/:id', async (c) => {
  const body = z.object({ secret: z.string() }).parse(await c.req.json().catch(() => ({})));
  const id = c.req.param('id');
  await checkSecret(id, body.secret);
  await db.tx(async (q) => {
    await q.run('DELETE FROM share_items WHERE share_id = ?', id);
    await q.run('DELETE FROM shares WHERE id = ?', id);
  });
  return c.json({});
});

sharesRouter.get('/api/share/:id/data', async (c) => {
  const id = c.req.param('id');
  if (!(await db.get('SELECT 1 AS ok FROM shares WHERE id = ?', id))) throw notFound('Share');
  c.header('Cache-Control', 'no-store');
  return c.json(await shareItems(id));
});

sharesRouter.get('/share/:id', async (c) => {
  const id = c.req.param('id');
  const share = await db.get('SELECT * FROM shares WHERE id = ?', id);
  if (!share) return c.html(renderSharePage(null, []), 404);
  c.header('Cache-Control', 'no-store');
  c.header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'");
  return c.html(renderSharePage(share, await shareItems(id)));
});

// ---------------- "Open in my BambooKit": clone a shared session into the opener's account ----------------

const IMPORT_CONTEXT_MAX = 8000;
const IMPORT_LIMIT_PER_MIN = 30;
const importByUser = new Map<string, number[]>();
function importRateLimit(userId: string) {
  const minuteAgo = Date.now() - 60_000;
  const recent = (importByUser.get(userId) ?? []).filter((t) => t > minuteAgo);
  if (recent.length >= IMPORT_LIMIT_PER_MIN) throw new HttpError(429, 'RATE_LIMITED', 'Too many import previews; try again shortly');
  recent.push(Date.now());
  importByUser.set(userId, recent);
  if (importByUser.size > 10_000) importByUser.clear();
}

const isText = (p: any) => p?.type === 'text' && !p?.synthetic && !p?.ignored && typeof p?.text === 'string' && p.text.trim();
const toolTitle = (p: any) => p?.state?.title || p?.state?.input?.command || p?.state?.input?.filePath || '';

/**
 * Builds a safe, compact seed for cloning a shared session: title, project name, model, prompt count, the
 * first user prompt, and a plain-text transcript of user prompts + assistant text + tool titles (NO raw file
 * contents or tool output), clamped to ~8000 chars. Shapes are fixed; three clients build against them.
 */
export function buildImportPreview(items: Array<{ type: string; data: any }>) {
  const session = items.find((i) => i.type === 'session')?.data ?? null;
  const messages = items.filter((i) => i.type === 'message').map((i) => i.data).sort((a, b) => (a?.time?.created ?? 0) - (b?.time?.created ?? 0));
  const partsByMessage = new Map<string, any[]>();
  for (const p of items.filter((i) => i.type === 'part').map((i) => i.data)) {
    partsByMessage.set(p.messageID, [...(partsByMessage.get(p.messageID) ?? []), p]);
  }
  const partsOf = (m: any) => (partsByMessage.get(m?.id) ?? []).slice().sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const userText = (m: any) => partsOf(m).filter(isText).map((p) => p.text.trim()).join('\n').trim();

  // Model: prefer an assistant message that names provider+model, else a 'model' item.
  let model: { providerID: string; modelID: string } | null = null;
  for (const m of messages) if (m?.role === 'assistant' && m.providerID && m.modelID) { model = { providerID: String(m.providerID), modelID: String(m.modelID) }; break; }
  if (!model) {
    const mi = items.find((i) => i.type === 'model')?.data;
    if (mi?.providerID && mi?.modelID) model = { providerID: String(mi.providerID), modelID: String(mi.modelID) };
  }

  const userMessages = messages.filter((m) => m?.role === 'user');
  let seedPrompt = '';
  for (const m of userMessages) { const t = userText(m); if (t) { seedPrompt = t; break; } }
  const promptCount = userMessages.filter((m) => userText(m)).length;

  const lines: string[] = [];
  for (const m of messages) {
    if (m?.role === 'user') {
      const t = userText(m);
      if (t) lines.push(`User: ${t}`);
    } else if (m?.role === 'assistant') {
      for (const p of partsOf(m)) {
        if (isText(p)) lines.push(`Assistant: ${p.text.trim()}`);
        else if (p?.type === 'tool') { const title = toolTitle(p); lines.push(`Assistant used ${p.tool || 'tool'}${title ? `: ${title}` : ''}`); }
      }
    }
  }
  const context = lines.join('\n').slice(0, IMPORT_CONTEXT_MAX);

  const title = String(session?.title || 'Shared session');
  const directory = String(session?.directory || '');
  const base = directory.replace(/[\\/]+$/, '').split(/[\\/]/).filter(Boolean).pop() || '';
  return { title, projectName: base || title, model, promptCount, seedPrompt: seedPrompt.slice(0, IMPORT_CONTEXT_MAX), context };
}

export const shareImportRouter = new Hono<AppEnv>();
shareImportRouter.use('*', requireUser);

// GET /v1/shares/:id/import-preview — a signed-in user reads a safe seed to clone a shared session into their
// own account (then creates it with the existing POST /v1/projects/:id/sessions). 404 if the share is gone.
shareImportRouter.get('/:id/import-preview', async (c) => {
  importRateLimit(c.get('user').id);
  const id = c.req.param('id');
  if (!(await db.get('SELECT 1 AS ok FROM shares WHERE id = ?', id))) throw notFound('Share');
  return c.json({ data: buildImportPreview(await shareItems(id)) });
});
