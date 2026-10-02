import { Hono } from 'hono';
import { z } from 'zod';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { env } from '../config/env.js';
import { db, now, tx } from '../db/database.js';
import { HttpError, notFound, sha256 } from '../lib/http.js';
import { renderSharePage } from './share-page.js';

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
db.exec(`
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL,
  opencode_session_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS share_items (
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  type TEXT NOT NULL,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (share_id, key)
);
`);

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

function checkSecret(id: string, secret: unknown) {
  const row = db.prepare('SELECT secret_hash FROM shares WHERE id = ?').get(id) as { secret_hash: string } | undefined;
  if (!row) throw notFound('Share');
  const given = Buffer.from(sha256(String(secret ?? '')), 'hex');
  const expected = Buffer.from(row.secret_hash, 'hex');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new HttpError(403, 'FORBIDDEN', 'Invalid share secret');
}

export function shareItems(id: string): Array<{ type: string; data: any }> {
  return (db.prepare('SELECT type, data FROM share_items WHERE share_id = ? ORDER BY key').all(id) as any[]).map((r) => ({ type: r.type, data: JSON.parse(r.data) }));
}

export const sharesRouter = new Hono();

sharesRouter.post('/api/share', async (c) => {
  rateLimit(clientIp(c));
  const { sessionID } = z.object({ sessionID: z.string().min(1).max(200) }).parse(await c.req.json());
  const id = randomBytes(6).toString('base64url');
  const secret = randomBytes(32).toString('base64url');
  const ts = now();
  db.prepare('INSERT INTO shares (id, secret_hash, opencode_session_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)').run(id, sha256(secret), sessionID, ts, ts);
  return c.json({ id, secret, url: shareUrl(c, id) });
});

sharesRouter.post('/api/share/:id/sync', async (c) => {
  const raw = await c.req.text();
  if (raw.length > MAX_SYNC_BYTES) throw new HttpError(422, 'TOO_LARGE', 'Share update too large');
  const body = z.object({ secret: z.string(), data: z.array(itemSchema).max(5000) }).parse(JSON.parse(raw));
  const id = c.req.param('id');
  checkSecret(id, body.secret);
  tx(() => {
    const count = Number((db.prepare('SELECT COUNT(*) AS n FROM share_items WHERE share_id = ?').get(id) as any).n);
    if (count + body.data.length > MAX_ITEMS_PER_SHARE) throw new HttpError(422, 'TOO_LARGE', 'Share has too many items');
    const ts = now();
    const upsert = db.prepare(`INSERT INTO share_items (share_id, key, type, data, updated_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(share_id, key) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`);
    for (const item of body.data) upsert.run(id, keyOf(item), item.type, JSON.stringify(item.data ?? null), ts);
    db.prepare('UPDATE shares SET updated_at = ? WHERE id = ?').run(ts, id);
  });
  return c.json({});
});

sharesRouter.delete('/api/share/:id', async (c) => {
  const body = z.object({ secret: z.string() }).parse(await c.req.json().catch(() => ({})));
  const id = c.req.param('id');
  checkSecret(id, body.secret);
  tx(() => {
    db.prepare('DELETE FROM share_items WHERE share_id = ?').run(id);
    db.prepare('DELETE FROM shares WHERE id = ?').run(id);
  });
  return c.json({});
});

sharesRouter.get('/api/share/:id/data', (c) => {
  const id = c.req.param('id');
  if (!db.prepare('SELECT 1 FROM shares WHERE id = ?').get(id)) throw notFound('Share');
  c.header('Cache-Control', 'no-store');
  return c.json(shareItems(id));
});

sharesRouter.get('/share/:id', (c) => {
  const id = c.req.param('id');
  const share = db.prepare('SELECT * FROM shares WHERE id = ?').get(id) as any;
  if (!share) return c.html(renderSharePage(null, []), 404);
  c.header('Cache-Control', 'no-store');
  c.header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'");
  return c.html(renderSharePage(share, shareItems(id)));
});
