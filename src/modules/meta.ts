import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv } from '../middleware/auth.js';
import { HttpError } from '../lib/http.js';
import { logger } from '../lib/logger.js';
import { API_VERSION, PROTOCOL_VERSION, REQUIREMENTS } from '../lib/compat.js';

/**
 * Public, non-secret service information: API and protocol versions, what each desktop feature needs,
 * and the latest BambooKit releases (read from the GitHub Releases the apps update from).
 */
export const metaRouter = new Hono<AppEnv>();

metaRouter.get('/meta', (c) =>
  c.json({
    data: {
      service: 'bambookit-api',
      apiVersion: API_VERSION,
      protocol: PROTOCOL_VERSION,
      desktopRequirements: Object.fromEntries(Object.entries(REQUIREMENTS).map(([k, v]) => [k, { since: v.since, capability: v.capability, reason: v.reason }])),
    },
  }),
);

const REPOS = { android: 'BambooKit/bambookit-android', windows: 'BambooKit/bambookit-application' } as const;
const CACHE_MS = 10 * 60_000;
const cache = new Map<string, { at: number; data: unknown }>();

type Release = {
  platform: keyof typeof REPOS;
  version: string;
  tag: string;
  name: string | null;
  publishedAt: string | null;
  notes: string;
  url: string;
  download: { name: string; url: string; size: number } | null;
};

export async function latestRelease(platform: keyof typeof REPOS): Promise<Release> {
  const hit = cache.get(platform);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.data as Release;
  let res: Response;
  try {
    res = await fetch(`https://api.github.com/repos/${REPOS[platform]}/releases/latest`, {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'bambookit-api' },
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err: any) {
    if (hit) return hit.data as Release;
    throw new HttpError(503, 'UPDATE_SOURCE_UNAVAILABLE', 'The release server could not be reached. Try again later.', { source: 'github', reason: String(err?.name ?? 'network') });
  }
  if (res.status === 404) throw new HttpError(404, 'NO_RELEASE', `No ${platform} release has been published yet.`, { platform });
  if (!res.ok) {
    if (hit) return hit.data as Release;
    logger.warn('release lookup failed', { platform, status: res.status });
    throw new HttpError(503, 'UPDATE_SOURCE_UNAVAILABLE', 'The release server did not answer. Try again later.', { source: 'github', status: res.status });
  }
  const json: any = await res.json();
  const want = platform === 'android' ? /\.apk$/i : /\.exe$/i;
  const asset = (Array.isArray(json.assets) ? json.assets : []).find((a: any) => want.test(String(a?.name ?? '')) && !/blockmap|uninstaller/i.test(String(a?.name)));
  const data: Release = {
    platform,
    version: String(json.tag_name ?? '').replace(/^v/i, ''),
    tag: String(json.tag_name ?? ''),
    name: json.name ?? null,
    publishedAt: json.published_at ?? null,
    notes: String(json.body ?? '').slice(0, 20_000),
    url: String(json.html_url ?? `https://github.com/${REPOS[platform]}/releases`),
    download: asset ? { name: String(asset.name), url: String(asset.browser_download_url), size: Number(asset.size) || 0 } : null,
  };
  if (!data.version) throw new HttpError(502, 'INVALID_RELEASE', 'The latest release has no version tag.', { platform });
  cache.set(platform, { at: Date.now(), data });
  return data;
}

// GET /v1/releases/latest?platform=android|windows
metaRouter.get('/releases/latest', async (c) => {
  const platform = z.enum(['android', 'windows']).parse(c.req.query('platform'));
  return c.json({ data: await latestRelease(platform) });
});
