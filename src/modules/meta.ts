import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv } from '../middleware/auth.js';
import { HttpError } from '../lib/http.js';
import { logger } from '../lib/logger.js';
import { env } from '../config/env.js';
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

/** Where each platform's releases are published: phones from the Android repo, every PC from the desktop repo. */
const REPOS = {
  android: 'BambooKit/bambookit-android',
  windows: 'BambooKit/bambookit-application',
  mac: 'BambooKit/bambookit-application',
  linux: 'BambooKit/bambookit-application',
} as const;
export type ReleasePlatform = keyof typeof REPOS;
export const RELEASE_PLATFORMS = Object.keys(REPOS) as ReleasePlatform[];

/** Installer files per platform, best first. */
const ASSETS: Record<ReleasePlatform, RegExp[]> = {
  android: [/\.apk$/i],
  windows: [/\.exe$/i, /\.msi$/i],
  // Apple silicon (arm64) first; a build without an architecture in its name is taken next.
  mac: [/(arm64|aarch64).*\.dmg$/i, /(arm64|aarch64).*\.zip$/i, /^(?!.*(x64|x86_64|intel)).*\.dmg$/i, /^(?!.*(x64|x86_64|intel|win|linux)).*(mac|darwin|osx).*\.zip$/i],
  linux: [/\.AppImage$/i, /\.deb$/i],
};
const SKIP = /blockmap|uninstaller|\.sig$|\.sha\d*$|latest.*\.ya?ml$/i;

const CACHE_MS = 10 * 60_000;
type Asset = { name: string; url: string; size: number };
type Release = {
  platform: ReleasePlatform;
  version: string;
  tag: string;
  name: string | null;
  publishedAt: string | null;
  notes: string;
  url: string;
  /** The preferred installer, or null when this release has none for the platform. */
  download: Asset | null;
  /** Every installer for the platform, best first (Linux: AppImage then deb). */
  downloads: Asset[];
  /** True when GitHub could not be reached and this is the last good answer. */
  stale: boolean;
};

/** Last good GitHub answer per repository (kept for good, so a GitHub outage serves it as stale). */
const lastGood = new Map<string, { at: number; json: any }>();
const inflight = new Map<string, Promise<any>>();

/** Tests: forget cached release answers. */
export function resetReleaseCache() {
  lastGood.clear();
  inflight.clear();
}

function toRelease(platform: ReleasePlatform, json: any, stale: boolean): Release {
  const assets = (Array.isArray(json.assets) ? json.assets : []).filter((a: any) => a?.name && a?.browser_download_url && !SKIP.test(String(a.name)));
  const downloads: Asset[] = [];
  for (const want of ASSETS[platform]) {
    for (const a of assets) {
      if (!want.test(String(a.name)) || downloads.some((d) => d.name === a.name)) continue;
      downloads.push({ name: String(a.name), url: String(a.browser_download_url), size: Number(a.size) || 0 });
    }
  }
  return {
    platform,
    version: String(json.tag_name ?? '').replace(/^v/i, ''),
    tag: String(json.tag_name ?? ''),
    name: json.name ?? null,
    publishedAt: json.published_at ?? null,
    notes: String(json.body ?? '').slice(0, 20_000),
    url: String(json.html_url ?? `https://github.com/${REPOS[platform]}/releases`),
    download: downloads[0] ?? null,
    downloads,
    stale,
  };
}

async function fetchLatest(repo: string): Promise<any> {
  const headers: Record<string, string> = { Accept: 'application/vnd.github+json', 'User-Agent': 'bambookit-api', 'X-GitHub-Api-Version': '2022-11-28' };
  if (env.GITHUB_TOKEN) headers.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  let res: Response;
  try {
    res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, { headers, signal: AbortSignal.timeout(10_000) });
  } catch (err: any) {
    throw new HttpError(503, 'UPDATE_SOURCE_UNAVAILABLE', 'The release server could not be reached. Try again later.', { source: 'github', reason: String(err?.name ?? 'network') });
  }
  if (res.status === 404) throw new HttpError(404, 'NO_RELEASE', 'No release has been published yet.');
  if (!res.ok) {
    logger.warn('release lookup failed', { repo, status: res.status, rateLimitRemaining: res.headers.get('x-ratelimit-remaining') });
    throw new HttpError(503, 'UPDATE_SOURCE_UNAVAILABLE', 'The release server did not answer. Try again later.', { source: 'github', status: res.status });
  }
  let json: any;
  try {
    json = await res.json();
  } catch {
    throw new HttpError(503, 'UPDATE_SOURCE_UNAVAILABLE', 'The release server sent an unreadable answer. Try again later.', { source: 'github' });
  }
  if (!String(json?.tag_name ?? '').replace(/^v/i, '')) throw new HttpError(502, 'INVALID_RELEASE', 'The latest release has no version tag.');
  return json;
}

/**
 * The latest release for a platform. GitHub answers are cached for 10 minutes; when GitHub fails (outage,
 * rate limit), the last good answer is served with `stale: true`. Only when nothing was ever fetched does
 * this answer 503 UPDATE_SOURCE_UNAVAILABLE (an expected outcome, not counted as a server error).
 */
export async function latestRelease(platform: ReleasePlatform): Promise<Release> {
  const repo = REPOS[platform];
  const hit = lastGood.get(repo);
  if (hit && Date.now() - hit.at < CACHE_MS) return toRelease(platform, hit.json, false);
  let pending = inflight.get(repo);
  if (!pending) {
    pending = fetchLatest(repo).finally(() => inflight.delete(repo));
    inflight.set(repo, pending);
  }
  try {
    const json = await pending;
    lastGood.set(repo, { at: Date.now(), json });
    return toRelease(platform, json, false);
  } catch (err) {
    if (err instanceof HttpError && err.code === 'NO_RELEASE') throw new HttpError(404, 'NO_RELEASE', `No ${platform} release has been published yet.`, { platform });
    if (hit) return toRelease(platform, hit.json, true);
    if (err instanceof HttpError) throw new HttpError(err.status, err.code, err.message, { ...(err.details as object | undefined), platform });
    throw err;
  }
}

// GET /v1/releases/latest?platform=android|windows|mac|linux
metaRouter.get('/releases/latest', async (c) => {
  const platform = z.enum(RELEASE_PLATFORMS as [ReleasePlatform, ...ReleasePlatform[]]).parse(c.req.query('platform'));
  return c.json({ data: await latestRelease(platform) });
});
