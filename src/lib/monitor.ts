import { monitorEventLoopDelay } from 'node:perf_hooks';

/**
 * In-process service health for the admin panel and Telegram alerts: request and error counters since
 * start and the most recent server errors. Only safe fields are kept (route, status, code, request id) —
 * never bodies, headers, tokens or user content.
 */
export type RecentError = { at: string; method: string; path: string; status: number; code: string; message: string; requestId: string; client: string | null };

const startedAt = new Date();
let requests = 0;
let serverErrors = 0;
let clientErrors = 0;
const recent: RecentError[] = [];
const RECENT_MAX = 200;
/** Time and code of every server error in the last 24 hours (for per-hour counts, spikes and top codes). */
const timeline: Array<{ t: number; code: string }> = [];
const TIMELINE_MAX = 20_000;
const listeners = new Set<(e: RecentError) => void>();

const loopDelay = (() => {
  try {
    const h = monitorEventLoopDelay({ resolution: 20 });
    h.enable();
    return h;
  } catch {
    return null;
  }
})();

export function recordRequest(status: number) {
  requests++;
  if (status >= 500) serverErrors++;
  else if (status >= 400) clientErrors++;
}

function prune(now = Date.now()) {
  const cutoff = now - 86_400_000;
  while (timeline.length && (timeline[0].t < cutoff || timeline.length > TIMELINE_MAX)) timeline.shift();
}

export function recordServerError(e: RecentError) {
  recent.unshift(e);
  if (recent.length > RECENT_MAX) recent.pop();
  timeline.push({ t: Date.parse(e.at) || Date.now(), code: e.code });
  prune();
  for (const l of listeners) {
    try {
      l(e);
    } catch {}
  }
}

export function onServerError(listener: (e: RecentError) => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Server errors within the last `ms` milliseconds (at most 24 h is kept). */
export function serverErrorsSince(ms: number, now = Date.now()) {
  prune(now);
  const from = now - ms;
  let n = 0;
  for (let i = timeline.length - 1; i >= 0 && timeline[i].t >= from; i--) n++;
  return n;
}

/** Most frequent error codes in the last 24 hours. */
export function topErrorCodes(limit = 5) {
  prune();
  const counts = new Map<string, number>();
  for (const e of timeline) counts.set(e.code, (counts.get(e.code) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([code, count]) => ({ code, count }));
}

/** All kept recent errors, newest first (up to 200). */
export function recentErrors() {
  return recent.slice();
}

export function health() {
  const mem = process.memoryUsage();
  return {
    startedAt: startedAt.toISOString(),
    uptimeSeconds: Math.round((Date.now() - startedAt.getTime()) / 1000),
    requests,
    serverErrors,
    clientErrors,
    memoryMb: Math.round(mem.rss / 1024 / 1024),
    heapMb: Math.round(mem.heapUsed / 1024 / 1024),
    eventLoopLagMs: loopDelay && Number.isFinite(loopDelay.mean) ? Math.round((loopDelay.mean / 1e6) * 10) / 10 : null,
    eventLoopLagP99Ms: loopDelay && Number.isFinite(loopDelay.percentile(99)) ? Math.round(loopDelay.percentile(99) / 1e6) : null,
    recentErrors: recent.slice(0, 20),
  };
}
