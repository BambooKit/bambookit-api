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
const listeners = new Set<(e: RecentError) => void>();

export function recordRequest(status: number) {
  requests++;
  if (status >= 500) serverErrors++;
  else if (status >= 400) clientErrors++;
}

export function recordServerError(e: RecentError) {
  recent.unshift(e);
  if (recent.length > 50) recent.pop();
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

export function health() {
  const mem = process.memoryUsage();
  return {
    startedAt: startedAt.toISOString(),
    uptimeSeconds: Math.round((Date.now() - startedAt.getTime()) / 1000),
    requests,
    serverErrors,
    clientErrors,
    memoryMb: Math.round(mem.rss / 1024 / 1024),
    recentErrors: recent.slice(0, 20),
  };
}
