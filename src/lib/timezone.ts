/**
 * Calendar helpers for one IANA time zone (the admin's, for the Telegram panel): local midnights as UTC
 * instants, local dates and short local times. Stored timestamps are ISO strings in UTC, so a window is
 * simply `created_at >= start AND created_at < end` with these instants.
 */
export function validZone(tz: string | null | undefined, fallback = 'UTC'): string {
  if (tz) {
    try {
      new Intl.DateTimeFormat('en-US', { timeZone: tz });
      return tz;
    } catch {}
  }
  return fallback;
}

const formatters = new Map<string, Intl.DateTimeFormat>();
function parts(d: Date, tz: string) {
  let f = formatters.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    formatters.set(tz, f);
  }
  const p = Object.fromEntries(f.formatToParts(d).map((x) => [x.type, x.value]));
  return { y: +p.year, m: +p.month, d: +p.day, h: +p.hour % 24, mi: +p.minute, s: +p.second };
}

/** Offset of local time from UTC at instant ms (local = utc + offset). */
function offsetAt(ms: number, tz: string) {
  const p = parts(new Date(ms), tz);
  return Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi, p.s) - Math.floor(ms / 1000) * 1000;
}

/** UTC instant of local midnight `days` days from the local day containing `at` (0 = today, -1 = yesterday). */
export function localMidnight(at: Date, tz: string, days = 0): Date {
  const p = parts(at, tz);
  const target = Date.UTC(p.y, p.m - 1, p.d + days);
  let t = target - offsetAt(target, tz);
  t = target - offsetAt(t, tz); // second pass settles DST transitions
  return new Date(t);
}

/** Local calendar date, e.g. '2026-10-05'. */
export function localDate(at: Date, tz: string): string {
  const p = parts(at, tz);
  return `${p.y}-${String(p.m).padStart(2, '0')}-${String(p.d).padStart(2, '0')}`;
}

/** Local hour and minute. */
export function localClock(at: Date, tz: string) {
  const p = parts(at, tz);
  return { hour: p.h, minute: p.mi };
}

const two = (n: number) => String(n).padStart(2, '0');
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** '14:05' in the zone. */
export function hhmm(at: Date | string, tz: string): string {
  const p = parts(typeof at === 'string' ? new Date(at) : at, tz);
  return `${two(p.h)}:${two(p.mi)}`;
}

/** '05 Oct 14:05' in the zone (year added when it is not the current year). */
export function shortDateTime(at: Date | string | null | undefined, tz: string): string {
  if (!at) return '—';
  const d = typeof at === 'string' ? new Date(at) : at;
  if (Number.isNaN(d.getTime())) return '—';
  const p = parts(d, tz);
  const year = parts(new Date(), tz).y === p.y ? '' : ` ${p.y}`;
  return `${two(p.d)} ${MONTHS[p.m - 1]}${year} ${two(p.h)}:${two(p.mi)}`;
}

/** Windows for one report: today, yesterday, last 7 / 30 local days (each including today), and the 7 days before. */
export function windows(at: Date, tz: string) {
  const iso = (d: Date) => d.toISOString();
  return {
    now: iso(at),
    today: iso(localMidnight(at, tz, 0)),
    yesterday: iso(localMidnight(at, tz, -1)),
    d7: iso(localMidnight(at, tz, -6)),
    prev7: iso(localMidnight(at, tz, -13)),
    d30: iso(localMidnight(at, tz, -29)),
    prev30: iso(localMidnight(at, tz, -59)),
    hour: iso(new Date(at.getTime() - 3600_000)),
    day: iso(new Date(at.getTime() - 86_400_000)),
  };
}
export type Windows = ReturnType<typeof windows>;
