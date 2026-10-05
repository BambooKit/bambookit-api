import { env } from '../config/env.js';
import { db } from '../db/database.js';
import { localDate, validZone } from './timezone.js';

/** The admin time zone (TELEGRAM_TIMEZONE, default Asia/Kolkata) used for admin day boundaries. */
export const adminTimeZone = () => validZone(env.TELEGRAM_TIMEZONE?.trim() || 'Asia/Kolkata', 'Asia/Kolkata');

/**
 * Records that a user was active on the current admin-zone day (one write per user per day per process),
 * so "DAU yesterday" stays exact even after the user is seen again today (users.last_seen_at only keeps
 * the latest visit).
 */
const recorded = new Map<string, string>();
export async function recordActiveDay(userId: string, at = new Date()) {
  const day = localDate(at, adminTimeZone());
  if (recorded.get(userId) === day) return;
  recorded.set(userId, day);
  if (recorded.size > 50_000) recorded.clear();
  await db.run('INSERT INTO user_active_days (user_id, day) VALUES (?, ?) ON CONFLICT (user_id, day) DO NOTHING', userId, day).catch(() => recorded.delete(userId));
}
