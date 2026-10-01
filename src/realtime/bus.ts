import { EventEmitter } from 'node:events';
import { db, now } from '../db/database.js';
import { env } from '../config/env.js';
import { newId } from '../lib/http.js';

export interface BambooEvent {
  seq: number;
  id: string;
  timestamp: string;
  userId: string;
  deviceId: string | null;
  projectId: string | null;
  sessionId: string | null;
  type: string;
  payload: unknown;
}

const emitter = new EventEmitter();
emitter.setMaxListeners(0);

const insert = db.prepare(`
  INSERT INTO events (id, user_id, device_id, project_id, session_id, type, payload, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);
const prune = db.prepare('DELETE FROM events WHERE created_at < ?');
let publishedSincePrune = 0;

/**
 * Persist an event and fan it out to the user's live streams.
 * The sequence number lets clients resume with ?after=<seq> without losing events.
 */
export function publish(input: {
  userId: string;
  type: string;
  payload: unknown;
  deviceId?: string | null;
  projectId?: string | null;
  sessionId?: string | null;
}): BambooEvent {
  const id = newId('evt');
  const timestamp = now();
  const result = insert.run(
    id,
    input.userId,
    input.deviceId ?? null,
    input.projectId ?? null,
    input.sessionId ?? null,
    input.type,
    JSON.stringify(input.payload ?? {}),
    timestamp,
  );
  const event: BambooEvent = {
    seq: Number(result.lastInsertRowid),
    id,
    timestamp,
    userId: input.userId,
    deviceId: input.deviceId ?? null,
    projectId: input.projectId ?? null,
    sessionId: input.sessionId ?? null,
    type: input.type,
    payload: input.payload ?? {},
  };
  emitter.emit(`user:${input.userId}`, event);

  if (++publishedSincePrune >= 500) {
    publishedSincePrune = 0;
    prune.run(new Date(Date.now() - env.EVENT_RETENTION_DAYS * 86_400_000).toISOString());
  }
  return event;
}

export function subscribe(userId: string, listener: (event: BambooEvent) => void): () => void {
  emitter.on(`user:${userId}`, listener);
  return () => emitter.off(`user:${userId}`, listener);
}

const listAfter = db.prepare('SELECT * FROM events WHERE user_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?');
const latestSeq = db.prepare('SELECT MAX(seq) AS seq FROM events WHERE user_id = ?');

export function eventsAfter(userId: string, after: number, limit = 500): BambooEvent[] {
  return (listAfter.all(userId, after, limit) as any[]).map(rowToEvent);
}

export function currentSeq(userId: string): number {
  return Number((latestSeq.get(userId) as any)?.seq ?? 0);
}

export function rowToEvent(row: any): BambooEvent {
  return {
    seq: row.seq,
    id: row.id,
    timestamp: row.created_at,
    userId: row.user_id,
    deviceId: row.device_id,
    projectId: row.project_id,
    sessionId: row.session_id,
    type: row.type,
    payload: JSON.parse(row.payload),
  };
}

// ---- Presence: desktops are online while they hold an open realtime stream. ----
const connections = new Map<string, number>();

export function markConnected(deviceId: string): boolean {
  const count = (connections.get(deviceId) ?? 0) + 1;
  connections.set(deviceId, count);
  return count === 1;
}

export function markDisconnected(deviceId: string): boolean {
  const count = (connections.get(deviceId) ?? 1) - 1;
  if (count <= 0) {
    connections.delete(deviceId);
    return true;
  }
  connections.set(deviceId, count);
  return false;
}

export function isConnected(deviceId: string): boolean {
  return (connections.get(deviceId) ?? 0) > 0;
}
