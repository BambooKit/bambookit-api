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

const INSERT_EVENT = `
  INSERT INTO events (id, user_id, device_id, project_id, session_id, type, payload, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq
`;
let publishedSincePrune = 0;

/**
 * Persist an event and fan it out to the user's live streams.
 * The sequence number lets clients resume with ?after=<seq> without losing events.
 */
export async function publish(input: {
  userId: string;
  type: string;
  payload: unknown;
  deviceId?: string | null;
  projectId?: string | null;
  sessionId?: string | null;
}): Promise<BambooEvent> {
  const id = newId('evt');
  const timestamp = now();
  const result = await db.get<{ seq: number }>(
    INSERT_EVENT,
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
    seq: Number(result!.seq),
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
    await db.run('DELETE FROM events WHERE created_at < ?', new Date(Date.now() - env.EVENT_RETENTION_DAYS * 86_400_000).toISOString());
  }
  return event;
}

export function subscribe(userId: string, listener: (event: BambooEvent) => void): () => void {
  emitter.on(`user:${userId}`, listener);
  return () => emitter.off(`user:${userId}`, listener);
}

export async function eventsAfter(userId: string, after: number, limit = 500): Promise<BambooEvent[]> {
  return (await db.all('SELECT * FROM events WHERE user_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?', userId, after, limit)).map(rowToEvent);
}

export async function currentSeq(userId: string): Promise<number> {
  return Number((await db.get('SELECT MAX(seq) AS seq FROM events WHERE user_id = ?', userId))?.seq ?? 0);
}

export function rowToEvent(row: any): BambooEvent {
  return {
    seq: Number(row.seq),
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

// Browser (BambooKit Web) streams have no device; count them per user.
const webConnections = new Map<string, number>();

export function webConnected(userId: string): boolean {
  const n = (webConnections.get(userId) ?? 0) + 1;
  webConnections.set(userId, n);
  return n === 1;
}

export function webDisconnected(userId: string): boolean {
  const n = (webConnections.get(userId) ?? 1) - 1;
  if (n <= 0) {
    webConnections.delete(userId);
    return true;
  }
  webConnections.set(userId, n);
  return false;
}

export function webCount(userId: string): number {
  return webConnections.get(userId) ?? 0;
}

/** Total live realtime streams for a user (all clients). */
export function streamCount(userId: string, deviceIds: string[]): number {
  return webCount(userId) + deviceIds.reduce((n, id) => n + (connections.get(id) ?? 0), 0);
}
