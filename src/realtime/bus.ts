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

/**
 * Session-content events that are also fanned out to a session's linked collaborators, so a collaborator's
 * live stream receives updates for sessions they are on (not only the owner's stream). Live delivery only:
 * stored events are kept under the owner's user id, so a collaborator who reconnects with ?after=<seq>
 * replays only their own events — collaborators refetch session content from the PC (/parts, /history).
 */
const COLLAB_FANOUT_TYPES = new Set(['session.updated', 'session.part', 'session.transcript', 'session.diff', 'session.todos', 'session.removed', 'activity', 'session.message']);

async function collaboratorUserIds(sessionId: string): Promise<string[]> {
  try {
    const rows = await db.all<{ user_id: string }>('SELECT DISTINCT user_id FROM session_collaborators WHERE session_id = ? AND user_id IS NOT NULL', sessionId);
    return rows.map((r) => r.user_id);
  } catch {
    return [];
  }
}

/** Deliver a session-content event to every linked collaborator's live stream (never the owner, already emitted). */
async function fanOutToCollaborators(event: BambooEvent): Promise<void> {
  if (!event.sessionId || !COLLAB_FANOUT_TYPES.has(event.type)) return;
  for (const id of await collaboratorUserIds(event.sessionId)) {
    if (id !== event.userId) emitter.emit(`user:${id}`, event);
  }
}

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
  await fanOutToCollaborators(event);

  if (++publishedSincePrune >= 500) {
    publishedSincePrune = 0;
    await db.run('DELETE FROM events WHERE created_at < ?', new Date(Date.now() - env.EVENT_RETENTION_DAYS * 86_400_000).toISOString());
  }
  return event;
}

/**
 * Deliver an event to the user's open streams without storing it anywhere. Used for session
 * content (chat parts, diffs, live activity) and relay requests: that data lives on the PC, so
 * clients that are not connected simply fetch it from the PC later. Ephemeral events have seq -1.
 */
export function emitEphemeral(input: {
  userId: string;
  type: string;
  payload: unknown;
  deviceId?: string | null;
  projectId?: string | null;
  sessionId?: string | null;
}): BambooEvent {
  const event: BambooEvent = {
    seq: -1,
    id: newId('evt'),
    timestamp: now(),
    userId: input.userId,
    deviceId: input.deviceId ?? null,
    projectId: input.projectId ?? null,
    sessionId: input.sessionId ?? null,
    type: input.type,
    payload: input.payload ?? {},
  };
  emitter.emit(`user:${input.userId}`, event);
  // Live fan-out to collaborators happens on the next tick so emitEphemeral stays synchronous for its callers.
  void fanOutToCollaborators(event);
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

/** Open realtime streams across all users (admin monitoring). */
export function connectionTotals() {
  let devices = 0;
  for (const n of connections.values()) devices += n;
  let web = 0;
  for (const n of webConnections.values()) web += n;
  return { devices, web, connectedDeviceIds: [...connections.keys()] };
}
