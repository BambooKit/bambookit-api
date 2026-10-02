import { db, parseJson } from '../db/database.js';
import { isConnected } from '../realtime/bus.js';
import type { DeviceRow } from '../middleware/auth.js';

const LINKS_FOR_DEVICE = `
  SELECT d.id, d.name, d.kind, d.platform FROM device_links l
  JOIN devices d ON d.id = CASE WHEN l.desktop_id = ? THEN l.mobile_id ELSE l.desktop_id END
  WHERE (l.desktop_id = ? OR l.mobile_id = ?) AND d.revoked_at IS NULL
`;
const ACTIVE_SESSION_FOR_DEVICE = `
  SELECT s.id, s.title, s.status, p.name AS project_name FROM sessions s
  LEFT JOIN projects p ON p.id = s.project_id
  WHERE s.device_id = ? ORDER BY CASE WHEN s.status IN ('busy','retry') THEN 0 ELSE 1 END, s.updated_at DESC LIMIT 1
`;

export function isDeviceOnline(row: DeviceRow): boolean {
  if (row.revoked_at) return false;
  // A device is online while it holds a realtime stream; phones also count as online shortly after any request.
  if (isConnected(row.id)) return true;
  if (row.kind === 'desktop') return false;
  return !!row.last_seen_at && Date.now() - Date.parse(row.last_seen_at) < 120_000;
}

export async function serializeDevice(row: DeviceRow) {
  const links = await db.all(LINKS_FOR_DEVICE, row.id, row.id, row.id);
  const active = row.kind === 'desktop' ? await db.get(ACTIVE_SESSION_FOR_DEVICE, row.id) : undefined;
  return {
    id: row.id,
    kind: row.kind,
    name: row.name,
    platform: row.platform,
    appVersion: row.app_version,
    online: isDeviceOnline(row),
    lastSeenAt: row.last_seen_at,
    createdAt: row.created_at,
    revokedAt: row.revoked_at,
    linkedDevices: links.map((l) => ({ id: l.id, name: l.name, kind: l.kind, platform: l.platform })),
    activeSession: active
      ? { id: active.id, title: active.title, status: active.status, projectName: active.project_name }
      : null,
  };
}

export function serializeProject(row: any) {
  return {
    id: row.id,
    deviceId: row.device_id,
    deviceName: row.device_name ?? null,
    opencodeProjectId: row.opencode_project_id,
    name: row.name,
    directory: row.directory,
    branch: row.branch,
    activeSessions: Number(row.active_sessions ?? 0),
    totalSessions: Number(row.total_sessions ?? 0),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function serializeSession(row: any) {
  return {
    id: row.id,
    deviceId: row.device_id,
    projectId: row.project_id,
    projectName: row.project_name ?? null,
    opencodeSessionId: row.opencode_session_id,
    parentOpencodeSessionId: row.parent_opencode_session_id,
    directory: row.directory,
    title: row.title,
    status: row.status,
    statusMessage: row.status_message,
    agent: row.agent,
    model: row.model,
    currentAction: row.current_action,
    // Phones may chat in this session only after it was continued on the PC.
    remote: Boolean(Number(row.remote ?? 0)),
    changes: { additions: Number(row.additions), deletions: Number(row.deletions), files: Number(row.files) },
    pendingApprovals: Number(row.pending_approvals ?? 0),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function serializeApproval(row: any) {
  return {
    id: row.id,
    deviceId: row.device_id,
    sessionId: row.session_id,
    sessionTitle: row.session_title ?? null,
    projectName: row.project_name ?? null,
    opencodeRequestId: row.opencode_request_id,
    permission: row.permission,
    title: row.title,
    patterns: parseJson<string[]>(row.patterns, []),
    status: row.status,
    reply: row.reply,
    createdAt: row.created_at,
    resolvedAt: row.resolved_at,
  };
}

export function serializeCommand(row: any) {
  return {
    id: row.id,
    deviceId: row.device_id,
    sessionId: row.session_id,
    type: row.type,
    payload: parseJson(row.payload, {}),
    // Where the desktop should execute it. Present when the command targets a session.
    target: row.opencode_session_id ? { opencodeSessionId: row.opencode_session_id, directory: row.directory } : null,
    status: row.status,
    result: parseJson(row.result, null),
    error: row.error,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export const COMMAND_SELECT = `
  SELECT c.*, s.opencode_session_id, s.directory FROM commands c LEFT JOIN sessions s ON s.id = c.session_id`;

export function commandRow(id: string): Promise<any> {
  return db.get(`${COMMAND_SELECT} WHERE c.id = ?`, id);
}

export function serializeNotification(row: any) {
  return {
    id: row.id,
    type: row.type,
    title: row.title,
    body: row.body,
    data: parseJson(row.data, {}),
    readAt: row.read_at,
    createdAt: row.created_at,
  };
}
