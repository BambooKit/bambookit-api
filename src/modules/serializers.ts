import { desktopCapabilities } from '../lib/compat.js';
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

export type PcSettings = { approvalMode: 'ask' | 'edits' | 'all'; keepAwake: boolean; allowRemoteControl: boolean };

/** Settings a PC reported (approval mode, keep awake, remote control), or null for desktops that never reported any. */
export function deviceSettings(row: { kind?: string; settings?: string | null }): PcSettings | null {
  if (row.kind !== 'desktop' || !row.settings) return null;
  const s = parseJson<Partial<PcSettings> | null>(row.settings, null);
  if (!s || typeof s !== 'object') return null;
  return {
    approvalMode: s.approvalMode === 'edits' || s.approvalMode === 'all' ? s.approvalMode : 'ask',
    keepAwake: s.keepAwake === true,
    // Remote terminal/power only ever run when the PC itself reports this true (turned on physically at the PC).
    allowRemoteControl: s.allowRemoteControl === true,
  };
}

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
    // Public half only: phones encrypt provider keys to it.
    encryptionKey: row.kind === 'desktop' ? (row.encryption_key ?? null) : null,
    protocol: row.kind === 'desktop' ? (row.protocol ?? 1) : null,
    capabilities: row.kind === 'desktop' ? [...desktopCapabilities(row)].sort() : null,
    // Desktops: { approvalMode: 'ask' | 'edits' | 'all', keepAwake } as last reported by the PC; null if never reported.
    settings: deviceSettings(row),
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
    status: row.status ?? 'active',
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
    starred: Boolean(Number(row.starred ?? 0)),
    changes: { additions: Number(row.additions), deletions: Number(row.deletions), files: Number(row.files) },
    pendingApprovals: Number(row.pending_approvals ?? 0),
    // The account that owns (and runs) this session. Collaborators see it on every session they can read.
    owner: { userId: row.user_id, email: row.owner_email ?? null, name: row.owner_name ?? null, avatar: row.owner_avatar ?? null },
    // The reading user's role: 'owner' for their own sessions, otherwise the collaborator role they were given.
    role: (row.my_role as 'owner' | 'chat' | 'viewer') ?? 'owner',
    collaboratorCount: Number(row.collaborator_count ?? 0),
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
    kind: row.kind === 'question' ? 'question' : 'permission',
    questions: row.questions ? parseJson<unknown[]>(row.questions, []) : null,
    answers: row.answers ? parseJson<string[][]>(row.answers, []) : null,
    createdAt: row.created_at,
    resolvedAt: row.resolved_at,
    // 'phone' | 'web' | 'pc' | 'auto' (approved by the PC's approval mode) | null (pending, expired or unknown).
    resolvedBy: row.status === 'PENDING' || row.status === 'RESPONDING' ? null : (row.resolved_by ?? null),
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
