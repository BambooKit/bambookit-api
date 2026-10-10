import { db } from '../db/database.js';
import { forbidden, notFound } from '../lib/http.js';
import { emitEphemeral } from '../realtime/bus.js';
import { storage } from '../services/storage.js';

/**
 * Session collaborators: the owner invites specific BambooKit accounts to one session. Collaborators
 * view it live and (role 'chat') send messages into it; it still runs on the OWNER's PC. This is
 * invite-only and separate from the public read-only share link.
 *
 * Authorization is centralized in assertSessionAccess: every route that used to check "this session
 * belongs to the requesting user" uses it, so a linked collaborator is allowed READ (and, for role
 * 'chat', SEND_MESSAGE) while everything else stays owner-only.
 */

/** Session row plus owner identity, pending-approval count and collaborator count. */
export const SESSION_SELECT = `
  SELECT s.*, p.name AS project_name,
    o.email AS owner_email, COALESCE(o.nickname, o.name) AS owner_name, o.avatar_url AS owner_avatar,
    (SELECT COUNT(*) FROM approvals a WHERE a.session_id = s.id AND a.status IN ('PENDING','RESPONDING')) AS pending_approvals,
    (SELECT COUNT(*) FROM session_collaborators sc WHERE sc.session_id = s.id) AS collaborator_count
  FROM sessions s LEFT JOIN projects p ON p.id = s.project_id JOIN users o ON o.id = s.user_id`;

export type SessionRole = 'owner' | 'chat' | 'viewer';
export type AccessNeed = 'read' | 'chat' | 'owner';
export interface SessionAccess {
  session: any;
  role: SessionRole;
  isOwner: boolean;
}

/**
 * Resolves and authorizes access to a session for a user.
 * - owner: always allowed.
 * - a linked collaborator: allowed for 'read'; for 'chat' only when their role is 'chat'; never for 'owner'.
 * - anyone else: 404 (the session's existence is not revealed).
 * A collaborator who lacks the needed capability gets 403 NOT_ALLOWED.
 */
export async function assertSessionAccess(userId: string, sessionId: string, need: AccessNeed): Promise<SessionAccess> {
  const session = await db.get(`${SESSION_SELECT} WHERE s.id = ?`, sessionId);
  if (!session) throw notFound('Session');
  if (session.user_id === userId) {
    session.my_role = 'owner';
    return { session, role: 'owner', isOwner: true };
  }
  const collab = await db.get<{ role: string }>('SELECT role FROM session_collaborators WHERE session_id = ? AND user_id = ?', sessionId, userId);
  if (!collab) throw notFound('Session');
  const role: SessionRole = collab.role === 'chat' ? 'chat' : 'viewer';
  if (need === 'owner') throw forbidden('Only the session owner can do this', 'NOT_ALLOWED');
  if (need === 'chat' && role !== 'chat') throw forbidden('You have view-only access to this session', 'NOT_ALLOWED');
  session.my_role = role;
  return { session, role, isOwner: false };
}

/** A photo URL for an account: the uploaded avatar (short-lived signed URL) or the identity provider's. */
async function avatarFor(avatarKey: string | null | undefined, avatarUrl: string | null | undefined): Promise<string | null> {
  if (avatarKey && storage) {
    try {
      return await storage.presignGet(avatarKey, 3600);
    } catch {}
  }
  return avatarUrl ?? null;
}

/**
 * The GET /v1/sessions/:id/collaborators body:
 * { owner:{userId,email,name,avatar}, collaborators:[{id,userId|null,email,name|null,avatar|null,role,pending,you}] }
 * `id` is the collaborator row id used by DELETE. `you` is set only when callerId is given.
 */
export async function collaboratorsPayload(sessionId: string, callerId: string | null) {
  const owner = await db.get<any>(
    'SELECT s.user_id AS id, o.email, COALESCE(o.nickname, o.name) AS name, o.avatar_url AS avatar_url, o.avatar_key AS avatar_key FROM sessions s JOIN users o ON o.id = s.user_id WHERE s.id = ?',
    sessionId,
  );
  const rows = await db.all<any>(
    `SELECT sc.id, sc.user_id, sc.email, sc.role, u.email AS u_email, COALESCE(u.nickname, u.name) AS u_name, u.avatar_url AS u_avatar, u.avatar_key AS u_avatar_key
     FROM session_collaborators sc LEFT JOIN users u ON u.id = sc.user_id WHERE sc.session_id = ? ORDER BY sc.created_at ASC`,
    sessionId,
  );
  return {
    owner: owner
      ? { userId: owner.id, email: owner.email ?? null, name: owner.name ?? null, avatar: await avatarFor(owner.avatar_key, owner.avatar_url) }
      : null,
    collaborators: await Promise.all(
      rows.map(async (r) => ({
        id: r.id,
        userId: r.user_id ?? null,
        email: r.email,
        name: r.user_id ? (r.u_name ?? null) : null,
        avatar: r.user_id ? await avatarFor(r.u_avatar_key, r.u_avatar) : null,
        role: r.role,
        pending: !r.user_id,
        you: !!callerId && r.user_id === callerId,
      })),
    ),
  };
}

/**
 * Emits `collaborators.updated` (live-only) to the owner and every linked collaborator, plus any extra
 * user ids (e.g. a collaborator who was just removed, so their UI updates). `you` is omitted from the
 * broadcast payload; clients recompute it from the collaborator userId and their own account id.
 */
export async function emitCollaboratorsUpdated(sessionId: string, extraUserIds: string[] = []) {
  const owner = await db.get<{ user_id: string }>('SELECT user_id FROM sessions WHERE id = ?', sessionId);
  if (!owner) return;
  const payload = await collaboratorsPayload(sessionId, null);
  const linked = await db.all<{ user_id: string }>('SELECT DISTINCT user_id FROM session_collaborators WHERE session_id = ? AND user_id IS NOT NULL', sessionId);
  const targets = new Set<string>([owner.user_id, ...linked.map((r) => r.user_id), ...extraUserIds]);
  for (const userId of targets) emitEphemeral({ userId, sessionId, type: 'collaborators.updated', payload });
}

/** Links pending email invitations to a user when they sign in. Called from the auth middleware. */
export async function linkPendingCollaborators(userId: string, email: string | null, nowIso: string) {
  if (!email) return;
  await db.run(
    'UPDATE session_collaborators SET user_id = ?, accepted_at = COALESCE(accepted_at, ?) WHERE user_id IS NULL AND LOWER(email) = LOWER(?)',
    userId,
    nowIso,
    email,
  );
}
