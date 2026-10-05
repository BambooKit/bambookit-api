import { createHash, randomBytes } from 'node:crypto';

export class HttpError extends Error {
  constructor(
    public status: 400 | 401 | 402 | 403 | 404 | 409 | 410 | 422 | 426 | 429 | 500 | 502 | 503,
    public code: string,
    message: string,
    /** Safe, structured context for the client's ⓘ details (never secrets). */
    public details?: Record<string, unknown>,
  ) {
    super(message);
  }
}

export const badRequest = (message: string, code = 'BAD_REQUEST') => new HttpError(400, code, message);
export const unauthorized = (message = 'Authentication required', code = 'UNAUTHORIZED') => new HttpError(401, code, message);
export const forbidden = (message = 'Forbidden', code = 'FORBIDDEN') => new HttpError(403, code, message);
export const notFound = (what: string) => new HttpError(404, 'NOT_FOUND', `${what} not found`);
export const conflict = (message: string, code = 'CONFLICT') => new HttpError(409, code, message);

export function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

/** Random, URL-safe identifier with a type prefix. */
export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(12).toString('base64url')}`;
}

/** Deterministic identifier derived from stable inputs (e.g. device + opencode id). */
export function stableId(prefix: string, ...parts: string[]): string {
  return `${prefix}_${sha256(parts.join('\u0000')).slice(0, 24)}`;
}
