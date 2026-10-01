import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify, type JWTPayload } from 'jose';
import { env } from '../config/env.js';
import { sha256, unauthorized } from '../lib/http.js';
import { logger } from '../lib/logger.js';

export interface AuthUser {
  id: string;
  email: string | null;
  name: string | null;
  avatarUrl: string | null;
}

const issuer = `${env.SUPABASE_URL.replace(/\/+$/, '')}/auth/v1`;
let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

// Short cache for tokens verified through the /auth/v1/user endpoint (legacy HS256 projects).
const remoteCache = new Map<string, { user: AuthUser; expires: number }>();

function fromClaims(payload: JWTPayload & Record<string, any>): AuthUser {
  if (!payload.sub) throw unauthorized('Token has no subject');
  const meta = payload.user_metadata ?? {};
  return {
    id: payload.sub,
    email: payload.email ?? null,
    name: meta.full_name ?? meta.name ?? null,
    avatarUrl: meta.avatar_url ?? meta.picture ?? null,
  };
}

async function verifyViaAuthServer(token: string): Promise<AuthUser> {
  if (!env.SUPABASE_ANON_KEY) {
    throw unauthorized('Server cannot verify HS256 tokens: set SUPABASE_JWT_SECRET or SUPABASE_ANON_KEY', 'AUTH_NOT_CONFIGURED');
  }
  const key = sha256(token);
  const cached = remoteCache.get(key);
  if (cached && cached.expires > Date.now()) return cached.user;

  const res = await fetch(`${issuer}/user`, {
    headers: { apikey: env.SUPABASE_ANON_KEY, Authorization: `Bearer ${token}` },
  });
  if (res.status === 401 || res.status === 403) throw unauthorized('Invalid or expired session', 'INVALID_TOKEN');
  if (!res.ok) {
    logger.error('Supabase auth server error', { status: res.status });
    throw unauthorized('Authentication service unavailable', 'AUTH_UNAVAILABLE');
  }
  const body = (await res.json()) as any;
  const user = fromClaims({ sub: body.id, email: body.email, user_metadata: body.user_metadata });
  remoteCache.set(key, { user, expires: Date.now() + 60_000 });
  if (remoteCache.size > 5000) remoteCache.clear();
  return user;
}

const FIREBASE_JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
let firebaseJwks: ReturnType<typeof createRemoteJWKSet> | null = null;

/** Verify a Firebase ID token (Google sign-in) for the configured Firebase project. */
async function verifyFirebaseToken(token: string): Promise<AuthUser> {
  const projectId = env.FIREBASE_PROJECT_ID!;
  firebaseJwks ??= createRemoteJWKSet(new URL(FIREBASE_JWKS_URL));
  try {
    const { payload } = await jwtVerify(token, firebaseJwks, {
      issuer: `https://securetoken.google.com/${projectId}`,
      audience: projectId,
      algorithms: ['RS256'],
    });
    const p = payload as JWTPayload & Record<string, any>;
    if (p.email && p.email_verified === false) throw unauthorized('Email address is not verified', 'EMAIL_NOT_VERIFIED');
    return fromClaims({ ...p, user_metadata: { full_name: p.name, avatar_url: p.picture } });
  } catch (err: any) {
    if (err?.status === 401) throw err;
    throw unauthorized(err?.code === 'ERR_JWT_EXPIRED' ? 'Session expired' : 'Invalid session token', 'INVALID_TOKEN');
  }
}

function tokenIssuer(token: string): string | undefined {
  try {
    const body = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'));
    return typeof body.iss === 'string' ? body.iss : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Verify an access token and return the authenticated user. Accepts Supabase Auth sessions and,
 * when FIREBASE_PROJECT_ID is set, Firebase ID tokens (Firebase as Supabase third-party auth).
 * The issuer only selects the verification path; the signature and claims are always checked.
 */
export async function verifySupabaseToken(token: string): Promise<AuthUser> {
  let alg: string | undefined;
  try {
    alg = decodeProtectedHeader(token).alg;
  } catch {
    throw unauthorized('Malformed token', 'INVALID_TOKEN');
  }

  if (env.FIREBASE_PROJECT_ID && tokenIssuer(token) === `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`) {
    return verifyFirebaseToken(token);
  }

  try {
    if (alg === 'HS256') {
      if (!env.SUPABASE_JWT_SECRET) return await verifyViaAuthServer(token);
      const { payload } = await jwtVerify(token, new TextEncoder().encode(env.SUPABASE_JWT_SECRET), {
        issuer,
        audience: 'authenticated',
      });
      return fromClaims(payload);
    }
    jwks ??= createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
    const { payload } = await jwtVerify(token, jwks, { issuer, audience: 'authenticated' });
    return fromClaims(payload);
  } catch (err: any) {
    if (err?.status === 401) throw err;
    throw unauthorized(err?.code === 'ERR_JWT_EXPIRED' ? 'Session expired' : 'Invalid session token', 'INVALID_TOKEN');
  }
}
