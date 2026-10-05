import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { logger } from '../lib/logger.js';

/**
 * AdMob rewarded-ad server-side verification (SSV).
 * Google calls our callback with the reward details; the query string up to (excluding) '&signature='
 * is signed with ECDSA P-256 / SHA-256 (DER signature, web-safe base64). key_id selects one of the
 * public keys published at VERIFIER_KEYS_URL, which rotate — cache them at most 24 hours.
 * Docs: https://developers.google.com/admob/android/ssv
 */
export const VERIFIER_KEYS_URL = 'https://www.gstatic.com/admob/reward/verifier-keys.json';
const CACHE_MS = 24 * 3600_000;
const REFETCH_MIN_MS = 60_000;

export type VerifierKeyLoader = () => Promise<Array<{ keyId: string | number; pem?: string; base64?: string }>>;

const defaultLoader: VerifierKeyLoader = async () => {
  const res = await fetch(VERIFIER_KEYS_URL, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`verifier keys: HTTP ${res.status}`);
  const json: any = await res.json();
  return Array.isArray(json?.keys) ? json.keys : [];
};

let loader: VerifierKeyLoader = defaultLoader;
let cache: { at: number; keys: Map<string, KeyObject> } | null = null;
let lastLoadError: { at: number; message: string } | null = null;

/** Cached verifier-key state for the admin health screen (no network call). */
export function verifierKeysState() {
  return {
    loadedAt: cache ? new Date(cache.at).toISOString() : null,
    keys: cache?.keys.size ?? 0,
    lastError: lastLoadError ? { at: new Date(lastLoadError.at).toISOString(), message: lastLoadError.message } : null,
  };
}

/** Tests inject their own key source (pass null to restore Google's). */
export function setVerifierKeyLoader(fn: VerifierKeyLoader | null) {
  loader = fn ?? defaultLoader;
  cache = null;
}

async function load() {
  const keys = new Map<string, KeyObject>();
  for (const k of await loader()) {
    try {
      const key = k.pem ? createPublicKey(k.pem) : createPublicKey({ key: Buffer.from(String(k.base64), 'base64'), format: 'der', type: 'spki' });
      keys.set(String(k.keyId), key);
    } catch {
      logger.warn('admob verifier key unreadable', { keyId: String(k.keyId) });
    }
  }
  cache = { at: Date.now(), keys };
  lastLoadError = null;
}

async function keyFor(keyId: string): Promise<KeyObject | null> {
  const age = cache ? Date.now() - cache.at : Infinity;
  // Reload when stale, or when a new (rotated) key id shows up — at most once a minute.
  if (age > CACHE_MS || (!cache!.keys.has(keyId) && age > REFETCH_MIN_MS)) {
    try {
      await load();
    } catch (err: any) {
      lastLoadError = { at: Date.now(), message: String(err?.message ?? err).slice(0, 200) };
      logger.warn('admob verifier keys unavailable', { error: String(err?.message ?? err).slice(0, 200) });
    }
  }
  return cache?.keys.get(keyId) ?? null;
}

/** Verifies a raw (still percent-encoded) callback query string. Returns its parameters when the signature is valid. */
export async function verifySsvQuery(rawQuery: string): Promise<URLSearchParams | null> {
  const at = rawQuery.indexOf('&signature=');
  if (at <= 0) return null;
  const params = new URLSearchParams(rawQuery);
  const signature = params.get('signature');
  const keyId = params.get('key_id');
  if (!signature || !keyId) return null;
  const key = await keyFor(keyId);
  if (!key) return null;
  try {
    // Node's base64 decoder also accepts the web-safe alphabet Google uses.
    return verify('sha256', Buffer.from(rawQuery.slice(0, at), 'utf8'), key, Buffer.from(signature, 'base64')) ? params : null;
  } catch {
    return null;
  }
}
