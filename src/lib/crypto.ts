import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { env } from '../config/env.js';

export function generateId(prefix?: string): string {
  const bytes = randomBytes(12).toString('hex');
  return prefix ? `${prefix}_${bytes}` : bytes;
}

export function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 10);
}

export function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function signToken(payload: object, expiresIn = '7d'): string {
  return jwt.sign(payload, env.AUTH_SECRET, { expiresIn } as jwt.SignOptions);
}

export function verifyToken<T = any>(token: string): T | null {
  try {
    return jwt.verify(token, env.AUTH_SECRET) as T;
  } catch {
    return null;
  }
}

// AES-256-GCM symmetric encryption for BYOK credentials at rest
export function encryptSecret(plaintext: string): { ciphertext: string; iv: string; tag: string } {
  const key = Buffer.from(env.ENCRYPTION_KEY.padEnd(32, '0').slice(0, 32), 'utf-8');
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-gcm', key, iv);

  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');

  return {
    ciphertext,
    iv: iv.toString('hex'),
    tag,
  };
}

export function decryptSecret(ciphertext: string, ivHex: string, tagHex: string): string {
  try {
    const key = Buffer.from(env.ENCRYPTION_KEY.padEnd(32, '0').slice(0, 32), 'utf-8');
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');

    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    let plaintext = decipher.update(ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');
    return plaintext;
  } catch (err) {
    throw new Error('Failed to decrypt secret: signature invalid or corrupted key');
  }
}

export function maskSecret(secret: string): string {
  if (!secret || secret.length < 8) return '********';
  return `${secret.slice(0, 4)}...${secret.slice(-4)}`;
}
