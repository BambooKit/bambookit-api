import { DeleteObjectsCommand, GetObjectCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { randomBytes } from 'node:crypto';
import { env } from '../config/env.js';

/**
 * Object storage (Cloudflare R2, S3-compatible). Only this server holds the R2 credentials; clients
 * receive short-lived signed URLs scoped to one object. Every key lives under users/{user_id}/, and
 * user ids come from the verified auth token only — never from the request.
 */
export interface StoredObject {
  body: Buffer;
  lastModified: Date;
  contentType: string | null;
}

export interface ObjectStore {
  readonly driver: 'r2' | 'memory';
  presignPut(key: string, contentType: string, contentLength: number, expiresIn: number): Promise<string>;
  presignGet(key: string, expiresIn: number): Promise<string>;
  put(key: string, body: Buffer, contentType: string): Promise<void>;
  get(key: string): Promise<StoredObject | null>;
  list(prefix: string): Promise<Array<{ key: string; lastModified: Date; size: number }>>;
  deleteKeys(keys: string[]): Promise<void>;
}

/** Signed URLs live this long: long enough to upload/download once, short enough to be useless later. */
export const SIGNED_URL_SECONDS = 300;

export const keys = {
  userPrefix: (userId: string) => `users/${safe(userId)}/`,
  avatar: (userId: string, ext: string) => `users/${safe(userId)}/profile/avatar-${randomBytes(8).toString('hex')}.${ext}`,
  avatarPrefix: (userId: string) => `users/${safe(userId)}/profile/`,
  sessionSnapshot: (userId: string, sessionId: string) => `users/${safe(userId)}/sessions/${safe(sessionId)}.json.gz`,
};

/** Ids become path segments; anything that could change the path is rejected. */
function safe(segment: string) {
  if (!/^[A-Za-z0-9_.:@-]{1,200}$/.test(segment) || segment.includes('..')) throw new Error('Unsafe storage key segment');
  return segment;
}

class R2Store implements ObjectStore {
  readonly driver = 'r2' as const;
  constructor(private s3: S3Client, private bucket: string) {}

  presignPut(key: string, contentType: string, contentLength: number, expiresIn: number) {
    return getSignedUrl(this.s3, new PutObjectCommand({ Bucket: this.bucket, Key: key, ContentType: contentType, ContentLength: contentLength }), { expiresIn });
  }
  presignGet(key: string, expiresIn: number) {
    return getSignedUrl(this.s3, new GetObjectCommand({ Bucket: this.bucket, Key: key }), { expiresIn });
  }
  async put(key: string, body: Buffer, contentType: string) {
    await this.s3.send(new PutObjectCommand({ Bucket: this.bucket, Key: key, Body: body, ContentType: contentType }));
  }
  async get(key: string): Promise<StoredObject | null> {
    try {
      const res = await this.s3.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
      return {
        body: Buffer.from(await res.Body!.transformToByteArray()),
        lastModified: res.LastModified ?? new Date(0),
        contentType: res.ContentType ?? null,
      };
    } catch (err: any) {
      if (err?.name === 'NoSuchKey' || err?.$metadata?.httpStatusCode === 404) return null;
      throw err;
    }
  }
  async list(prefix: string) {
    const out: Array<{ key: string; lastModified: Date; size: number }> = [];
    let token: string | undefined;
    do {
      const res = await this.s3.send(new ListObjectsV2Command({ Bucket: this.bucket, Prefix: prefix, ContinuationToken: token }));
      for (const o of res.Contents ?? []) out.push({ key: o.Key!, lastModified: o.LastModified ?? new Date(0), size: o.Size ?? 0 });
      token = res.IsTruncated ? res.NextContinuationToken : undefined;
    } while (token);
    return out;
  }
  async deleteKeys(list: string[]) {
    for (let i = 0; i < list.length; i += 1000) {
      const batch = list.slice(i, i + 1000);
      if (batch.length) await this.s3.send(new DeleteObjectsCommand({ Bucket: this.bucket, Delete: { Objects: batch.map((Key) => ({ Key })) } }));
    }
  }
}

/** In-memory store for tests and local development. Signed URLs are not usable over HTTP. */
export class MemoryStore implements ObjectStore {
  readonly driver = 'memory' as const;
  readonly objects = new Map<string, StoredObject>();
  async presignPut(key: string, contentType: string, contentLength: number, expiresIn: number) {
    return `memory://put/${encodeURIComponent(key)}?type=${encodeURIComponent(contentType)}&length=${contentLength}&expires=${expiresIn}`;
  }
  async presignGet(key: string, expiresIn: number) {
    return `memory://get/${encodeURIComponent(key)}?expires=${expiresIn}`;
  }
  async put(key: string, body: Buffer, contentType: string) {
    this.objects.set(key, { body, lastModified: new Date(), contentType });
  }
  async get(key: string) {
    return this.objects.get(key) ?? null;
  }
  async list(prefix: string) {
    return [...this.objects].filter(([k]) => k.startsWith(prefix)).map(([key, o]) => ({ key, lastModified: o.lastModified, size: o.body.length }));
  }
  async deleteKeys(list: string[]) {
    for (const k of list) this.objects.delete(k);
  }
}

function createStore(): ObjectStore | null {
  if (env.STORAGE_DRIVER === 'memory') return new MemoryStore();
  const endpoint = env.R2_ENDPOINT ?? (env.CLOUDFLARE_ACCOUNT_ID ? `https://${env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com` : undefined);
  if (!endpoint || !env.R2_ACCESS_KEY_ID || !env.R2_SECRET_ACCESS_KEY || !env.R2_BUCKET_NAME) return null;
  const s3 = new S3Client({
    region: 'auto',
    endpoint,
    credentials: { accessKeyId: env.R2_ACCESS_KEY_ID, secretAccessKey: env.R2_SECRET_ACCESS_KEY },
  });
  return new R2Store(s3, env.R2_BUCKET_NAME);
}

/** null when R2 is not configured: cloud features answer 503 STORAGE_NOT_CONFIGURED. */
export const storage: ObjectStore | null = createStore();
