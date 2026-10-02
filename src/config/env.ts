import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(8080),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  // SQLite database file. Use ':memory:' for tests.
  DATABASE_PATH: z.string().default('./data/bambookit.db'),
  CORS_ORIGINS: z.string().default('http://localhost:3000'),

  // Supabase project used for authentication. The API never needs the service-role key:
  // tokens are verified against the project's JWKS, or via /auth/v1/user for legacy
  // HS256 projects when SUPABASE_JWT_SECRET is not provided.
  SUPABASE_URL: z.string().url(),
  SUPABASE_ANON_KEY: z.string().optional(),
  SUPABASE_JWT_SECRET: z.string().optional(),
  // Firebase project used as the Google identity provider (Supabase third-party auth).
  // Firebase ID tokens are verified against Google's public keys; no secret is required.
  FIREBASE_PROJECT_ID: z.string().optional(),

  // Public origin used in share links (e.g. https://bambookit-web.onrender.com). Defaults to this API's origin.
  PUBLIC_SHARE_BASE_URL: z.string().url().optional(),
  PAIRING_TOKEN_TTL_SECONDS: z.coerce.number().default(120),
  // Max allowed clock skew for device request signatures.
  DEVICE_SIGNATURE_MAX_SKEW_SECONDS: z.coerce.number().default(300),
  EVENT_RETENTION_DAYS: z.coerce.number().default(14),
});

export type Env = z.infer<typeof envSchema>;

function parseEnv(): Env {
  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    console.error('Invalid environment variables:', JSON.stringify(result.error.format(), null, 2));
    throw new Error('Invalid environment configuration');
  }
  return result.data;
}

export const env = parseEnv();

export const VERSION = '0.2.0';
