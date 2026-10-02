import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(8080),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  // SQLite database file. Use ':memory:' for tests.
  DATABASE_PATH: z.string().default('./data/bambookit.db'),
  // Postgres connection string (e.g. Supabase → Project settings → Database → Connection string, "Session pooler").
  // When set, it is used instead of SQLite. Required on hosts whose disk is wiped on restart (Render free tier).
  POSTGRES_URL: z.string().optional(),
  CORS_ORIGINS: z.string().default('http://localhost:3000,https://bambookit-web.onrender.com'),

  // Supabase project used for authentication. The API never needs the service-role key:
  // tokens are verified against the project's JWKS, or via /auth/v1/user for legacy
  // HS256 projects when SUPABASE_JWT_SECRET is not provided.
  // Public project URL (not a secret). Tokens are verified with the project's public JWKS keys.
  SUPABASE_URL: z.string().url().default('https://skvjitpcpwfprgxvnpdd.supabase.co'),
  SUPABASE_ANON_KEY: z.string().optional(),
  SUPABASE_JWT_SECRET: z.string().optional(),
  // Firebase project used as the Google identity provider (Supabase third-party auth).
  // Firebase ID tokens are verified against Google's public keys; no secret is required.
  FIREBASE_PROJECT_ID: z.string().default('bambookit-product'),

  // Public origin used in share links (e.g. https://bambookit-web.onrender.com). Defaults to this API's origin.
  PUBLIC_SHARE_BASE_URL: z.string().url().optional(),
  // Set automatically by Render; used for sensible hosted defaults.
  RENDER: z.string().optional(),
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

// On Render, share links point at the public website unless configured otherwise.
if (!env.PUBLIC_SHARE_BASE_URL && env.RENDER) env.PUBLIC_SHARE_BASE_URL = 'https://bambookit-web.onrender.com';

export const VERSION = '0.2.0';
