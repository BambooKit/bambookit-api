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

  // Cloudflare R2 (S3-compatible) object storage: profile photos and 7-day session history copies.
  // Server-side only; clients get short-lived signed URLs. Unset = cloud storage features are off.
  CLOUDFLARE_ACCOUNT_ID: z.string().optional(),
  R2_ACCESS_KEY_ID: z.string().optional(),
  R2_SECRET_ACCESS_KEY: z.string().optional(),
  R2_BUCKET_NAME: z.string().optional(),
  // Defaults to https://<CLOUDFLARE_ACCOUNT_ID>.r2.cloudflarestorage.com
  R2_ENDPOINT: z.string().url().optional(),
  // 'memory' keeps objects in memory (tests and local development without R2).
  STORAGE_DRIVER: z.enum(['r2', 'memory']).optional(),
  SESSION_SNAPSHOT_DAYS: z.coerce.number().int().positive().default(7),

  // Account deletion: Supabase Auth users are removed with the service-role key (server only, never in clients).
  SUPABASE_SERVICE_ROLE_KEY: z.string().optional(),
  // Firebase Web API key (public) to delete Firebase (Google one-tap) accounts with the user's own token.
  FIREBASE_API_KEY: z.string().optional(),
  // Admin panel and Telegram monitoring (all optional; features stay off until set).
  // Comma-separated emails of BambooKit accounts that may open the admin panel.
  ADMIN_EMAILS: z.string().optional(),
  // Bot token from @BotFather. Never logged or returned by any route.
  TELEGRAM_BOT_TOKEN: z.string().optional(),
  // Comma-separated Telegram chat ids allowed to use the bot (send /start to the bot to see yours).
  TELEGRAM_ADMIN_CHAT_IDS: z.string().optional(),
  // Secret Telegram sends with every webhook call; derived from the bot token when not set.
  TELEGRAM_WEBHOOK_SECRET: z.string().optional(),
  // IANA time zone for the bot's "today / 7 d / 30 d" windows, times shown and the 09:00 daily report.
  TELEGRAM_TIMEZONE: z.string().default('Asia/Kolkata'),

  // Payments through Cashfree (optional; checkout answers 503 PAYMENTS_NOT_CONFIGURED until both are set).
  // Cashfree dashboard -> Developers -> API keys. Never logged or returned.
  CASHFREE_APP_ID: z.string().optional(),
  CASHFREE_SECRET_KEY: z.string().optional(),
  CASHFREE_ENV: z.preprocess((v) => (v === '' ? undefined : v), z.enum(['sandbox', 'production']).optional()),
  // Page Cashfree returns the buyer to (?order_id=... is appended). Defaults to the BambooKit website.
  BILLING_RETURN_URL: z.string().url().optional().or(z.literal('').transform(() => undefined)),
  // HMAC key for rewarded-ad custom data; derived from another configured server secret when unset.
  REWARD_SIGNING_SECRET: z.string().optional(),
  // AdMob rewarded ad unit whose server-side verification callbacks grant Pro time (ad unit ids are public).
  ADMOB_REWARDED_UNIT: z.string().optional(),
  // GitHub token (no scopes needed for public repos) for release lookups: 5,000 instead of 60 requests an hour. Never logged.
  GITHUB_TOKEN: z.string().optional(),
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


export const VERSION = '1.3.0';
