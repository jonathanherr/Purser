import { z } from 'zod';

const Env = z.object({
  // Local SQLite file for the Node server and admin CLI. Ignored inside the Worker (D1 binding).
  DATABASE_PATH: z.string().min(1).default('purser.db'),
  // Admin CLI against the production D1 database over Cloudflare's API (PURSER_DB=remote).
  PURSER_DB: z.enum(['local', 'remote']).default('local'),
  CLOUDFLARE_ACCOUNT_ID: z.string().optional(),
  CLOUDFLARE_API_TOKEN: z.string().optional(),
  D1_DATABASE_ID: z.string().optional(),
  PORT: z.coerce.number().default(8787),
  PLAID_CLIENT_ID: z.string().optional(),
  PLAID_SECRET: z.string().optional(),
  // 'production' links real accounts (Plaid Trial or paid plan). Sandbox stays the default.
  PLAID_ENV: z.enum(['sandbox', 'production']).default('sandbox'),
  PLAID_WEBHOOK_URL: z.string().url().optional(),
  // Required wherever access tokens are sealed or opened (server, Worker, sync, linking).
  VAULT_MASTER_KEY: z.string().min(1).optional(),
  SYNC_INTERVAL_HOURS: z.coerce.number().positive().default(6),
});

export type Config = z.infer<typeof Env>;

export function loadConfig(env: Record<string, unknown> = process.env): Config {
  const parsed = Env.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n  ');
    throw new Error(`Invalid configuration:\n  ${issues}`);
  }
  return parsed.data;
}
