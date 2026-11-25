import { z } from 'zod';

const Env = z.object({
  DATABASE_URL: z.string().min(1),
  PORT: z.coerce.number().default(8787),
  PLAID_CLIENT_ID: z.string().optional(),
  PLAID_SECRET: z.string().optional(),
  // Purser is sandbox-only until phase 1c. Anything else is refused at start-up.
  PLAID_ENV: z.literal('sandbox').default('sandbox'),
  PLAID_WEBHOOK_URL: z.string().url().optional(),
  VAULT_MASTER_KEY: z.string().min(1),
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
