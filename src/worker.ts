import { loadConfig } from './config.js';
import { pgDb } from './db/index.js';
import { LocalKeyProvider } from './crypto/envelope.js';
import { plaidClient } from './plaid/client.js';
import { createApp } from './http/app.js';
import { syncAll } from './plaid/sync.js';
import { expireProposals } from './vault/proposals.js';

/**
 * Cloudflare Workers entry point. The Node entry (src/index.ts) stays for local development.
 *
 * Differences from Node:
 * - Postgres is reached through Hyperdrive. Workers cannot share a socket between requests, so
 *   each request opens a small pool against Hyperdrive (which keeps the real connections warm)
 *   and closes it once the response and any background work are done.
 * - The in-process setInterval timers become Cron Triggers (see wrangler.jsonc).
 * - Migrations are not run here: the deploy workflow runs `npm run migrate` before deploying.
 */

// Only the Workers types we use, so the Node typecheck needs no extra global types.
interface Hyperdrive {
  connectionString: string;
}
interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}
interface ScheduledController {
  cron: string;
  scheduledTime: number;
}

interface Env {
  HYPERDRIVE: Hyperdrive;
  // Secrets (wrangler secret put ...)
  PLAID_CLIENT_ID?: string;
  PLAID_SECRET?: string;
  VAULT_MASTER_KEY: string;
  // Plain vars (wrangler.jsonc)
  PLAID_ENV?: string;
  PLAID_WEBHOOK_URL?: string;
}

/** Must match the expiry schedule in wrangler.jsonc. Every other cron runs the Plaid sync. */
const EXPIRY_CRON = '*/15 * * * *';

function wire(env: Env) {
  const config = loadConfig({ ...env, DATABASE_URL: env.HYPERDRIVE.connectionString });
  const db = pgDb(config.DATABASE_URL, { max: 3 });
  const kp = new LocalKeyProvider(config.VAULT_MASTER_KEY);
  const plaid = config.PLAID_CLIENT_ID && config.PLAID_SECRET ? plaidClient(config) : undefined;
  return { config, db, kp, plaid };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { config, db, kp, plaid } = wire(env);
    const pending: Promise<unknown>[] = [];
    const app = createApp({
      db,
      kp,
      plaid,
      plaidWebhookUrl: config.PLAID_WEBHOOK_URL,
      background: (work) => pending.push(work),
    });
    try {
      return await app.fetch(request);
    } finally {
      // Close the pool only after background work (webhook-triggered syncs) has finished.
      ctx.waitUntil(Promise.allSettled(pending).then(() => db.close()));
    }
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const { db, kp, plaid } = wire(env);
    const work =
      controller.cron === EXPIRY_CRON
        ? expireProposals(db)
        : plaid
          ? syncAll(db, plaid, kp)
          : Promise.resolve(console.log('scheduled sync skipped: Plaid is not configured'));
    ctx.waitUntil(work.finally(() => db.close()));
  },
};
