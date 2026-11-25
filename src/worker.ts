import { loadConfig } from './config.js';
import { d1Db, type D1Like } from './db/index.js';
import { LocalKeyProvider } from './crypto/envelope.js';
import { plaidClient } from './plaid/client.js';
import { createApp } from './http/app.js';
import { syncAll } from './plaid/sync.js';
import { expireProposals } from './vault/proposals.js';
import { pruneSignIns } from './http/oauth.js';

/**
 * Cloudflare Workers entry point. The Node entry (src/index.ts) stays for local development.
 *
 * Differences from Node:
 * - The database is D1 (SQLite), bound as env.DB. Same SQL as the local node:sqlite database.
 * - The in-process setInterval timers become Cron Triggers (see wrangler.jsonc).
 * - Migrations are not run here: the deploy workflow runs `wrangler d1 migrations apply` first.
 */

// Only the Workers types we use, so the Node typecheck needs no extra global types.
interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}
interface ScheduledController {
  cron: string;
  scheduledTime: number;
}

interface Env {
  DB: D1Like;
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
  const config = loadConfig(env as unknown as Record<string, unknown>);
  if (!config.VAULT_MASTER_KEY) throw new Error('Set the VAULT_MASTER_KEY Worker secret');
  const db = d1Db(env.DB);
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
    const response = await app.fetch(request);
    // Keep the Worker alive for background work (webhook-triggered syncs).
    if (pending.length) ctx.waitUntil(Promise.allSettled(pending));
    return response;
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const { db, kp, plaid } = wire(env);
    const work =
      controller.cron === EXPIRY_CRON
        ? Promise.all([expireProposals(db), pruneSignIns(db)])
        : plaid
          ? syncAll(db, plaid, kp)
          : Promise.resolve(console.log('scheduled sync skipped: Plaid is not configured'));
    ctx.waitUntil(work);
  },
};
