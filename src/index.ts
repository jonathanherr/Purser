import { serve } from '@hono/node-server';
import { runtime } from './runtime.js';
import { migrate } from './db/migrate.js';
import { createApp } from './http/app.js';
import { syncAll } from './plaid/sync.js';
import { expireProposals } from './vault/proposals.js';

// Local development server on a SQLite file. Production runs src/worker.ts on Cloudflare.
const { config, db, kp, plaid } = runtime({ requireKey: true });
await migrate(db);

const app = createApp({ db, kp: kp!, plaid, plaidWebhookUrl: config.PLAID_WEBHOOK_URL });
serve({ fetch: app.fetch, port: config.PORT }, (info) => {
  console.log(`purser vault listening on :${info.port} (db ${config.DATABASE_PATH}, plaid ${plaid ? config.PLAID_ENV : 'not configured'})`);
});

// Backstop sync in case a webhook is missed, plus proposal expiry.
const hours = config.SYNC_INTERVAL_HOURS;
setInterval(() => {
  if (plaid) syncAll(db, plaid, kp!).catch((e) => console.error('scheduled sync failed', e));
}, hours * 3_600_000).unref();
setInterval(() => {
  expireProposals(db).catch((e) => console.error('expiry failed', e));
}, 15 * 60_000).unref();
