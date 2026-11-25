import { loadConfig, type Config } from './config.js';
import { d1HttpDb, type Db } from './db/index.js';
import { sqliteDb } from './db/sqlite.js';
import { LocalKeyProvider, type KeyProvider } from './crypto/envelope.js';
import { plaidClient, type PlaidLike } from './plaid/client.js';

export interface Runtime {
  config: Config;
  db: Db;
  kp?: KeyProvider;
  plaid?: PlaidLike;
}

/**
 * Wires the real dependencies for Node (local server and admin CLI). The Worker wires its own
 * in src/worker.ts. Swap LocalKeyProvider for a KMS-backed provider before holding real tokens.
 */
export function runtime(opts: { requirePlaid?: boolean; requireKey?: boolean } = {}): Runtime {
  const config = loadConfig();
  const db = openDb(config);
  if (opts.requireKey && !config.VAULT_MASTER_KEY) throw new Error('Set VAULT_MASTER_KEY');
  const kp = config.VAULT_MASTER_KEY ? new LocalKeyProvider(config.VAULT_MASTER_KEY) : undefined;
  const hasPlaid = Boolean(config.PLAID_CLIENT_ID && config.PLAID_SECRET);
  if (opts.requirePlaid && !hasPlaid) throw new Error('Set PLAID_CLIENT_ID and PLAID_SECRET (sandbox keys)');
  return { config, db, kp, plaid: hasPlaid ? plaidClient(config) : undefined };
}

export function openDb(config: Config): Db {
  if (config.PURSER_DB === 'local') return sqliteDb(config.DATABASE_PATH);
  const { CLOUDFLARE_ACCOUNT_ID: accountId, CLOUDFLARE_API_TOKEN: apiToken, D1_DATABASE_ID: databaseId } = config;
  if (!accountId || !apiToken || !databaseId) {
    throw new Error('PURSER_DB=remote needs CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN and D1_DATABASE_ID');
  }
  return d1HttpDb({ accountId, apiToken, databaseId });
}
