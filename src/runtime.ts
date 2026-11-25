import { loadConfig, type Config } from './config.js';
import { pgDb, type Db } from './db/index.js';
import { LocalKeyProvider, type KeyProvider } from './crypto/envelope.js';
import { plaidClient, type PlaidLike } from './plaid/client.js';

export interface Runtime {
  config: Config;
  db: Db;
  kp: KeyProvider;
  plaid?: PlaidLike;
}

/**
 * Wires the real dependencies from the environment. Swap LocalKeyProvider for a KMS-backed
 * provider before holding real (non-sandbox) tokens.
 */
export function runtime(opts: { requirePlaid?: boolean } = {}): Runtime {
  const config = loadConfig();
  const db = pgDb(config.DATABASE_URL);
  const kp = new LocalKeyProvider(config.VAULT_MASTER_KEY);
  const hasPlaid = Boolean(config.PLAID_CLIENT_ID && config.PLAID_SECRET);
  if (opts.requirePlaid && !hasPlaid) throw new Error('Set PLAID_CLIENT_ID and PLAID_SECRET (sandbox keys)');
  return { config, db, kp, plaid: hasPlaid ? plaidClient(config) : undefined };
}
