import { hkdfSync } from 'node:crypto';
import { aesGcmDecrypt, aesGcmEncrypt } from './aes.js';

/**
 * Field-level encryption for the ledger at rest.
 *
 * Everything that says what you have or spend (amounts, merchant names, account names and
 * numbers, balances, positions) is stored as one AES-256-GCM ciphertext per row, in a `sealed`
 * column. Only what the vault needs to find rows stays in the clear: ids, dates, categories,
 * pending flags and account types. So a copy of the database (an export, a backup, a leaked
 * D1 API token, the Cloudflare console) shows when and how often money moved, but not how much,
 * where, or in which named account.
 *
 * The key is derived from VAULT_MASTER_KEY with HKDF, separately from the key that wraps Plaid
 * access tokens. Each ciphertext is bound to its row (the additional data names the row), so a
 * ciphertext copied onto another row fails to decrypt.
 *
 * Not covered: someone who controls the Cloudflare account can deploy code that reads the
 * Worker's secret. Moving the key to a KMS outside Cloudflare is the fix for that (phase 1c).
 */
export class FieldCipher {
  static readonly version = 'f1';

  private constructor(private readonly key: Buffer) {}

  static fromMaster(master: Buffer): FieldCipher {
    return new FieldCipher(Buffer.from(hkdfSync('sha256', master, 'purser', 'ledger-fields/v1', 32)));
  }

  seal(value: unknown, row: string): string {
    return `${FieldCipher.version}:${aesGcmEncrypt(this.key, Buffer.from(JSON.stringify(value), 'utf8'), row)}`;
  }

  open<T>(sealed: string, row: string): T {
    const [version, body] = [sealed.slice(0, 2), sealed.slice(3)];
    if (version !== FieldCipher.version) throw new Error(`unknown ledger cipher version ${version}`);
    return JSON.parse(aesGcmDecrypt(this.key, body, row).toString('utf8')) as T;
  }
}

/** Row names used as additional data. Each names a row by ids that never change. */
export const rowId = {
  account: (plaidAccountId: string) => `account:${plaidAccountId}`,
  balance: (plaidAccountId: string, asOf: string) => `balance:${plaidAccountId}:${asOf}`,
  transaction: (plaidTransactionId: string) => `transaction:${plaidTransactionId}`,
  holding: (plaidAccountId: string, securityId: string, asOf: string) => `holding:${plaidAccountId}:${securityId}:${asOf}`,
};

/** The sealed contents of each ledger row. */
export interface AccountFields {
  name: string;
  official_name: string | null;
  mask: string | null;
  current_balance: number | null;
  available_balance: number | null;
  currency: string | null;
}
export interface BalanceFields {
  current: number | null;
  available: number | null;
}
export interface TransactionFields {
  amount: number;
  authorized_date: string | null;
  currency: string | null;
  merchant_name: string | null;
  raw_name: string | null;
  plaid_category: string | null;
}
export interface HoldingFields {
  quantity: number | null;
  cost_basis: number | null;
  market_value: number | null;
}

/** How long the ledger keeps transactions, balance history and holdings snapshots. */
export const RETENTION_MONTHS = 13;

/** The first date (YYYY-MM-DD) still inside the retention window. */
export function retentionCutoff(now = new Date()): string {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - RETENTION_MONTHS, now.getUTCDate()));
  return d.toISOString().slice(0, 10);
}
