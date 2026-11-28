import { randomBytes } from 'node:crypto';
import type { Plaid } from 'plaid';
import type { JWK } from 'jose';
import type { Db } from '../src/db/index.js';
import { sqliteDb } from '../src/db/sqlite.js';
import { migrate } from '../src/db/migrate.js';
import { LocalKeyProvider } from '../src/crypto/envelope.js';
import type { PlaidLike } from '../src/plaid/client.js';
import { createAgent, createMember, AGENT_PRESETS } from '../src/scripts/admin.js';
import { storeInstitution, syncInstitution } from '../src/plaid/sync.js';
import { authenticateAgent } from '../src/vault/auth.js';

/** An in-memory SQLite database (the same SQL dialect as D1) behind the vault's Db interface. */
export async function testDb(): Promise<Db> {
  const db = sqliteDb(':memory:');
  await migrate(db);
  return db;
}

/** The field cipher seedHousehold used for each database, for tests that call tools directly. */
export const ciphers = new WeakMap<Db, import('../src/crypto/fields.js').FieldCipher>();

export const testKey = () => new LocalKeyProvider(randomBytes(32).toString('base64'));

const balances = (current: number, available: number | null = current) =>
  ({ current, available, iso_currency_code: 'USD', limit: null, unofficial_currency_code: null }) as Plaid.AccountBalance;

export function account(id: string, name: string, type: string, subtype: string, current: number): Plaid.AccountBase {
  return { account_id: id, name, official_name: null, type, subtype, mask: id.slice(-4), balances: balances(current) } as unknown as Plaid.AccountBase;
}

export function txn(id: string, accountId: string, date: string, amount: number, merchant: string): Plaid.Transaction {
  return {
    transaction_id: id,
    account_id: accountId,
    date,
    authorized_date: date,
    amount,
    iso_currency_code: 'USD',
    name: merchant.toUpperCase(),
    merchant_name: merchant,
    pending: false,
    personal_finance_category: { primary: 'GENERAL_MERCHANDISE', detailed: 'GENERAL_MERCHANDISE_OTHER' },
  } as unknown as Plaid.Transaction;
}

/**
 * A scripted stand-in for Plaid. `pages` are returned by successive transactions/sync calls,
 * keyed by the cursor passed in. It also records which access tokens it saw.
 */
export class FakePlaid implements PlaidLike {
  accounts: Plaid.AccountBase[] = [];
  pages = new Map<string, Partial<Plaid.TransactionsSyncResponse>>();
  holdings: { holdings: Plaid.Holding[]; securities: Plaid.Security[] } | null = null;
  seenTokens: string[] = [];
  nextAccessToken = 'access-sandbox-fake';
  failWith: string | null = null;

  private fail() {
    if (this.failWith) throw Object.assign(new Error('plaid error'), { body: { error_code: this.failWith } });
  }
  async getAccounts(token: string) {
    this.seenTokens.push(token);
    this.fail();
    return this.accounts;
  }
  async syncTransactions(_token: string, cursor: string | undefined) {
    const page = this.pages.get(cursor ?? '') ?? {};
    return { added: [], modified: [], removed: [], has_more: false, next_cursor: cursor ?? '', ...page } as Plaid.TransactionsSyncResponse;
  }
  async getHoldings() {
    if (!this.holdings) throw Object.assign(new Error('x'), { body: { error_code: 'NO_INVESTMENT_ACCOUNTS' } });
    return this.holdings;
  }
  async exchangePublicToken(publicToken: string) {
    return { accessToken: this.nextAccessToken, itemId: `item-${publicToken}` };
  }
  async createLinkToken(_memberId?: string, _opts?: { webhook?: string; redirectUri?: string; accessToken?: string }) {
    return { linkToken: 'link-sandbox-x', expiration: new Date().toISOString() };
  }
  async createSandboxPublicToken(institutionId: string) {
    return `public-${institutionId}`;
  }
  async getWebhookVerificationKey(): Promise<JWK> {
    throw new Error('not used');
  }
}

/**
 * A household with two members. Jonathan owns a shared checking account, a private savings
 * account, and a brokerage. The partner owns a private card and a hidden account.
 */
export async function seedHousehold(db: Db) {
  const kp = testKey();
  const jonathanToken = await createMember(db, 'jonathan', 'Jonathan', 'owner');
  const partnerToken = await createMember(db, 'partner', 'Partner', 'member');

  const pj = new FakePlaid();
  pj.accounts = [
    account('acc-checking-1111', 'Joint checking', 'depository', 'checking', 5200),
    account('acc-savings-2222', 'Savings', 'depository', 'savings', 20000),
    account('acc-broker-3333', 'Brokerage', 'investment', 'brokerage', 41000),
  ];
  pj.pages.set('', {
    added: [
      txn('t1', 'acc-checking-1111', '2026-11-03', 82.15, 'Whole Foods'),
      txn('t2', 'acc-checking-1111', '2026-11-05', 15.99, 'Netflix'),
      txn('t3', 'acc-checking-1111', '2026-11-10', -3200, 'Payroll'),
      txn('t4', 'acc-savings-2222', '2026-11-12', 500, 'Transfer out'),
    ],
    next_cursor: 'c1',
  });
  pj.holdings = {
    holdings: [{ account_id: 'acc-broker-3333', security_id: 'sec-vti', quantity: 100, cost_basis: 20000, institution_value: 29000 } as unknown as Plaid.Holding],
    securities: [{ security_id: 'sec-vti', name: 'Vanguard Total Stock Market ETF', ticker_symbol: 'VTI', type: 'etf', close_price: 290 } as unknown as Plaid.Security],
  };
  const jInst = await storeInstitution(db, kp, { ownerMemberId: 'jonathan', itemId: 'item-j', accessToken: 'access-j', products: ['transactions', 'investments'] });
  await syncInstitution(db, pj, kp, jInst);

  const pp = new FakePlaid();
  pp.accounts = [
    account('acc-card-4444', 'Partner card', 'credit', 'credit card', 640),
    account('acc-hidden-5555', 'Partner personal', 'depository', 'checking', 3000),
  ];
  pp.pages.set('', {
    added: [
      txn('t5', 'acc-card-4444', '2026-11-04', 120, 'Trader Joes'),
      txn('t6', 'acc-hidden-5555', '2026-11-06', 75, 'Gift shop'),
    ],
    next_cursor: 'c1',
  });
  const pInst = await storeInstitution(db, kp, { ownerMemberId: 'partner', itemId: 'item-p', accessToken: 'access-p', products: ['transactions'] });
  await syncInstitution(db, pp, kp, pInst);

  await db.query(`UPDATE accounts SET visibility = 'shared' WHERE plaid_account_id IN ('acc-checking-1111', 'acc-broker-3333')`);
  await db.query(`UPDATE accounts SET visibility = 'hidden' WHERE plaid_account_id = 'acc-hidden-5555'`);
  await db.query(`UPDATE transactions SET category_id = 'groceries' WHERE plaid_transaction_id IN ('t1', 't5')`);
  await db.query(`UPDATE transactions SET category_id = 'subscriptions' WHERE plaid_transaction_id = 't2'`);
  await db.query(`INSERT INTO budgets (category_id, month, amount) VALUES ('groceries', '2026-11-01', 600)`);

  const ids = Object.fromEntries(
    (await db.query<{ plaid_account_id: string; id: string }>(`SELECT plaid_account_id, id FROM accounts`)).rows.map((r) => [r.plaid_account_id, r.id]),
  );

  const agentToken = async (id: string, actsFor: string, scopes = AGENT_PRESETS[id] ?? AGENT_PRESETS.watchdog!) => {
    const token = await createAgent(db, `${id}-${actsFor}`, scopes, actsFor);
    return { token, agent: (await authenticateAgent(db, token))! };
  };

  ciphers.set(db, kp.fields);
  return { kp, ids, jonathanToken, partnerToken, agentToken, pj, jInst };
}
