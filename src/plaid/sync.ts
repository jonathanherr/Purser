import type { Plaid } from 'plaid';

type AccountBase = Plaid.AccountBase;
type Holding = Plaid.Holding;
type Security = Plaid.Security;
type Transaction = Plaid.Transaction;
type RemovedTransaction = Plaid.RemovedTransaction;
import { json, NOW, type Db, type Stmt } from '../db/index.js';
import type { KeyProvider } from '../crypto/envelope.js';
import { seal, unseal } from '../crypto/envelope.js';
import { audit } from '../vault/audit.js';
import { plaidErrorCode, type PlaidLike } from './client.js';

interface InstitutionRow {
  id: string;
  owner_member_id: string;
  plaid_item_id: string;
  access_token_ct: string;
  wrapped_dek: string;
  key_id: string;
  transactions_cursor: string | null;
  products: string;
}

export interface SyncResult {
  institutionId: string;
  accounts: number;
  added: number;
  modified: number;
  removed: number;
  holdings: number;
  status: 'ok' | 'needs_relink' | 'error';
  error?: string;
}

const SYSTEM = { type: 'system', id: 'sync' } as const;
const tokenContext = (itemId: string) => `plaid-access-token:${itemId}`;

/** Stores a newly linked Plaid Item with its access token sealed. Returns the institution id. */
export async function storeInstitution(
  db: Db,
  kp: KeyProvider,
  args: {
    ownerMemberId: string;
    itemId: string;
    accessToken: string;
    plaidInstitutionId?: string | null;
    name?: string | null;
    products: string[];
  },
): Promise<string> {
  const sealed = await seal(kp, args.accessToken, tokenContext(args.itemId));
  const { rows } = await db.query<{ id: string }>(
    `INSERT INTO institutions (owner_member_id, plaid_item_id, plaid_institution_id, name,
                               access_token_ct, wrapped_dek, key_id, products)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
     ON CONFLICT (plaid_item_id) DO UPDATE SET
       access_token_ct = excluded.access_token_ct, wrapped_dek = excluded.wrapped_dek,
       key_id = excluded.key_id, status = 'active', last_error = NULL
     RETURNING id`,
    [
      args.ownerMemberId,
      args.itemId,
      args.plaidInstitutionId ?? null,
      args.name ?? null,
      sealed.ciphertext,
      sealed.wrappedDek,
      sealed.keyId,
      args.products,
    ],
  );
  const id = rows[0]!.id;
  await audit(db, {
    actor: SYSTEM,
    action: 'institution.link',
    outcome: 'ok',
    detail: { institutionId: id, owner: args.ownerMemberId },
  });
  return id;
}

/**
 * Pulls accounts, balances, transactions (cursor-based) and holdings for one Plaid Item, and writes
 * them to the ledger. This is the only code path that decrypts an access token.
 */
export async function syncInstitution(
  db: Db,
  plaid: PlaidLike,
  kp: KeyProvider,
  institutionId: string,
): Promise<SyncResult> {
  const { rows } = await db.query<InstitutionRow>(
    `SELECT id, owner_member_id, plaid_item_id, access_token_ct, wrapped_dek, key_id,
            transactions_cursor, products
       FROM institutions WHERE id = ?1 AND status <> 'removed'`,
    [institutionId],
  );
  const inst = rows[0];
  if (!inst) throw new Error(`institution ${institutionId} not found`);

  const result: SyncResult = {
    institutionId,
    accounts: 0,
    added: 0,
    modified: 0,
    removed: 0,
    holdings: 0,
    status: 'ok',
  };

  try {
    const accessToken = await unseal(
      kp,
      { ciphertext: inst.access_token_ct, wrappedDek: inst.wrapped_dek, keyId: inst.key_id },
      tokenContext(inst.plaid_item_id),
    );

    const accounts = await plaid.getAccounts(accessToken);
    const tx = await pullTransactions(plaid, accessToken, inst.transactions_cursor);
    const investments = json<string[]>(inst.products).includes('investments')
      ? await pullHoldings(plaid, accessToken)
      : null;

    // Every ledger write for this sync lands in one atomic batch, cursor included: if any
    // statement fails, nothing is written and the next sync retries from the old cursor.
    // On D1 the whole batch also counts as a single query against the per-request limit.
    await db.batch([
      ...upsertAccounts(inst, accounts),
      ...applyTransactions(tx.added, tx.modified, tx.removed),
      ...(investments ? upsertHoldings(investments.holdings, investments.securities) : []),
      {
        sql: `UPDATE institutions SET transactions_cursor = ?2, last_synced_at = ${NOW}, status = 'active',
                last_error = NULL WHERE id = ?1`,
        params: [inst.id, tx.cursor],
      },
    ]);
    result.accounts = accounts.length;
    result.added = tx.added.length;
    result.modified = tx.modified.length;
    result.removed = tx.removed.length;
    result.holdings = investments?.holdings.length ?? 0;
  } catch (err) {
    const code = plaidErrorCode(err);
    result.status = code === 'ITEM_LOGIN_REQUIRED' ? 'needs_relink' : 'error';
    result.error = code ?? (err instanceof Error ? err.message : String(err));
    await db.query(`UPDATE institutions SET status = ?2, last_error = ?3 WHERE id = ?1`, [
      inst.id,
      result.status,
      result.error,
    ]);
  }

  await audit(db, {
    actor: SYSTEM,
    action: 'institution.sync',
    outcome: result.status === 'ok' ? 'ok' : 'error',
    detail: { ...result },
  });
  return result;
}

export async function syncAll(db: Db, plaid: PlaidLike, kp: KeyProvider): Promise<SyncResult[]> {
  const { rows } = await db.query<{ id: string }>(
    `SELECT id FROM institutions WHERE status IN ('active', 'error') ORDER BY created_at`,
  );
  const results: SyncResult[] = [];
  for (const r of rows) results.push(await syncInstitution(db, plaid, kp, r.id));
  return results;
}

async function pullTransactions(plaid: PlaidLike, accessToken: string, startCursor: string | null) {
  // Plaid asks clients to restart the whole pagination loop from the original cursor if the data
  // changes mid-way (TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION).
  for (let attempt = 0; attempt < 3; attempt++) {
    const added: Transaction[] = [];
    const modified: Transaction[] = [];
    const removed: RemovedTransaction[] = [];
    let cursor = startCursor ?? undefined;
    try {
      for (let page = 0; page < 100; page++) {
        const data = await plaid.syncTransactions(accessToken, cursor);
        added.push(...data.added);
        modified.push(...data.modified);
        removed.push(...data.removed);
        cursor = data.next_cursor;
        if (!data.has_more) return { added, modified, removed, cursor: cursor ?? null };
      }
      throw new Error('transactions sync exceeded 100 pages');
    } catch (err) {
      if (plaidErrorCode(err) !== 'TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION') throw err;
    }
  }
  throw new Error('transactions sync kept changing during pagination');
}

async function pullHoldings(plaid: PlaidLike, accessToken: string) {
  try {
    return await plaid.getHoldings(accessToken);
  } catch (err) {
    const code = plaidErrorCode(err);
    if (code === 'NO_INVESTMENT_ACCOUNTS' || code === 'PRODUCTS_NOT_SUPPORTED') return null;
    throw err;
  }
}

function upsertAccounts(inst: InstitutionRow, accounts: AccountBase[]): Stmt[] {
  return accounts.flatMap((a): Stmt[] => [
    {
      sql: `INSERT INTO accounts (institution_id, plaid_account_id, owner_member_id, name, official_name,
                             type, subtype, mask, current_balance, available_balance, iso_currency_code)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
       ON CONFLICT (plaid_account_id) DO UPDATE SET
         name = excluded.name, official_name = excluded.official_name, type = excluded.type,
         subtype = excluded.subtype, mask = excluded.mask,
         current_balance = excluded.current_balance, available_balance = excluded.available_balance,
         iso_currency_code = excluded.iso_currency_code, updated_at = ${NOW}`,
      params: [
        inst.id,
        a.account_id,
        inst.owner_member_id,
        a.name,
        a.official_name ?? null,
        a.type,
        a.subtype ?? null,
        a.mask ?? null,
        a.balances.current ?? null,
        a.balances.available ?? null,
        a.balances.iso_currency_code ?? null,
      ],
    },
    {
      sql: `INSERT INTO balances (account_id, as_of, current, available)
       SELECT id, ${NOW}, ?2, ?3 FROM accounts WHERE plaid_account_id = ?1
       ON CONFLICT DO NOTHING`,
      params: [a.account_id, a.balances.current ?? null, a.balances.available ?? null],
    },
  ]);
}

function applyTransactions(added: Transaction[], modified: Transaction[], removed: RemovedTransaction[]): Stmt[] {
  const upserts = [...added, ...modified].map(
    (t): Stmt => ({
      sql: `INSERT INTO transactions (plaid_transaction_id, account_id, date, authorized_date, amount,
                                 iso_currency_code, merchant_name, raw_name, pending, plaid_category,
                                 raw)
       SELECT ?1, a.id, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11
         FROM accounts a WHERE a.plaid_account_id = ?2
       ON CONFLICT (plaid_transaction_id) DO UPDATE SET
         date = excluded.date, authorized_date = excluded.authorized_date, amount = excluded.amount,
         iso_currency_code = excluded.iso_currency_code, merchant_name = excluded.merchant_name,
         raw_name = excluded.raw_name, pending = excluded.pending,
         plaid_category = excluded.plaid_category, raw = excluded.raw,
         removed_at = NULL, updated_at = ${NOW}`,
      params: [
        t.transaction_id,
        t.account_id,
        t.date,
        t.authorized_date ?? null,
        t.amount,
        t.iso_currency_code ?? null,
        t.merchant_name ?? null,
        t.name ?? null,
        t.pending,
        t.personal_finance_category?.primary ?? null,
        JSON.stringify(t),
      ],
    }),
  );
  const removals = removed.map(
    (r): Stmt => ({
      sql: `UPDATE transactions SET removed_at = ${NOW}, updated_at = ${NOW} WHERE plaid_transaction_id = ?1`,
      params: [r.transaction_id],
    }),
  );
  return [...upserts, ...removals];
}

function upsertHoldings(holdings: Holding[], securities: Security[]): Stmt[] {
  const secs = securities.map(
    (s): Stmt => ({
      sql: `INSERT INTO securities (plaid_security_id, name, ticker, type, close_price, close_price_as_of)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)
       ON CONFLICT (plaid_security_id) DO UPDATE SET
         name = excluded.name, ticker = excluded.ticker, type = excluded.type,
         close_price = excluded.close_price, close_price_as_of = excluded.close_price_as_of`,
      params: [s.security_id, s.name ?? null, s.ticker_symbol ?? null, s.type ?? null, s.close_price ?? null, s.close_price_as_of ?? null],
    }),
  );
  const pos = holdings.map(
    (h): Stmt => ({
      sql: `INSERT INTO holdings (account_id, plaid_security_id, as_of, quantity, cost_basis, institution_value)
       SELECT a.id, ?2, date('now'), ?3, ?4, ?5 FROM accounts a WHERE a.plaid_account_id = ?1
       ON CONFLICT (account_id, plaid_security_id, as_of) DO UPDATE SET
         quantity = excluded.quantity, cost_basis = excluded.cost_basis,
         institution_value = excluded.institution_value`,
      params: [h.account_id, h.security_id, h.quantity, h.cost_basis ?? null, h.institution_value],
    }),
  );
  return [...secs, ...pos];
}
