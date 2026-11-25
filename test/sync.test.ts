import { describe, expect, it } from 'vitest';
import { storeInstitution, syncInstitution } from '../src/plaid/sync.js';
import { createMember } from '../src/scripts/admin.js';
import { account, FakePlaid, testDb, testKey, txn } from './helpers.js';

async function setup() {
  const db = await testDb();
  const kp = testKey();
  await createMember(db, 'jonathan', 'Jonathan', 'owner');
  const plaid = new FakePlaid();
  plaid.accounts = [account('acc-1', 'Checking', 'depository', 'checking', 1000)];
  const inst = await storeInstitution(db, kp, { ownerMemberId: 'jonathan', itemId: 'item-1', accessToken: 'access-secret', products: ['transactions'] });
  return { db, kp, plaid, inst };
}

describe('sync', () => {
  it('stores the access token encrypted and decrypts it only to call Plaid', async () => {
    const { db, kp, plaid, inst } = await setup();
    const { rows } = await db.query<Record<string, string>>(`SELECT * FROM institutions`);
    expect(JSON.stringify(rows)).not.toContain('access-secret');
    await syncInstitution(db, plaid, kp, inst);
    expect(plaid.seenTokens).toEqual(['access-secret']);
  });

  it('applies added, modified and removed transactions across pages and saves the cursor', async () => {
    const { db, kp, plaid, inst } = await setup();
    plaid.pages.set('', { added: [txn('t1', 'acc-1', '2026-11-01', 10, 'A')], has_more: true, next_cursor: 'p2' });
    plaid.pages.set('p2', { added: [txn('t2', 'acc-1', '2026-11-02', 20, 'B')], has_more: false, next_cursor: 'c1' });
    const first = await syncInstitution(db, plaid, kp, inst);
    expect(first).toMatchObject({ status: 'ok', accounts: 1, added: 2 });

    plaid.pages.set('c1', {
      modified: [txn('t1', 'acc-1', '2026-11-01', 12.5, 'A')],
      removed: [{ transaction_id: 't2', account_id: 'acc-1' } as never],
      next_cursor: 'c2',
    });
    const second = await syncInstitution(db, plaid, kp, inst);
    expect(second).toMatchObject({ modified: 1, removed: 1 });

    const live = await db.query<{ plaid_transaction_id: string; amount: number }>(
      `SELECT plaid_transaction_id, amount FROM transactions WHERE removed_at IS NULL`,
    );
    expect(live.rows).toEqual([{ plaid_transaction_id: 't1', amount: 12.5 }]);
    const cursor = await db.query<{ transactions_cursor: string }>(`SELECT transactions_cursor FROM institutions`);
    expect(cursor.rows[0]!.transactions_cursor).toBe('c2');
  });

  it('marks an item for relinking when Plaid needs the user to log in again', async () => {
    const { db, kp, plaid, inst } = await setup();
    plaid.failWith = 'ITEM_LOGIN_REQUIRED';
    const r = await syncInstitution(db, plaid, kp, inst);
    expect(r.status).toBe('needs_relink');
    const { rows } = await db.query<{ status: string }>(`SELECT status FROM institutions`);
    expect(rows[0]!.status).toBe('needs_relink');
  });

  it('new accounts start private', async () => {
    const { db, kp, plaid, inst } = await setup();
    await syncInstitution(db, plaid, kp, inst);
    const { rows } = await db.query<{ visibility: string }>(`SELECT visibility FROM accounts`);
    expect(rows[0]!.visibility).toBe('private');
  });
});
