import { describe, expect, it } from 'vitest';
import { pruneLedger, storeInstitution, syncInstitution } from '../src/plaid/sync.js';
import { retentionCutoff } from '../src/crypto/fields.js';
import { createMember } from '../src/scripts/admin.js';
import { account, FakePlaid, testDb, testKey, txn } from './helpers.js';

async function synced(dates: string[]) {
  const db = await testDb();
  const kp = testKey();
  await createMember(db, 'jonathan', 'Jonathan', 'owner');
  const plaid = new FakePlaid();
  plaid.accounts = [account('acc-1', 'Everyday Checking', 'depository', 'checking', 4321.99)];
  plaid.pages.set('', { added: dates.map((d, i) => txn(`t${i}`, 'acc-1', d, 57.31 + i, 'Corner Bakery')), next_cursor: 'c1' });
  const inst = await storeInstitution(db, kp, { ownerMemberId: 'jonathan', itemId: 'item-1', accessToken: 'tok', products: ['transactions'] });
  await syncInstitution(db, plaid, kp, inst);
  return { db, kp };
}

const dump = async (db: Awaited<ReturnType<typeof testDb>>) => {
  const out: unknown[] = [];
  for (const t of ['accounts', 'balances', 'transactions', 'holdings']) out.push((await db.query(`SELECT * FROM ${t}`)).rows);
  return JSON.stringify(out);
};

describe('ledger at rest', () => {
  it('stores no amounts, merchants, account names, numbers or balances in the clear', async () => {
    const { db } = await synced(['2026-11-01', '2026-11-02']);
    const raw = await dump(db);
    for (const secret of ['Corner Bakery', 'CORNER BAKERY', '57.31', '58.31', 'Everyday Checking', '4321.99']) {
      expect(raw).not.toContain(secret);
    }
    expect(raw).toContain('2026-11-01'); // dates stay searchable
  });

  it('a ciphertext moved onto another row does not decrypt', async () => {
    const { db, kp } = await synced(['2026-11-01', '2026-11-02']);
    const { rows } = await db.query<{ plaid_transaction_id: string; sealed: string }>(`SELECT plaid_transaction_id, sealed FROM transactions ORDER BY plaid_transaction_id`);
    expect(() => kp.fields.open(rows[0]!.sealed, `transaction:${rows[1]!.plaid_transaction_id}`)).toThrow();
    expect(kp.fields.open<{ amount: number }>(rows[0]!.sealed, `transaction:${rows[0]!.plaid_transaction_id}`).amount).toBe(57.31);
  });

  it('keeps 13 months: older transactions are never stored, and aged rows are pruned', async () => {
    const now = new Date('2026-11-25T12:00:00Z');
    expect(retentionCutoff(now)).toBe('2025-10-25');
    const cutoff = retentionCutoff();
    const old = new Date(Date.parse(cutoff) - 86_400_000).toISOString().slice(0, 10);
    const { db } = await synced([old, cutoff, '2026-11-01']);
    const kept = await db.query<{ date: string }>(`SELECT date FROM transactions ORDER BY date`);
    expect(kept.rows.map((r) => r.date)).toEqual([cutoff, '2026-11-01'].sort());

    // More than 13 months later, everything synced today has aged out.
    await pruneLedger(db, new Date(Date.now() + 400 * 86_400_000));
    expect((await db.query(`SELECT 1 FROM transactions`)).rows).toEqual([]);
    expect((await db.query(`SELECT 1 FROM balances`)).rows).toEqual([]);
  });
});
