import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { getPlatformProxy } from 'wrangler';
import { d1Db, type D1Like, type Db } from '../src/db/index.js';
import { storeInstitution, syncInstitution } from '../src/plaid/sync.js';
import { createMember } from '../src/scripts/admin.js';
import { account, FakePlaid, testKey, txn } from './helpers.js';

/**
 * The same flows the other suites run on node:sqlite, against Cloudflare's real D1 engine
 * (Miniflare, local, no network), migrated by `wrangler d1 migrations apply` exactly as in
 * production. Catches anything node:sqlite accepts that D1 doesn't.
 */
let dir: string;
let proxy: Awaited<ReturnType<typeof getPlatformProxy<{ DB: D1Like }>>>;
let db: Db;

beforeAll(async () => {
  dir = mkdtempSync(path.join(tmpdir(), 'purser-d1-'));
  execFileSync('npx', ['wrangler', 'd1', 'migrations', 'apply', 'DB', '--local', '--persist-to', dir], {
    stdio: 'ignore',
    env: { ...process.env, CI: '1', WRANGLER_SEND_METRICS: 'false' },
  });
  proxy = await getPlatformProxy<{ DB: D1Like }>({ persist: { path: path.join(dir, 'v3') } });
  db = d1Db(proxy.env.DB);
}, 60_000);

afterAll(async () => {
  await proxy?.dispose();
  rmSync(dir, { recursive: true, force: true });
});

describe('on D1', () => {
  it('seals the access token, syncs in one batch, and decrypts only to call Plaid', async () => {
    const kp = testKey();
    await createMember(db, 'jonathan', 'Jonathan', 'owner');
    const plaid = new FakePlaid();
    plaid.accounts = [account('acc-1', 'Checking', 'depository', 'checking', 1000)];
    plaid.pages.set('', { added: [txn('t1', 'acc-1', '2026-11-01', 10, 'A'), txn('t2', 'acc-1', '2026-11-02', -20, 'B')], next_cursor: 'c1' });
    const inst = await storeInstitution(db, kp, { ownerMemberId: 'jonathan', itemId: 'item-1', accessToken: 'access-secret', products: ['transactions'] });

    const stored = await db.query(`SELECT * FROM institutions`);
    expect(JSON.stringify(stored.rows)).not.toContain('access-secret');

    const r = await syncInstitution(db, plaid, kp, inst);
    expect(r).toMatchObject({ status: 'ok', accounts: 1, added: 2 });
    expect(plaid.seenTokens).toEqual(['access-secret']);
    const { rows } = await db.query<{ n: number; cursor: string }>(
      `SELECT (SELECT count(*) FROM transactions) AS n, (SELECT transactions_cursor FROM institutions) AS cursor`,
    );
    expect(rows[0]).toEqual({ n: 2, cursor: 'c1' });
  });

  it('a failing statement rolls back the whole sync batch', async () => {
    await expect(
      db.batch([
        { sql: `UPDATE institutions SET transactions_cursor = 'should-not-stick'` },
        { sql: `INSERT INTO transactions (plaid_transaction_id, account_id, date, amount) VALUES ('x', 'no-such-account', '2026-11-01', 1)` },
      ]),
    ).rejects.toThrow();
    const { rows } = await db.query<{ c: string }>(`SELECT transactions_cursor AS c FROM institutions`);
    expect(rows[0]?.c).toBe('c1');
  });

  it('keeps the audit log append-only', async () => {
    await expect(db.query(`UPDATE audit_log SET outcome = 'ok'`)).rejects.toThrow(/append-only/);
    await expect(db.query(`DELETE FROM audit_log`)).rejects.toThrow(/append-only/);
  });
});
