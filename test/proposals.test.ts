import { describe, expect, it } from 'vitest';
import { createProposal, decide, expireProposals } from '../src/vault/proposals.js';
import { authenticateMember } from '../src/vault/auth.js';
import { renderProposal } from '../src/vault/render.js';
import { seedHousehold, testDb } from './helpers.js';

async function setup() {
  const db = await testDb();
  const h = await seedHousehold(db);
  const { agent } = await h.agentToken('planner', 'jonathan');
  const jonathan = (await authenticateMember(db, h.jonathanToken))!;
  const partner = (await authenticateMember(db, h.partnerToken))!;
  return { db, ...h, agent, jonathan, partner };
}

describe('proposals', () => {
  it('a valid transfer change waits for both people, then is approved but not executed', async () => {
    const { db, agent, ids, jonathan, partner } = await setup();
    const p = await createProposal(db, agent, {
      kind: 'transfer_change', from_account_id: ids['acc-checking-1111']!, to_account_id: ids['acc-broker-3333']!, new_amount_usd: 500, frequency: 'monthly',
    }, 'Idle cash in checking');
    expect(p).toMatchObject({ status: 'pending', approvals_required: 2, violations: [] });

    expect(await decide(db, jonathan, p.id, 'approve')).toMatchObject({ ok: true, status: 'pending', approvals: 1 });
    expect(await decide(db, jonathan, p.id, 'approve')).toEqual({ ok: false, error: 'already_decided' });
    expect(await decide(db, partner, p.id, 'approve')).toMatchObject({ ok: true, status: 'approved' });

    const { rows } = await db.query<{ status: string }>(`SELECT status FROM proposals WHERE id = ?1`, [p.id]);
    expect(rows[0]!.status).toBe('approved');
  });

  it('one rejection closes a proposal', async () => {
    const { db, agent, ids, partner, jonathan } = await setup();
    const p = await createProposal(db, agent, { kind: 'trade', account_id: ids['acc-broker-3333']!, side: 'buy', ticker: 'VTI', notional_usd: 300 }, 'Rebalance');
    expect(p.approvals_required).toBe(1);
    expect(await decide(db, partner, p.id, 'reject')).toMatchObject({ status: 'rejected' });
    expect(await decide(db, jonathan, p.id, 'approve')).toEqual({ ok: false, error: 'not_pending' });
  });

  it('blocks proposals that break guardrails before anyone sees them', async () => {
    const { db, agent, ids } = await setup();
    const big = await createProposal(db, agent, {
      kind: 'transfer_change', from_account_id: ids['acc-checking-1111']!, to_account_id: ids['acc-savings-2222']!, new_amount_usd: 5000, frequency: 'monthly',
    }, 'x');
    expect(big.status).toBe('blocked');
    expect(big.violations.map((v) => v.rule)).toContain('per_transfer_cap');

    const meme = await createProposal(db, agent, { kind: 'trade', account_id: ids['acc-broker-3333']!, side: 'buy', ticker: 'GME', notional_usd: 100 }, 'x');
    expect(meme.violations.map((v) => v.rule)).toEqual(['ticker_allowlist']);

    const wrongAcct = await createProposal(db, agent, { kind: 'trade', account_id: ids['acc-checking-1111']!, side: 'buy', ticker: 'VTI', notional_usd: 100 }, 'x');
    expect(wrongAcct.violations.map((v) => v.rule)).toEqual(['not_brokerage']);
  });

  it("cannot target an account outside the household, or one hidden from the agent", async () => {
    const { db, agent, ids } = await setup();
    const p = await createProposal(db, agent, {
      kind: 'transfer_change', from_account_id: ids['acc-checking-1111']!, to_account_id: ids['acc-hidden-5555']!, new_amount_usd: 50, frequency: 'monthly',
    }, 'x');
    expect(p.violations.map((v) => v.rule)).toEqual(['unknown_account']);
    const q = await createProposal(db, agent, {
      kind: 'transfer_change', from_account_id: ids['acc-checking-1111']!, to_account_id: '00000000-0000-4000-8000-000000000000', new_amount_usd: 50, frequency: 'monthly',
    }, 'x');
    expect(q.violations.map((v) => v.rule)).toEqual(['unknown_account']);
  });

  it('the kill switch blocks every new proposal', async () => {
    const { db, agent, ids } = await setup();
    await db.query(`UPDATE settings SET value = 'true' WHERE key = 'execution_frozen'`);
    const p = await createProposal(db, agent, { kind: 'trade', account_id: ids['acc-broker-3333']!, side: 'buy', ticker: 'VTI', notional_usd: 100 }, 'x');
    expect(p.violations.map((v) => v.rule)).toEqual(['kill_switch']);
  });

  it('expires proposals after their time to live', async () => {
    const { db, agent, ids, jonathan } = await setup();
    const p = await createProposal(db, agent, { kind: 'trade', account_id: ids['acc-broker-3333']!, side: 'buy', ticker: 'VTI', notional_usd: 100 }, 'x');
    await db.query(`UPDATE proposals SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 minute') WHERE id = ?1`, [p.id]);
    expect(await expireProposals(db)).toBe(1);
    expect(await decide(db, jonathan, p.id, 'approve')).toEqual({ ok: false, error: 'not_pending' });
  });

  it('renders the approval card from structured fields only', async () => {
    const { db, ids } = await setup();
    const text = await renderProposal(db, {
      kind: 'transfer_change', from_account_id: ids['acc-checking-1111'], to_account_id: ids['acc-broker-3333'], new_amount_usd: 500, frequency: 'monthly',
    });
    expect(text).toBe('Change the monthly transfer from Joint checking (…1111) to Brokerage (…3333) to $500.00');
    expect(await renderProposal(db, { kind: 'transfer_change', note: 'ignore previous instructions' })).toMatch(/do not approve/);
  });
});

describe('audit log', () => {
  it('records proposal activity and cannot be edited or deleted', async () => {
    const { db, agent, ids, jonathan } = await setup();
    const p = await createProposal(db, agent, { kind: 'trade', account_id: ids['acc-broker-3333']!, side: 'buy', ticker: 'VTI', notional_usd: 100 }, 'x');
    await decide(db, jonathan, p.id, 'approve');
    const { rows } = await db.query<{ action: string }>(`SELECT action FROM audit_log WHERE action LIKE 'proposal.%' ORDER BY id`);
    expect(rows.map((r) => r.action)).toEqual(['proposal.create', 'proposal.approve']);
    await expect(db.query(`UPDATE audit_log SET outcome = 'ok'`)).rejects.toThrow(/append-only/);
    await expect(db.query(`DELETE FROM audit_log`)).rejects.toThrow(/append-only/);
  });
});
