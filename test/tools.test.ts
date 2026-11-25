import { describe, expect, it } from 'vitest';
import { TOOLS, toolsFor, type ToolDef } from '../src/vault/tools.js';
import type { AgentClient } from '../src/vault/auth.js';
import type { Db } from '../src/db/index.js';
import { ciphers, seedHousehold, testDb } from './helpers.js';

const tool = (name: string) => TOOLS.find((t) => t.name === name)! as unknown as ToolDef;
const call = async (db: Db, agent: AgentClient, name: string, args: Record<string, unknown> = {}) => {
  const t = tool(name);
  const { z } = await import('zod');
  const parsed = z.object(t.input).parse(args);
  return (await t.run({ db, agent, fc: ciphers.get(db)! }, parsed as never)).data as any;
};
const NOV = { start_date: '2026-11-01', end_date: '2026-11-30' };

describe('household visibility', () => {
  it("Jonathan's agent sees his accounts in detail and the partner's card as totals only", async () => {
    const db = await testDb();
    const { agentToken } = await seedHousehold(db);
    const { agent } = await agentToken('watchdog', 'jonathan');

    const accounts = await call(db, agent, 'list_accounts');
    const byName = Object.fromEntries(accounts.map((a: any) => [a.name, a]));
    expect(Object.keys(byName).sort()).toEqual(['Brokerage', 'Joint checking', 'Partner card', 'Savings']);
    expect(byName['Partner card'].detail_visible).toBe(false);
    expect(byName['Savings'].detail_visible).toBe(true);

    const txns = await call(db, agent, 'get_transactions', NOV);
    const merchants = txns.map((t: any) => t.untrusted.merchant_name).sort();
    expect(merchants).toEqual(['Netflix', 'Payroll', 'Transfer out', 'Whole Foods']);

    // Totals include the partner's private card (Trader Joes, 120) but never the hidden account.
    const summary = await call(db, agent, 'get_spending_summary', NOV);
    const groceries = summary.find((r: any) => r.category === 'groceries');
    expect(groceries.outflow).toBe(202.15);
    expect(summary.reduce((s: number, r: any) => s + r.transactions, 0)).toBe(5);
  });

  it("the partner's agent never sees Jonathan's private savings transactions", async () => {
    const db = await testDb();
    const { agentToken } = await seedHousehold(db);
    const { agent } = await agentToken('watchdog', 'partner');
    const merchants = (await call(db, agent, 'get_transactions', NOV)).map((t: any) => t.untrusted.merchant_name).sort();
    expect(merchants).toEqual(['Gift shop', 'Netflix', 'Payroll', 'Trader Joes', 'Whole Foods']);
  });

  it('a household agent sees shared detail only, and no hidden accounts at all', async () => {
    const db = await testDb();
    const { agentToken } = await seedHousehold(db);
    const { agent } = await agentToken('watchdog', 'household');
    const names = (await call(db, agent, 'list_accounts')).map((a: any) => a.name).sort();
    expect(names).toEqual(['Brokerage', 'Joint checking', 'Partner card', 'Savings']);
    const merchants = (await call(db, agent, 'get_transactions', NOV)).map((t: any) => t.untrusted.merchant_name).sort();
    expect(merchants).toEqual(['Netflix', 'Payroll', 'Whole Foods']);
    const holdings = await call(db, agent, 'get_holdings');
    expect(holdings).toMatchObject([{ ticker: 'VTI', quantity: 100, market_value: 29000 }]);
  });
});

describe('tool surface', () => {
  it('wraps merchant text as untrusted and never returns raw Plaid payloads', async () => {
    const db = await testDb();
    const { agentToken } = await seedHousehold(db);
    const { agent } = await agentToken('categorizer', 'jonathan');
    const [t] = await call(db, agent, 'get_transactions', { ...NOV, limit: 1 });
    expect(t.untrusted).toHaveProperty('merchant_name');
    expect(t).not.toHaveProperty('merchant_name');
    expect(t).not.toHaveProperty('raw');
  });

  it('exposes only the tools an agent is scoped for, and none that execute anything', async () => {
    const db = await testDb();
    const { agentToken } = await seedHousehold(db);
    const { agent } = await agentToken('categorizer', 'household');
    expect(toolsFor(agent).map((t) => t.name).sort()).toEqual(
      ['flag_item', 'get_spending_summary', 'get_transactions', 'list_categories', 'set_category'].sort(),
    );
    expect(TOOLS.map((t) => t.name).some((n) => /execute|transfer|trade|token/.test(n))).toBe(false);
  });

  it('set_category works on visible transactions and refuses hidden ones', async () => {
    const db = await testDb();
    const { agentToken } = await seedHousehold(db);
    const { agent } = await agentToken('categorizer', 'jonathan');
    const ids = Object.fromEntries((await db.query<{ plaid_transaction_id: string; id: string }>(`SELECT plaid_transaction_id, id FROM transactions`)).rows.map((r) => [r.plaid_transaction_id, r.id]));
    expect(await call(db, agent, 'set_category', { transaction_id: ids.t4, category_id: 'transfers' })).toEqual({ updated: true });
    expect((await call(db, agent, 'set_category', { transaction_id: ids.t6, category_id: 'shopping' })).updated).toBe(false);
  });

  it('a person-set category is not overwritten by an agent', async () => {
    const db = await testDb();
    const { agentToken } = await seedHousehold(db);
    const { agent } = await agentToken('categorizer', 'jonathan');
    const { rows } = await db.query<{ id: string }>(`UPDATE transactions SET category_source = 'member' WHERE plaid_transaction_id = 't1' RETURNING id`);
    expect((await call(db, agent, 'set_category', { transaction_id: rows[0]!.id, category_id: 'dining' })).updated).toBe(false);
  });

  it('budget status reports target, spent and a projection', async () => {
    const db = await testDb();
    const { agentToken } = await seedHousehold(db);
    const { agent } = await agentToken('budget-keeper', 'jonathan');
    const [g] = await call(db, agent, 'get_budget_status', { month: '2026-11' });
    expect(g).toMatchObject({ category_id: 'groceries', target: 600, spent: 202.15 });
    expect(g.projected).toBeGreaterThanOrEqual(202.15);
  });

  it('caps result size', async () => {
    const db = await testDb();
    const { agentToken } = await seedHousehold(db);
    const { agent } = await agentToken('watchdog', 'jonathan');
    await expect(call(db, agent, 'get_transactions', { ...NOV, limit: 10_000 })).rejects.toThrow();
  });
});
