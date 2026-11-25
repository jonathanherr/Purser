import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createApp } from '../src/http/app.js';
import { seedHousehold, testDb } from './helpers.js';

async function setup() {
  const db = await testDb();
  const h = await seedHousehold(db);
  const app = createApp({ db, kp: h.kp, verifyWebhook: async () => false });
  return { db, app, ...h };
}

async function connect(app: ReturnType<typeof createApp>, token: string) {
  const client = new Client({ name: 'test-agent', version: '0.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL('http://vault.test/mcp'), {
    requestInit: { headers: { authorization: `Bearer ${token}` } },
    fetch: async (input, init) => app.fetch(new Request(input, init)),
  });
  await client.connect(transport);
  return client;
}

describe('MCP over HTTP', () => {
  it('rejects requests without a valid agent token', async () => {
    const { app, db } = await setup();
    const res = await app.fetch(new Request('http://vault.test/mcp', { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } }));
    expect(res.status).toBe(401);
    const { rows } = await db.query<{ outcome: string }>(`SELECT outcome FROM audit_log WHERE action = 'mcp.auth'`);
    expect(rows).toEqual([{ outcome: 'denied' }]);
  });

  it('an agent lists only its own tools and can call them; every call is audited', async () => {
    const { app, db, agentToken } = await setup();
    const { token } = await agentToken('budget-keeper', 'jonathan');
    const client = await connect(app, token);

    const tools = (await client.listTools()).tools.map((t) => t.name).sort();
    expect(tools).toEqual(['flag_item', 'get_budget_status', 'get_spending_summary', 'get_transactions', 'list_categories']);

    const res = await client.callTool({ name: 'get_budget_status', arguments: { month: '2026-11' } });
    const data = JSON.parse((res.content as { text: string }[])[0]!.text);
    expect(data[0]).toMatchObject({ category_id: 'groceries', target: 600 });

    const denied = await client.callTool({ name: 'create_proposal', arguments: {} }).catch((e) => e);
    expect(String((denied as { content?: { text: string }[] }).content?.[0]?.text ?? denied)).toMatch(/not found|Unknown tool|-32602/i);

    const { rows } = await db.query<{ action: string; outcome: string }>(
      `SELECT action, outcome FROM audit_log WHERE actor_type = 'agent' AND action LIKE 'tool.%'`,
    );
    expect(rows).toEqual([{ action: 'tool.get_budget_status', outcome: 'ok' }]);
    await client.close();
  });

  it('a revoked agent is locked out', async () => {
    const { app, db, agentToken } = await setup();
    const { token, agent } = await agentToken('watchdog', 'household');
    await db.query(`UPDATE agent_clients SET revoked_at = now() WHERE id = $1`, [agent.id]);
    await expect(connect(app, token)).rejects.toThrow();
  });
});

describe('people API', () => {
  it('lists pending proposals with the vault-rendered summary, and takes a decision', async () => {
    const { app, agentToken, ids, jonathanToken } = await setup();
    const { token } = await agentToken('planner', 'jonathan');
    const client = await connect(app, token);
    const created = await client.callTool({
      name: 'create_proposal',
      arguments: { proposal: { kind: 'trade', account_id: ids['acc-broker-3333'], side: 'buy', ticker: 'VTI', notional_usd: 250 }, reason: 'Idle cash' },
    });
    const { id, status } = JSON.parse((created.content as { text: string }[])[0]!.text);
    expect(status).toBe('pending');

    const auth = { authorization: `Bearer ${jonathanToken}` };
    const list = await (await app.fetch(new Request('http://vault.test/me/proposals', { headers: auth }))).json();
    expect(list[0]).toMatchObject({ id, summary: 'Buy $250.00 of VTI in Brokerage (…3333)', agent_reason: 'Idle cash' });

    const res = await app.fetch(new Request(`http://vault.test/me/proposals/${id}/decision`, {
      method: 'POST', headers: { ...auth, 'content-type': 'application/json' }, body: JSON.stringify({ decision: 'approve' }),
    }));
    expect(await res.json()).toMatchObject({ ok: true, status: 'approved' });
    await client.close();
  });

  it('only the owner can change an account visibility', async () => {
    const { app, ids, partnerToken, jonathanToken } = await setup();
    const patch = (token: string) => app.fetch(new Request(`http://vault.test/me/accounts/${ids['acc-savings-2222']}`, {
      method: 'PATCH', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ visibility: 'shared' }),
    }));
    expect((await patch(partnerToken)).status).toBe(403);
    expect((await patch(jonathanToken)).status).toBe(200);
  });

  it('rejects webhooks that fail verification', async () => {
    const { app } = await setup();
    const res = await app.fetch(new Request('http://vault.test/plaid/webhook', { method: 'POST', body: '{"webhook_type":"TRANSACTIONS"}' }));
    expect(res.status).toBe(401);
  });
});
