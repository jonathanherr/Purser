import { describe, expect, it } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createApp } from '../src/http/app.js';
import { approvePairing } from '../src/http/oauth.js';
import { seedHousehold, testDb } from './helpers.js';

const BASE = 'https://vault.test';
const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';

async function setup() {
  const db = await testDb();
  const h = await seedHousehold(db);
  const app = createApp({ db, kp: h.kp, verifyWebhook: async () => false });
  const call = (path: string, init?: RequestInit) => app.fetch(new Request(`${BASE}${path}`, init));
  return { db, app, call };
}

const postJson = (body: unknown): RequestInit => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

async function register(call: Awaited<ReturnType<typeof setup>>['call']) {
  const res = await call('/register', postJson({ client_name: 'Claude', redirect_uris: [CALLBACK] }));
  expect(res.status).toBe(201);
  return ((await res.json()) as { client_id: string }).client_id;
}

/** Runs /authorize and returns the request handle and pairing code from the page. */
async function startSignIn(call: Awaited<ReturnType<typeof setup>>['call'], clientId: string) {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: CALLBACK,
    state: 'st8',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  const res = await call(`/authorize?${q}`);
  expect(res.status).toBe(200);
  const html = await res.text();
  const pairing = html.match(/class="code">([A-Z0-9-]+)</)![1]!;
  const req = html.match(/const id = "([^"]+)"/)![1]!;
  return { verifier, pairing, req };
}

async function token(call: Awaited<ReturnType<typeof setup>>['call'], fields: Record<string, string>) {
  return call('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', redirect_uri: CALLBACK, ...fields }).toString(),
  });
}

describe('OAuth for Claude connectors', () => {
  it('advertises itself from the MCP 401 and the well-known documents', async () => {
    const { call } = await setup();
    const res = await call('/mcp', postJson({}));
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain(`resource_metadata="${BASE}/.well-known/oauth-protected-resource"`);
    const pr = (await (await call('/.well-known/oauth-protected-resource')).json()) as { authorization_servers: string[] };
    expect(pr.authorization_servers).toEqual([BASE]);
    const as = (await (await call('/.well-known/oauth-authorization-server')).json()) as Record<string, unknown>;
    expect(as).toMatchObject({ token_endpoint: `${BASE}/token`, registration_endpoint: `${BASE}/register`, code_challenge_methods_supported: ['S256'] });
  });

  it('only registers Claude callback URLs', async () => {
    const { call } = await setup();
    const res = await call('/register', postJson({ redirect_uris: ['https://evil.example/cb'] }));
    expect(res.status).toBe(400);
  });

  it('pairs, approves and connects as the member with read-only tools', async () => {
    const { db, app, call } = await setup();
    const clientId = await register(call);
    const { verifier, pairing, req } = await startSignIn(call, clientId);

    // Nothing is issued before approval.
    expect(await (await call(`/authorize/poll?req=${req}`)).json()).toEqual({ status: 'pending' });
    await expect(approvePairing(db, 'ZZZZ-ZZZZ', 'jonathan')).resolves.toBe(false);
    await expect(approvePairing(db, pairing.toLowerCase().replace('-', ''), 'jonathan')).resolves.toBe(true);

    const poll = (await (await call(`/authorize/poll?req=${req}`)).json()) as { redirect: string };
    const redirect = new URL(poll.redirect);
    expect(redirect.origin + redirect.pathname).toBe(CALLBACK);
    expect(redirect.searchParams.get('state')).toBe('st8');
    const code = redirect.searchParams.get('code')!;
    // The code is handed out once.
    expect(await (await call(`/authorize/poll?req=${req}`)).json()).toEqual({ status: 'expired' });

    const good = await token(call, { code, client_id: clientId, code_verifier: verifier });
    expect(good.status).toBe(200);
    const { access_token } = (await good.json()) as { access_token: string };
    // A code works once.
    expect((await token(call, { code, client_id: clientId, code_verifier: verifier })).status).toBe(400);

    const client = new Client({ name: 'claude', version: '0.0.0' });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), {
        requestInit: { headers: { authorization: `Bearer ${access_token}` } },
        fetch: async (input, init) => app.fetch(new Request(input, init)),
      }),
    );
    const tools = (await client.listTools()).tools.map((t) => t.name);
    expect(tools).toContain('get_transactions');
    expect(tools).not.toContain('create_proposal');
    expect(tools).not.toContain('set_category');
    expect(tools).not.toContain('flag_item');
    await client.close();

    const { rows } = await db.query<{ acts_for: string }>(`SELECT acts_for FROM agent_clients WHERE id LIKE 'connector-%'`);
    expect(rows).toEqual([{ acts_for: 'jonathan' }]);
  });

  it('rejects a wrong PKCE verifier and burns the code', async () => {
    const { db, call } = await setup();
    const clientId = await register(call);
    const { verifier, pairing, req } = await startSignIn(call, clientId);
    await approvePairing(db, pairing, 'jonathan');
    const { redirect } = (await (await call(`/authorize/poll?req=${req}`)).json()) as { redirect: string };
    const code = new URL(redirect).searchParams.get('code')!;
    expect((await token(call, { code, client_id: clientId, code_verifier: 'x'.repeat(43) })).status).toBe(400);
    expect((await token(call, { code, client_id: clientId, code_verifier: verifier })).status).toBe(400);
  });

  it('refuses an unregistered redirect without redirecting', async () => {
    const { call } = await setup();
    const clientId = await register(call);
    const q = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'https://claude.com/api/mcp/auth_callback',
      code_challenge: 'abc',
      code_challenge_method: 'S256',
    });
    const res = await call(`/authorize?${q}`);
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
  });
});
