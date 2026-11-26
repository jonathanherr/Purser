import { describe, expect, it } from 'vitest';
import { createApp } from '../src/http/app.js';
import { createPasskeySetup } from '../src/http/passkeys.js';
import { FakePlaid, seedHousehold, testDb } from './helpers.js';
import { softAuthenticator } from './softkey.js';

const BASE = 'https://vault.test';

async function setup() {
  const db = await testDb();
  const h = await seedHousehold(db);
  const plaid = new FakePlaid();
  plaid.nextAccessToken = 'access-production-sofi';
  plaid.accounts = h.pj.accounts.slice(0, 1).map((a) => ({ ...a, account_id: 'sofi-acc-1', name: 'SoFi Checking' }));
  const linkCalls: unknown[] = [];
  const createLinkToken = plaid.createLinkToken.bind(plaid);
  plaid.createLinkToken = async (memberId: string, opts?: { webhook?: string; redirectUri?: string }) => {
    linkCalls.push({ memberId, ...opts });
    return createLinkToken();
  };
  const app = createApp({ db, kp: h.kp, plaid, plaidWebhookUrl: `${BASE}/plaid/webhook`, verifyWebhook: async () => false });
  const call = (path: string, init?: RequestInit) => app.fetch(new Request(`${BASE}${path}`, init));
  const post = async (path: string, body: unknown) => {
    const res = await call(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  };
  // Jonathan adds a passkey.
  const t = new URL(await createPasskeySetup(db, 'jonathan', BASE)).searchParams.get('t')!;
  const key = softAuthenticator();
  const o = await post('/passkey/setup/options', { t });
  expect((await post('/passkey/setup/verify', { t, response: key.register(o.body.challenge) })).body).toEqual({ ok: true });
  return { db, call, post, key, linkCalls };
}

describe('link an account page', () => {
  it('signs in with a passkey, starts Plaid Link and stores the exchanged Item for that member', async () => {
    const { db, call, post, key, linkCalls } = await setup();
    expect(await (await call('/link')).text()).toContain('Sign in with passkey');
    expect((await call('/plaid/oauth?oauth_state_id=x')).status).toBe(200);

    const start = await post('/link/start', {});
    // Nothing can be exchanged before the passkey checks out.
    expect((await post('/link/exchange', { sid: start.body.sid, public_token: 'public-x' })).status).toBe(400);

    const v = await post('/link/verify', { sid: start.body.sid, response: key.sign(start.body.options.challenge) });
    expect(v.body.linkToken).toBeTruthy();
    expect(linkCalls).toEqual([{ memberId: 'jonathan', webhook: `${BASE}/plaid/webhook`, redirectUri: `${BASE}/plaid/oauth` }]);

    const ex = await post('/link/exchange', { sid: start.body.sid, public_token: 'public-sofi', institution_name: 'SoFi', institution_id: 'ins_sofi' });
    expect(ex.body).toEqual({ ok: true, institution: 'SoFi' });
    // One Item per sign-in.
    expect((await post('/link/exchange', { sid: start.body.sid, public_token: 'public-again' })).status).toBe(400);

    const { rows } = await db.query<{ owner_member_id: string; name: string; access_token_ct: string }>(
      `SELECT owner_member_id, name, access_token_ct FROM institutions WHERE plaid_item_id = 'item-public-sofi'`,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ owner_member_id: 'jonathan', name: 'SoFi' });
    expect(rows[0]!.access_token_ct).not.toContain('access-production-sofi');
    const accts = await db.query(`SELECT 1 FROM accounts WHERE plaid_account_id = 'sofi-acc-1'`);
    expect(accts.rows).toHaveLength(1);
  });

  it('refuses a wrong passkey and a reused challenge', async () => {
    const { post, key } = await setup();
    const start = await post('/link/start', {});
    const stranger = softAuthenticator();
    expect((await post('/link/verify', { sid: start.body.sid, response: stranger.sign(start.body.options.challenge) })).status).toBe(400);
    expect((await post('/link/verify', { sid: start.body.sid, response: key.sign(start.body.options.challenge) })).status).toBe(400);
  });
});
