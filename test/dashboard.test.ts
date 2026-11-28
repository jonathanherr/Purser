import { describe, expect, it } from 'vitest';
import { createApp } from '../src/http/app.js';
import { createPasskeySetup } from '../src/http/passkeys.js';
import { FakePlaid, seedHousehold, testDb } from './helpers.js';
import { softAuthenticator } from './softkey.js';

const BASE = 'https://vault.test';

async function setup() {
  const db = await testDb();
  const h = await seedHousehold(db);
  const plaid = h.pj as FakePlaid;
  const linkCalls: Record<string, unknown>[] = [];
  const original = plaid.createLinkToken.bind(plaid);
  plaid.createLinkToken = async (memberId: string, opts?: { webhook?: string; redirectUri?: string; accessToken?: string }) => {
    linkCalls.push({ memberId, ...opts });
    return original();
  };
  const app = createApp({ db, kp: h.kp, plaid, plaidEnv: 'production', plaidWebhookUrl: `${BASE}/plaid/webhook`, verifyWebhook: async () => false });
  let cookie = '';
  const call = async (path: string, body?: unknown, headers: Record<string, string> = { 'x-purser': '1' }) => {
    const res = await app.fetch(
      new Request(`${BASE}${path}`, {
        method: body === undefined ? 'GET' : 'POST',
        headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}), ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    );
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0]!;
    const isJson = res.headers.get("content-type")?.includes("json");
    return { status: res.status, set, body: (isJson ? await res.json() : await res.text()) as any };
  };
  const addKey = async (member: string) => {
    const t = new URL(await createPasskeySetup(db, member, BASE)).searchParams.get('t')!;
    const key = softAuthenticator();
    const o = await call('/passkey/setup/options', { t });
    await call('/passkey/setup/verify', { t, response: key.register(o.body.challenge) });
    return key;
  };
  const signIn = async (key: ReturnType<typeof softAuthenticator>) => {
    const o = await call('/app/api/login/options', {});
    return call('/app/api/login/verify', { sid: o.body.sid, response: key.sign(o.body.options.challenge) });
  };
  return { db, h, call, addKey, signIn, linkCalls, plaid, signOutLocal: () => (cookie = '') };
}

describe('dashboard', () => {
  it('serves the shell, and the API needs a passkey session', async () => {
    const { call } = await setup();
    expect(await (await call('/app')).body).toContain('Sign in with passkey');
    expect((await call('/plaid/oauth?oauth_state_id=x')).status).toBe(200);
    expect((await call('/link')).status).toBe(302);
    expect((await call('/app/api/connections')).status).toBe(401);
  });

  it('signs in with a passkey and sets a hardened session cookie', async () => {
    const { call, addKey, signIn } = await setup();
    const key = await addKey('jonathan');
    const res = await signIn(key);
    expect(res.body).toEqual({ ok: true });
    expect(res.set).toMatch(/^__Host-purser_session=pss_/);
    expect(res.set).toMatch(/HttpOnly/i);
    expect(res.set).toMatch(/Secure/i);
    expect(res.set).toMatch(/SameSite=Lax/i);
    expect((await call('/app/api/me')).body).toEqual({ member: { id: 'jonathan', name: 'Jonathan' } });
    await call('/app/api/logout', {});
    expect((await call('/app/api/me')).status).toBe(401);
  });

  it('refuses POSTs without the X-Purser header, and reused or foreign passkey challenges', async () => {
    const { call, addKey } = await setup();
    const key = await addKey('jonathan');
    expect((await call('/app/api/login/options', {}, {})).status).toBe(403);
    const o = await call('/app/api/login/options', {});
    const stranger = softAuthenticator();
    expect((await call('/app/api/login/verify', { sid: o.body.sid, response: stranger.sign(o.body.options.challenge) })).status).toBe(400);
    expect((await call('/app/api/login/verify', { sid: o.body.sid, response: key.sign(o.body.options.challenge) })).status).toBe(400);
  });

  it('lists household connections with status, and only owners can repair or sync', async () => {
    const { db, h, call, addKey, signIn, linkCalls } = await setup();
    await db.query(`UPDATE institutions SET status = 'needs_relink', last_error = 'ITEM_LOGIN_REQUIRED' WHERE id = ?1`, [h.jInst]);
    await signIn(await addKey('jonathan'));
    const d = (await call('/app/api/connections')).body;
    expect(d.plaid).toMatchObject({ configured: true, env: 'production', itemsUsed: 2, itemLimit: 10 });
    expect(d.connections).toHaveLength(2);
    const mine = d.connections.find((c: any) => c.mine);
    expect(mine).toMatchObject({ status: 'needs_relink', error: 'ITEM_LOGIN_REQUIRED', accounts: 3 });
    const theirs = d.connections.find((c: any) => !c.mine);
    expect(theirs).toMatchObject({ owner: 'Partner', mine: false });
    // No balances, names of accounts or transactions in this view.
    expect(JSON.stringify(d)).not.toMatch(/Joint checking|Partner card|5200/);

    // Repair uses Plaid update mode with the connection's own access token.
    const fix = await call('/app/api/plaid/link-token', { institutionId: h.jInst });
    expect(fix.body.linkToken).toBeTruthy();
    expect(linkCalls.at(-1)).toMatchObject({ memberId: 'jonathan', accessToken: 'access-j', redirectUri: `${BASE}/plaid/oauth` });
    expect((await call('/app/api/plaid/link-token', { institutionId: theirs.id })).status).toBe(403);
    expect((await call('/app/api/plaid/sync', { institutionId: theirs.id })).status).toBe(403);

    const synced = await call('/app/api/plaid/sync', { institutionId: h.jInst });
    expect(synced.body.status).toBe('ok');
  });

  it('links a new account for the signed-in member and records Link errors', async () => {
    const { db, call, addKey, signIn, linkCalls } = await setup();
    await signIn(await addKey('partner'));
    const lt = await call('/app/api/plaid/link-token', {});
    expect(lt.body.linkToken).toBeTruthy();
    expect(linkCalls.at(-1)).toMatchObject({ memberId: 'partner', accessToken: undefined });

    await call('/app/api/plaid/event', { event: 'ERROR', error_code: 'INVALID_CREDENTIALS', institution_name: 'SoFi' });
    const d = (await call('/app/api/connections')).body;
    expect(d.problems[0]).toMatchObject({ error_code: 'INVALID_CREDENTIALS', institution_name: 'SoFi' });

    const ex = await call('/app/api/plaid/exchange', { public_token: 'public-sofi', institution_name: 'SoFi' });
    expect(ex.body.ok).toBe(true);
    const { rows } = await db.query<{ owner_member_id: string; name: string }>(`SELECT owner_member_id, name FROM institutions WHERE plaid_item_id = 'item-public-sofi'`);
    expect(rows).toEqual([{ owner_member_id: 'partner', name: 'SoFi' }]);
  });
});
