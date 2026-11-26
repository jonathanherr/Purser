import { describe, expect, it } from 'vitest';
import { createHash, createSign, generateKeyPairSync, randomBytes } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { createApp } from '../src/http/app.js';
import { createPasskeySetup } from '../src/http/passkeys.js';
import { seedHousehold, testDb } from './helpers.js';

const BASE = 'https://vault.test';
const RP = 'vault.test';
const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';

const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');
const sha = (b: Uint8Array | Buffer | string) => createHash('sha256').update(b).digest();
const u32 = (n: number) => Buffer.from([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);

/** A software passkey: enough of an authenticator to register and sign like a phone would. */
function softAuthenticator() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = randomBytes(16);
  let counter = 0;
  const cose = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, new Uint8Array(Buffer.from(jwk.x!, 'base64url'))],
      [-3, new Uint8Array(Buffer.from(jwk.y!, 'base64url'))],
    ]),
  );
  const clientData = (type: string, challenge: string, origin = BASE) =>
    Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  return {
    id: b64u(credId),
    register(challenge: string, origin = BASE) {
      const authData = Buffer.concat([sha(RP), Buffer.from([0x45]), u32(counter), Buffer.alloc(16), Buffer.from([0, credId.length]), credId, Buffer.from(cose)]);
      const att = isoCBOR.encode(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', new Uint8Array(authData)]]) as never);
      return {
        id: b64u(credId),
        rawId: b64u(credId),
        type: 'public-key',
        clientExtensionResults: {},
        response: { clientDataJSON: b64u(clientData('webauthn.create', challenge, origin)), attestationObject: b64u(att), transports: ['internal'] },
      };
    },
    sign(challenge: string, opts: { uv?: boolean; origin?: string } = {}) {
      counter += 1;
      const authData = Buffer.concat([sha(RP), Buffer.from([opts.uv === false ? 0x01 : 0x05]), u32(counter)]);
      const cd = clientData('webauthn.get', challenge, opts.origin);
      const signature = createSign('SHA256').update(Buffer.concat([authData, sha(cd)])).sign(privateKey);
      return {
        id: b64u(credId),
        rawId: b64u(credId),
        type: 'public-key',
        clientExtensionResults: {},
        response: { clientDataJSON: b64u(cd), authenticatorData: b64u(authData), signature: b64u(signature), userHandle: b64u(Buffer.from('jonathan')) },
      };
    },
  };
}

async function setup() {
  const db = await testDb();
  const h = await seedHousehold(db);
  const app = createApp({ db, kp: h.kp, verifyWebhook: async () => false });
  const call = (path: string, init?: RequestInit) => app.fetch(new Request(`${BASE}${path}`, init));
  const post = async (path: string, body: unknown) => {
    const res = await call(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  };
  return { db, call, post };
}

type Env = Awaited<ReturnType<typeof setup>>;

async function addPasskey(env: Env, member = 'jonathan') {
  const link = new URL(await createPasskeySetup(env.db, member, BASE));
  const t = link.searchParams.get('t')!;
  expect((await env.call(link.pathname + link.search)).status).toBe(200);
  const key = softAuthenticator();
  const opts = await env.post('/passkey/setup/options', { t });
  expect(opts.status).toBe(200);
  expect(opts.body.authenticatorSelection).toMatchObject({ residentKey: 'required', userVerification: 'required' });
  const res = await env.post('/passkey/setup/verify', { t, response: key.register(opts.body.challenge) });
  expect(res.body).toEqual({ ok: true });
  return { key, t };
}

async function startSignIn(env: Env) {
  const reg = await env.post('/register', { client_name: 'Claude', redirect_uris: [CALLBACK] });
  const verifier = randomBytes(32).toString('base64url');
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: reg.body.client_id,
    redirect_uri: CALLBACK,
    state: 'st8',
    code_challenge: b64u(sha(verifier)),
    code_challenge_method: 'S256',
  });
  const html = await (await env.call(`/authorize?${q}`)).text();
  expect(html).toContain('Approve with passkey');
  return { clientId: reg.body.client_id as string, verifier, req: html.match(/const id = "([^"]+)"/)![1]! };
}

describe('passkeys', () => {
  it('approves a connector sign-in on the page in one visit', async () => {
    const env = await setup();
    const { key } = await addPasskey(env);
    const { clientId, verifier, req } = await startSignIn(env);

    const opts = await env.post('/authorize/passkey/options', { req });
    expect(opts.body.userVerification).toBe('required');
    const res = await env.post('/authorize/passkey/verify', { req, response: key.sign(opts.body.challenge) });
    const redirect = new URL(res.body.redirect);
    expect(redirect.origin + redirect.pathname).toBe(CALLBACK);
    expect(redirect.searchParams.get('state')).toBe('st8');

    // The page's poll can't hand out a second code.
    expect((await (await env.call(`/authorize/poll?req=${req}`)).json())).toEqual({ status: 'expired' });

    const tok = await env.call('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        redirect_uri: CALLBACK,
        code: redirect.searchParams.get('code')!,
        client_id: clientId,
        code_verifier: verifier,
      }).toString(),
    });
    expect(tok.status).toBe(200);
    const { rows } = await env.db.query<{ acts_for: string }>(`SELECT acts_for FROM agent_clients WHERE id LIKE 'connector-%'`);
    expect(rows).toEqual([{ acts_for: 'jonathan' }]);
  });

  it('uses a setup link once', async () => {
    const env = await setup();
    const { t } = await addPasskey(env);
    expect((await env.post('/passkey/setup/options', { t })).status).toBe(400);
    expect((await env.call(`/passkey/setup?t=${t}`)).status).toBe(400);
  });

  it('rejects a replayed challenge, a wrong origin, no user verification and unknown passkeys', async () => {
    const env = await setup();
    const { key } = await addPasskey(env);
    const { req } = await startSignIn(env);

    let o = await env.post('/authorize/passkey/options', { req });
    expect((await env.post('/authorize/passkey/verify', { req, response: key.sign(o.body.challenge, { origin: 'https://evil.example' }) })).status).toBe(400);
    // That attempt used up the challenge.
    expect((await env.post('/authorize/passkey/verify', { req, response: key.sign(o.body.challenge) })).status).toBe(400);

    o = await env.post('/authorize/passkey/options', { req });
    expect((await env.post('/authorize/passkey/verify', { req, response: key.sign(o.body.challenge, { uv: false }) })).status).toBe(400);

    o = await env.post('/authorize/passkey/options', { req });
    const stranger = softAuthenticator();
    expect((await env.post('/authorize/passkey/verify', { req, response: stranger.sign(o.body.challenge) })).status).toBe(400);

    const { rows } = await env.db.query(`SELECT 1 FROM oauth_requests WHERE id = ?1 AND approved_at IS NULL`, [req]);
    expect(rows).toHaveLength(1);
  });
});
