import { Hono, type Context } from 'hono';
import { z } from 'zod';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { json, NOW, type Db } from '../db/index.js';
import { hashToken, newToken } from '../crypto/tokens.js';
import { audit } from '../vault/audit.js';

/**
 * Passkeys for members (migrations/0004_passkeys.sql). A member adds a passkey once from a
 * one-time setup link, then approves each Claude connector sign-in on the sign-in page itself.
 */

const SETUP_HOURS = 24;

const rpId = (c: Context) => new URL(c.req.url).hostname;
const origin = (c: Context) => new URL(c.req.url).origin;
const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

/** Creates a one-time link that lets a member add a passkey. For the admin CLI, never over HTTP. */
export async function createPasskeySetup(db: Db, memberId: string, baseUrl: string): Promise<string> {
  const { rows } = await db.query(`SELECT 1 FROM members WHERE id = ?1`, [memberId]);
  if (!rows.length) throw new Error(`no member ${memberId}`);
  const token = newToken('pks');
  await db.query(
    `INSERT INTO passkey_setups (token_hash, member_id, expires_at)
     VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?3))`,
    [hashToken(token), memberId, `+${SETUP_HOURS} hours`],
  );
  await audit(db, { actor: { type: 'system', id: 'admin' }, action: 'passkey.setup_link', outcome: 'ok', detail: { memberId } });
  return `${new URL(baseUrl).origin}/passkey/setup?t=${encodeURIComponent(token)}`;
}

type SetupRow = { member_id: string; display_name: string; challenge: string | null };

async function openSetup(db: Db, token: string): Promise<SetupRow | undefined> {
  const { rows } = await db.query<SetupRow>(
    `SELECT s.member_id, m.display_name, s.challenge FROM passkey_setups s JOIN members m ON m.id = s.member_id
      WHERE s.token_hash = ?1 AND s.used_at IS NULL AND s.expires_at > ${NOW}`,
    [hashToken(token)],
  );
  return rows[0];
}

type PasskeyRow = { credential_id: string; member_id: string; public_key: string; counter: number; transports: string | null };

/** Base64url helpers and WebAuthn JSON conversion for the browser, shared by both pages. */
export const BROWSER_HELPERS = `
  const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (ch) => ch.charCodeAt(0));
  const post = async (path, body) => { const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return r.json(); };
  const passkeysWork = () => !!(window.PublicKeyCredential && navigator.credentials);
`;

/**
 * Routes: the setup page and its two calls, plus the two calls the sign-in page makes to
 * approve with a passkey. `approve` marks the sign-in approved for the member and returns
 * the redirect back to Claude (or null if the sign-in can no longer be approved).
 */
export function passkeyRoutes(db: Db, approve: (requestId: string, memberId: string) => Promise<string | null>) {
  const app = new Hono();

  // ---- Adding a passkey ----
  app.get('/passkey/setup', async (c) => {
    const s = await openSetup(db, c.req.query('t') ?? '');
    if (!s) return c.html(page('Link expired', '<p>This setup link has expired or was already used. Ask for a new one.</p>'), 400);
    return c.html(
      page(
        'Add a passkey',
        `<p>Hi ${esc(s.display_name)}. Add a passkey on this device so you can approve Claude's access to your Purser vault
         with Face ID, Touch ID or your device PIN. Nothing secret leaves your device.</p>
         <p><button id="go" type="button">Create passkey</button></p>
         <p id="status" class="muted">This link works once.</p>
         <script>
           ${BROWSER_HELPERS}
           const t = new URLSearchParams(location.search).get('t');
           const status = (m) => { document.getElementById('status').textContent = m; };
           if (!passkeysWork()) status('This browser cannot create passkeys. Try Safari or Chrome.');
           document.getElementById('go').addEventListener('click', async () => {
             try {
               const o = await post('/passkey/setup/options', { t });
               if (o.error) return status(o.error);
               o.challenge = dec(o.challenge);
               o.user.id = dec(o.user.id);
               o.excludeCredentials = (o.excludeCredentials || []).map((x) => ({ ...x, id: dec(x.id) }));
               const cred = await navigator.credentials.create({ publicKey: o });
               const res = await post('/passkey/setup/verify', { t, response: {
                 id: cred.id, rawId: enc(cred.rawId), type: cred.type,
                 authenticatorAttachment: cred.authenticatorAttachment || undefined,
                 clientExtensionResults: cred.getClientExtensionResults(),
                 response: {
                   clientDataJSON: enc(cred.response.clientDataJSON),
                   attestationObject: enc(cred.response.attestationObject),
                   transports: cred.response.getTransports ? cred.response.getTransports() : [],
                 },
               } });
               if (res.ok) { document.getElementById('go').remove(); status('Passkey added. Next time Claude asks to connect, choose "Approve with passkey".'); }
               else status(res.error || 'That did not work. Try again.');
             } catch (e) { status('Passkey creation was cancelled or failed. Try again.'); }
           });
         </script>`,
      ),
    );
  });

  app.post('/passkey/setup/options', async (c) => {
    const body = z.object({ t: z.string() }).safeParse(await c.req.json().catch(() => null));
    const s = body.success ? await openSetup(db, body.data.t) : undefined;
    if (!body.success || !s) return c.json({ error: 'This setup link has expired or was already used.' }, 400);
    const { rows: existing } = await db.query<{ credential_id: string; transports: string | null }>(
      `SELECT credential_id, transports FROM member_passkeys WHERE member_id = ?1 AND revoked_at IS NULL`,
      [s.member_id],
    );
    const options = await generateRegistrationOptions({
      rpName: 'Purser',
      rpID: rpId(c),
      userName: s.member_id,
      userDisplayName: s.display_name,
      userID: new TextEncoder().encode(s.member_id),
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      excludeCredentials: existing.map((p) => ({
        id: p.credential_id,
        transports: p.transports ? json<AuthenticatorTransportFuture[]>(p.transports) : undefined,
      })),
    });
    await db.query(`UPDATE passkey_setups SET challenge = ?2 WHERE token_hash = ?1`, [hashToken(body.data.t), options.challenge]);
    return c.json(options);
  });

  app.post('/passkey/setup/verify', async (c) => {
    const body = z.object({ t: z.string(), response: z.record(z.string(), z.unknown()) }).safeParse(await c.req.json().catch(() => null));
    const s = body.success ? await openSetup(db, body.data.t) : undefined;
    if (!body.success || !s?.challenge) return c.json({ error: 'This setup link has expired or was already used.' }, 400);
    let info;
    try {
      const v = await verifyRegistrationResponse({
        response: body.data.response as unknown as RegistrationResponseJSON,
        expectedChallenge: s.challenge,
        expectedOrigin: origin(c),
        expectedRPID: rpId(c),
        requireUserVerification: true,
      });
      if (!v.verified) throw new Error('not verified');
      info = v.registrationInfo;
    } catch {
      await audit(db, { actor: { type: 'member', id: s.member_id }, action: 'passkey.add', outcome: 'denied' });
      return c.json({ error: 'The passkey could not be verified. Try again.' }, 400);
    }
    // Use the link up only now, and only once, so a cancelled prompt doesn't waste it.
    const { rows: used } = await db.query(
      `UPDATE passkey_setups SET used_at = ${NOW}, challenge = NULL
        WHERE token_hash = ?1 AND used_at IS NULL AND challenge = ?2 RETURNING member_id`,
      [hashToken(body.data.t), s.challenge],
    );
    if (!used.length) return c.json({ error: 'This setup link has expired or was already used.' }, 400);
    await db.query(
      `INSERT INTO member_passkeys (credential_id, member_id, public_key, counter, transports, label) VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
      [
        info.credential.id,
        s.member_id,
        b64u(info.credential.publicKey),
        info.credential.counter,
        info.credential.transports ?? null,
        (c.req.header('user-agent') ?? '').slice(0, 120) || null,
      ],
    );
    await audit(db, { actor: { type: 'member', id: s.member_id }, action: 'passkey.add', outcome: 'ok', detail: { deviceType: info.credentialDeviceType } });
    return c.json({ ok: true });
  });

  // ---- Approving a connector sign-in with a passkey ----
  app.post('/authorize/passkey/options', async (c) => {
    const body = z.object({ req: z.string() }).safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: 'bad request' }, 400);
    const options = await generateAuthenticationOptions({ rpID: rpId(c), userVerification: 'required' });
    const { rows } = await db.query(
      `UPDATE oauth_requests SET webauthn_challenge = ?2
        WHERE id = ?1 AND approved_at IS NULL AND expires_at > ${NOW} RETURNING id`,
      [body.data.req, options.challenge],
    );
    if (!rows.length) return c.json({ error: 'This sign-in has expired. Start again from Claude.' }, 400);
    return c.json(options);
  });

  app.post('/authorize/passkey/verify', async (c) => {
    const body = z.object({ req: z.string(), response: z.object({ id: z.string() }).passthrough() }).safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: 'bad request' }, 400);
    const { req, response } = body.data;
    // Take the challenge, so each one is good for a single attempt.
    const { rows: pending } = await db.query<{ challenge: string }>(
      `SELECT webauthn_challenge AS challenge FROM oauth_requests
        WHERE id = ?1 AND approved_at IS NULL AND expires_at > ${NOW} AND webauthn_challenge IS NOT NULL`,
      [req],
    );
    const { rows: taken } = pending[0]
      ? await db.query(`UPDATE oauth_requests SET webauthn_challenge = NULL WHERE id = ?1 AND webauthn_challenge = ?2 RETURNING id`, [
          req,
          pending[0].challenge,
        ])
      : { rows: [] };
    const challenge = taken.length ? pending[0]!.challenge : undefined;
    const { rows: pk } = await db.query<PasskeyRow>(
      `SELECT credential_id, member_id, public_key, counter, transports FROM member_passkeys WHERE credential_id = ?1 AND revoked_at IS NULL`,
      [response.id],
    );
    const p = pk[0];
    if (!challenge || !p) {
      await audit(db, { actor: { type: 'system', id: 'oauth' }, action: 'oauth.approve', outcome: 'denied', detail: { method: 'passkey' } });
      return c.json({ error: challenge ? 'This passkey is not registered with Purser.' : 'This sign-in has expired. Start again from Claude.' }, 400);
    }
    let newCounter: number;
    try {
      const v = await verifyAuthenticationResponse({
        response: response as unknown as AuthenticationResponseJSON,
        expectedChallenge: challenge,
        expectedOrigin: origin(c),
        expectedRPID: rpId(c),
        credential: {
          id: p.credential_id,
          publicKey: unb64u(p.public_key),
          counter: p.counter,
          transports: p.transports ? json<AuthenticatorTransportFuture[]>(p.transports) : undefined,
        },
        requireUserVerification: true,
      });
      if (!v.verified) throw new Error('not verified');
      newCounter = v.authenticationInfo.newCounter;
    } catch {
      await audit(db, { actor: { type: 'member', id: p.member_id }, action: 'oauth.approve', outcome: 'denied', detail: { method: 'passkey' } });
      return c.json({ error: 'The passkey could not be verified. Try again.' }, 400);
    }
    await db.query(`UPDATE member_passkeys SET counter = ?2, last_used_at = ${NOW} WHERE credential_id = ?1`, [p.credential_id, newCounter]);
    const redirect = await approve(req, p.member_id);
    if (!redirect) return c.json({ error: 'This sign-in has expired. Start again from Claude.' }, 400);
    return c.json({ redirect });
  });

  return app;
}

type AuthenticatorTransportFuture = 'ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb';

export const esc = (s: string) => s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);

export function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><meta name="referrer" content="no-referrer">
<style>
  :root { color-scheme: light dark; --bg:#fbfaf7; --fg:#1d1c1a; --muted:#6b6861; --card:#fff; --line:#e6e2da; --accent:#1d1c1a; --on-accent:#fff; }
  @media (prefers-color-scheme: dark) { :root { --bg:#161513; --fg:#ece9e3; --muted:#a29e96; --card:#1f1e1b; --line:#34322e; --accent:#ece9e3; --on-accent:#161513; } }
  body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui, sans-serif; }
  main { max-width:30rem; margin:12vh auto; padding:2rem; background:var(--card); border:1px solid var(--line); border-radius:12px; }
  h1 { font-size:1.25rem; margin:0 0 1rem; } .muted { color:var(--muted); font-size:.9rem; }
  button { font:inherit; padding:.5rem 1rem; border-radius:8px; border:1px solid var(--line); background:var(--bg); color:var(--fg); cursor:pointer; }
  button.primary { background:var(--accent); color:var(--on-accent); border-color:var(--accent); font-weight:600; }
  details { margin-top:1.25rem; } summary { cursor:pointer; color:var(--muted); }
  .code { font:600 2rem/1.2 ui-monospace, monospace; letter-spacing:.08em; margin:.25rem 0 1rem; }
  @media (max-width:520px) { main { margin:0; border-radius:0; border:0; padding:1.5rem 16px; } }
</style></head><body><main><h1>${esc(title)}</h1>${body}</main></body></html>`;
}
