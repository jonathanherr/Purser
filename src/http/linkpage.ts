import { Hono, type Context } from 'hono';
import { z } from 'zod';
import { randomBytes } from 'node:crypto';
import { NOW, type Db } from '../db/index.js';
import type { KeyProvider } from '../crypto/envelope.js';
import type { PlaidLike } from '../plaid/client.js';
import { plaidErrorCode } from '../plaid/client.js';
import { hashToken } from '../crypto/tokens.js';
import { audit } from '../vault/audit.js';
import { storeInstitution, syncInstitution } from '../plaid/sync.js';
import { DEFAULT_PRODUCTS } from '../plaid/link.js';
import { BROWSER_ASSERT, BROWSER_HELPERS, page, passkeyLoginOptions, verifyPasskeyAssertion } from './passkeys.js';

/**
 * "Link an account": a member signs in with their passkey, Plaid Link runs in the browser, and
 * the vault exchanges the public token Plaid hands back (migrations/0005_link_sessions.sql).
 * Bank credentials go only to Plaid and the bank.
 */

const SESSION_MINUTES = 30;
const PLAID_LINK_JS = 'https://cdn.plaid.com/link/v2/stable/link-initialize.js';

export interface LinkDeps {
  db: Db;
  kp: KeyProvider;
  plaid?: PlaidLike;
  plaidWebhookUrl?: string;
  background?: (work: Promise<unknown>) => void;
}

/** Where Plaid sends people back after a bank's own (OAuth) sign-in. Must be allowed in the Plaid Dashboard. */
export const oauthReturnUrl = (c: Context) => `${new URL(c.req.url).origin}/plaid/oauth`;

export function linkRoutes(deps: LinkDeps) {
  const { db } = deps;
  const app = new Hono();

  const session = async (sid: string) =>
    (
      await db.query<{ member_id: string | null; challenge: string | null; authed: number; used: number }>(
        `SELECT member_id, challenge, authed_at IS NOT NULL AS authed, used_at IS NOT NULL AS used
           FROM link_sessions WHERE id_hash = ?1 AND expires_at > ${NOW}`,
        [hashToken(sid)],
      )
    ).rows[0];

  const linkPage = (c: Context) => c.html(page('Link an account', linkBody(!!deps.plaid)));
  app.get('/link', linkPage);
  // Plaid returns here after an OAuth bank sign-in; the same page picks up where it left off.
  app.get('/plaid/oauth', linkPage);

  app.post('/link/start', async (c) => {
    if (!deps.plaid) return c.json({ error: 'Plaid is not configured on this vault.' }, 503);
    const sid = randomBytes(32).toString('base64url');
    const options = await passkeyLoginOptions(c);
    await db.query(
      `INSERT INTO link_sessions (id_hash, challenge, expires_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?3))`,
      [hashToken(sid), options.challenge, `+${SESSION_MINUTES} minutes`],
    );
    return c.json({ sid, options });
  });

  app.post('/link/verify', async (c) => {
    const body = z.object({ sid: z.string(), response: z.object({ id: z.string() }).passthrough() }).safeParse(await c.req.json().catch(() => null));
    if (!body.success || !deps.plaid) return c.json({ error: 'bad request' }, 400);
    const s = await session(body.data.sid);
    if (!s?.challenge || s.authed) return c.json({ error: 'This page has expired. Reload it and try again.' }, 400);
    // One attempt per challenge.
    const { rows: taken } = await db.query(
      `UPDATE link_sessions SET challenge = NULL WHERE id_hash = ?1 AND challenge = ?2 RETURNING id_hash`,
      [hashToken(body.data.sid), s.challenge],
    );
    if (!taken.length) return c.json({ error: 'This page has expired. Reload it and try again.' }, 400);
    const who = await verifyPasskeyAssertion(db, c, s.challenge, body.data.response);
    if ('error' in who) {
      await audit(db, {
        actor: who.memberId ? { type: 'member', id: who.memberId } : { type: 'system', id: 'link' },
        action: 'link.signin',
        outcome: 'denied',
      });
      return c.json({ error: who.error }, 400);
    }
    await db.query(`UPDATE link_sessions SET member_id = ?2, authed_at = ${NOW} WHERE id_hash = ?1`, [hashToken(body.data.sid), who.memberId]);
    await audit(db, { actor: { type: 'member', id: who.memberId }, action: 'link.signin', outcome: 'ok' });
    try {
      const { linkToken } = await createLinkToken(deps.plaid, who.memberId, deps.plaidWebhookUrl, oauthReturnUrl(c));
      return c.json({ linkToken });
    } catch (e) {
      return c.json({ error: `Plaid refused to start Link (${plaidErrorCode(e) ?? 'unknown error'}).` }, 502);
    }
  });

  app.post('/link/exchange', async (c) => {
    const body = z
      .object({ sid: z.string(), public_token: z.string().min(1), institution_name: z.string().max(200).optional(), institution_id: z.string().max(64).optional() })
      .safeParse(await c.req.json().catch(() => null));
    if (!body.success || !deps.plaid) return c.json({ error: 'bad request' }, 400);
    // Each signed-in session links one Item.
    const { rows } = await db.query<{ member_id: string }>(
      `UPDATE link_sessions SET used_at = ${NOW}
        WHERE id_hash = ?1 AND authed_at IS NOT NULL AND used_at IS NULL AND expires_at > ${NOW} RETURNING member_id`,
      [hashToken(body.data.sid)],
    );
    const memberId = rows[0]?.member_id;
    if (!memberId) return c.json({ error: 'This page has expired. Reload it and try again.' }, 400);
    const { accessToken, itemId } = await deps.plaid.exchangePublicToken(body.data.public_token);
    const institutionId = await storeInstitution(db, deps.kp, {
      ownerMemberId: memberId,
      itemId,
      accessToken,
      products: DEFAULT_PRODUCTS,
      name: body.data.institution_name ?? null,
      plaidInstitutionId: body.data.institution_id ?? null,
    });
    const sync = syncInstitution(db, deps.plaid, deps.kp, institutionId).catch((e) => console.error('first sync failed', e));
    if (deps.background) deps.background(sync);
    else await sync;
    return c.json({ ok: true, institution: body.data.institution_name ?? 'your bank' });
  });

  return app;
}

/** Asks Plaid for a Link token, with the OAuth return page when the Dashboard allows it. */
async function createLinkToken(plaid: PlaidLike, memberId: string, webhook: string | undefined, redirectUri: string) {
  try {
    return await plaid.createLinkToken(memberId, { webhook, redirectUri });
  } catch (e) {
    // Until the return page is added to "Allowed redirect URIs", Plaid rejects it. Most banks
    // still work without it (OAuth banks then finish in a pop-up), so try again without.
    if (plaidErrorCode(e)?.startsWith('INVALID_')) return plaid.createLinkToken(memberId, { webhook });
    throw e;
  }
}

function linkBody(configured: boolean): string {
  if (!configured) return '<p>Plaid is not configured on this vault yet.</p>';
  return `<p>Sign in with your passkey, then choose your bank in Plaid's window. Your bank password goes only to Plaid
     and your bank. The vault stores what Plaid returns, encrypted, and keeps 13 months.</p>
   <p><button id="go" class="primary" type="button">Sign in with passkey</button></p>
   <p id="status" class="muted"></p>
   <script src="${PLAID_LINK_JS}"></script>
   <script>
     ${BROWSER_HELPERS}
     ${BROWSER_ASSERT}
     const status = (m) => { document.getElementById('status').textContent = m; };
     const store = { get: (k) => { try { return sessionStorage.getItem(k); } catch (e) { return null; } },
                     set: (k, v) => { try { sessionStorage.setItem(k, v); } catch (e) {} } };
     const returning = location.pathname === '/plaid/oauth' && location.search.includes('oauth_state_id');

     function openLink(sid, token) {
       const handler = Plaid.create({
         token,
         receivedRedirectUri: returning ? location.href : undefined,
         onSuccess: async (public_token, meta) => {
           status('Saving the connection...');
           const r = await post('/link/exchange', { sid, public_token,
             institution_name: meta && meta.institution ? meta.institution.name : undefined,
             institution_id: meta && meta.institution ? meta.institution.institution_id : undefined });
           if (r.ok) { document.getElementById('go').remove(); status(r.institution + ' is linked. The first sync is running; you can close this page.'); }
           else status(r.error || 'Saving failed. Reload and try again.');
         },
         onExit: (err) => { if (err) status('Plaid stopped: ' + (err.display_message || err.error_message || err.error_code)); else status('Cancelled. Press the button to try again.'); },
       });
       handler.open();
     }

     if (returning && store.get('purser.sid') && store.get('purser.lt')) {
       status('Finishing your bank sign-in...');
       openLink(store.get('purser.sid'), store.get('purser.lt'));
     } else if (!passkeysWork()) {
       status('This browser cannot use passkeys. Try Safari or Chrome.');
     }

     document.getElementById('go').addEventListener('click', async () => {
       try {
         status('');
         const start = await post('/link/start', {});
         if (start.error) return status(start.error);
         const response = await assertPasskey(start.options);
         const v = await post('/link/verify', { sid: start.sid, response });
         if (v.error) return status(v.error);
         store.set('purser.sid', start.sid); store.set('purser.lt', v.linkToken);
         openLink(start.sid, v.linkToken);
       } catch (e) { status('The passkey prompt was cancelled. Try again.'); }
     });
   </script>`;
}
