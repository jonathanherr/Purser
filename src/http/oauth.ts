import { Hono, type Context } from 'hono';
import { z } from 'zod';
import { createHash, randomBytes } from 'node:crypto';
import { json, NOW, type Db } from '../db/index.js';
import { hashToken, newToken } from '../crypto/tokens.js';
import { audit } from '../vault/audit.js';
import type { Scope } from '../vault/auth.js';

/**
 * OAuth 2.1 for remote MCP clients such as Claude custom connectors: discovery metadata,
 * dynamic client registration, a pairing-code sign-in page, and the token endpoint.
 * See migrations/0002_oauth.sql for the model. Connections are read-only.
 */

/** What a connector may do: read everything the member may see, change nothing. */
export const CONNECTOR_SCOPES: Scope[] = ['read:accounts', 'read:transactions', 'read:investments', 'read:budgets', 'read:flags'];

/** Only these redirect targets can register, so a sign-in can't be steered to another site. */
const ALLOWED_REDIRECT = /^https:\/\/(claude\.ai|claude\.com)\/api\/mcp\/auth_callback$/;

const SIGN_IN_MINUTES = 15;
const MAX_PENDING = 20;
// No 0/O/1/I/L, so codes survive being read aloud or retyped.
const ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';

export function pairingCode(): string {
  const bytes = randomBytes(8);
  const chars = Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]);
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`;
}

export function normalizePairingCode(code: string): string {
  const raw = code.toUpperCase().replace(/[^0-9A-Z]/g, '');
  return raw.length === 8 ? `${raw.slice(0, 4)}-${raw.slice(4)}` : raw;
}

const s256 = (verifier: string) => createHash('sha256').update(verifier).digest('base64url');
const origin = (c: Context) => new URL(c.req.url).origin;
const esc = (s: string) => s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);

export function resourceMetadataUrl(requestUrl: string): string {
  return `${new URL(requestUrl).origin}/.well-known/oauth-protected-resource`;
}

/**
 * Approves a pending sign-in for a member. Called by the admin CLI, never over HTTP.
 * Returns false when the code is unknown, expired or already approved.
 */
export async function approvePairing(db: Db, code: string, memberId: string): Promise<boolean> {
  const { rows: m } = await db.query(`SELECT 1 FROM members WHERE id = ?1`, [memberId]);
  if (!m.length) throw new Error(`no member ${memberId}`);
  const { rows } = await db.query<{ id: string; client_id: string }>(
    `UPDATE oauth_requests SET member_id = ?2, approved_at = ${NOW}
      WHERE pairing_code = ?1 AND approved_at IS NULL AND expires_at > ${NOW}
      RETURNING id, client_id`,
    [normalizePairingCode(code), memberId],
  );
  await audit(db, {
    actor: { type: 'system', id: 'admin' },
    action: 'oauth.approve',
    outcome: rows.length ? 'ok' : 'denied',
    detail: { memberId, clientId: rows[0]?.client_id ?? null },
  });
  return rows.length > 0;
}

/** Drops sign-in attempts a day after they expire. Runs with the proposal-expiry cron. */
export async function pruneSignIns(db: Db): Promise<void> {
  await db.query(`DELETE FROM oauth_requests WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')`);
}

export function oauthRoutes(db: Db) {
  const app = new Hono();

  app.get('/.well-known/oauth-protected-resource', (c) => c.json(protectedResource(c)));
  app.get('/.well-known/oauth-protected-resource/mcp', (c) => c.json(protectedResource(c)));
  app.get('/.well-known/oauth-authorization-server', (c) => {
    const o = origin(c);
    return c.json({
      issuer: o,
      authorization_endpoint: `${o}/authorize`,
      token_endpoint: `${o}/token`,
      registration_endpoint: `${o}/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      scopes_supported: ['vault:read'],
    });
  });

  // ---- Dynamic client registration (RFC 7591) ----
  app.post('/register', async (c) => {
    const body = z
      .object({ redirect_uris: z.array(z.string()).min(1).max(5), client_name: z.string().max(100).optional() })
      .passthrough()
      .safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: 'invalid_client_metadata' }, 400);
    const bad = body.data.redirect_uris.find((u) => !ALLOWED_REDIRECT.test(u));
    if (bad) return c.json({ error: 'invalid_redirect_uri', error_description: 'Only Claude connectors can register' }, 400);
    const clientId = `pc_${randomBytes(16).toString('base64url')}`;
    await db.query(`INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?1, ?2, ?3)`, [
      clientId,
      body.data.client_name ?? null,
      body.data.redirect_uris,
    ]);
    await audit(db, { actor: { type: 'system', id: 'oauth' }, action: 'oauth.register', outcome: 'ok', detail: { clientId } });
    return c.json(
      {
        client_id: clientId,
        client_name: body.data.client_name,
        redirect_uris: body.data.redirect_uris,
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      },
      201,
    );
  });

  // ---- Sign-in: show a pairing code and wait for a member to approve it ----
  app.get('/authorize', async (c) => {
    const q = c.req.query();
    if (q.response_type !== 'code' || !q.client_id || !q.redirect_uri || !q.code_challenge || q.code_challenge_method !== 'S256') {
      return c.html(page('Sign-in request is incomplete', '<p>Start again from Claude.</p>'), 400);
    }
    const { rows } = await db.query<{ redirect_uris: string; client_name: string | null }>(
      `SELECT redirect_uris, client_name FROM oauth_clients WHERE client_id = ?1`,
      [q.client_id],
    );
    const client = rows[0];
    // An unknown client or a redirect it didn't register gets an error page, never a redirect.
    if (!client || !json<string[]>(client.redirect_uris).includes(q.redirect_uri)) {
      return c.html(page('Unknown connector', '<p>Remove the connector in Claude and add it again.</p>'), 400);
    }
    const { rows: pending } = await db.query<{ n: number }>(
      `SELECT count(*) AS n FROM oauth_requests WHERE approved_at IS NULL AND expires_at > ${NOW}`,
    );
    if ((pending[0]?.n ?? 0) >= MAX_PENDING) {
      return c.html(page('Too many sign-ins in progress', '<p>Try again in a few minutes.</p>'), 429);
    }
    const id = randomBytes(32).toString('base64url');
    const code = pairingCode();
    await db.query(
      `INSERT INTO oauth_requests (id, pairing_code, client_id, redirect_uri, state, code_challenge, expires_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?7))`,
      [id, code, q.client_id, q.redirect_uri, q.state ?? null, q.code_challenge, `+${SIGN_IN_MINUTES} minutes`],
    );
    const who = client.client_name ? esc(client.client_name) : 'A connector';
    return c.html(
      page(
        'Connect to Purser',
        `<p>${who} wants read-only access to your Purser vault.</p>
         <p>Your pairing code:</p>
         <p class="code">${code}</p>
         <p>Approve it from the <b>Vault admin</b> workflow (command <code>connect-approve</code>, with this code and
         your member id), or ask Claude in your Purser project to approve it for you.</p>
         <p id="status" class="muted">Waiting for approval. Keep this window open: it finishes the sign-in on its own
         once the code is approved. The code expires in ${SIGN_IN_MINUTES} minutes.</p>
         <p><button id="check" type="button">Check now</button></p>
         <script>
           const id = ${JSON.stringify(id)};
           let timer = null, busy = false, done = false;
           const status = (t) => { document.getElementById('status').textContent = t; };
           async function poll() {
             if (busy || done) return;
             busy = true; clearTimeout(timer);
             try {
               const r = await fetch('/authorize/poll?req=' + encodeURIComponent(id), { cache: 'no-store' });
               const b = await r.json();
               if (b.redirect) { done = true; status('Approved. Returning to Claude...'); location.href = b.redirect; return; }
               if (b.status === 'expired') { done = true; status('This code expired or was already used. Start again from Claude.'); return; }
             } catch (e) {} finally { busy = false; }
             if (!done) timer = setTimeout(poll, 3000);
           }
           // Browsers slow timers in background windows, so check again as soon as the window is back in view.
           document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
           window.addEventListener('focus', poll);
           window.addEventListener('pageshow', poll);
           document.getElementById('check').addEventListener('click', poll);
           poll();
         </script>`,
      ),
    );
  });

  app.get('/authorize/poll', async (c) => {
    const id = c.req.query('req') ?? '';
    const { rows } = await db.query<{ redirect_uri: string; state: string | null; approved: number; expired: number; issued: number }>(
      `SELECT redirect_uri, state, approved_at IS NOT NULL AS approved, expires_at <= ${NOW} AS expired,
              code_hash IS NOT NULL AS issued
         FROM oauth_requests WHERE id = ?1`,
      [id],
    );
    const r = rows[0];
    if (!r || r.expired) return c.json({ status: 'expired' });
    if (!r.approved) return c.json({ status: 'pending' });
    if (r.issued) return c.json({ status: 'expired' }); // the code was already handed out once
    const code = newToken('pac');
    const { rows: set } = await db.query(
      `UPDATE oauth_requests SET code_hash = ?2 WHERE id = ?1 AND code_hash IS NULL RETURNING id`,
      [id, hashToken(code)],
    );
    if (!set.length) return c.json({ status: 'expired' });
    const to = new URL(r.redirect_uri);
    to.searchParams.set('code', code);
    if (r.state) to.searchParams.set('state', r.state);
    return c.json({ status: 'approved', redirect: to.toString() });
  });

  // ---- Token endpoint: authorization code + PKCE -> a read-only agent token for the member ----
  app.post('/token', async (c) => {
    const form = await c.req.parseBody().catch(() => ({}) as Record<string, unknown>);
    const p = z
      .object({
        grant_type: z.literal('authorization_code'),
        code: z.string().min(1),
        redirect_uri: z.string().min(1),
        client_id: z.string().min(1),
        code_verifier: z.string().min(43).max(128),
      })
      .safeParse(form);
    if (!p.success) return c.json({ error: 'invalid_request' }, 400);
    const { rows } = await db.query<{ id: string; client_id: string; redirect_uri: string; code_challenge: string; member_id: string }>(
      `UPDATE oauth_requests SET code_used_at = ${NOW}
        WHERE code_hash = ?1 AND code_used_at IS NULL AND member_id IS NOT NULL AND expires_at > ${NOW}
        RETURNING id, client_id, redirect_uri, code_challenge, member_id`,
      [hashToken(p.data.code)],
    );
    const r = rows[0];
    const ok =
      r && r.client_id === p.data.client_id && r.redirect_uri === p.data.redirect_uri && s256(p.data.code_verifier) === r.code_challenge;
    if (!r || !ok) {
      await audit(db, { actor: { type: 'system', id: 'oauth' }, action: 'oauth.token', outcome: 'denied' });
      return c.json({ error: 'invalid_grant' }, 400);
    }
    const token = newToken('pa');
    const agentId = `connector-${r.member_id}-${randomBytes(4).toString('hex')}`;
    const { rows: client } = await db.query<{ client_name: string | null }>(
      `SELECT client_name FROM oauth_clients WHERE client_id = ?1`,
      [r.client_id],
    );
    await db.query(`INSERT INTO agent_clients (id, name, token_hash, scopes, acts_for) VALUES (?1, ?2, ?3, ?4, ?5)`, [
      agentId,
      `${client[0]?.client_name ?? 'Connector'} for ${r.member_id}`,
      hashToken(token),
      CONNECTOR_SCOPES,
      r.member_id,
    ]);
    await audit(db, {
      actor: { type: 'member', id: r.member_id },
      action: 'oauth.token',
      outcome: 'ok',
      detail: { agentId, clientId: r.client_id, scopes: CONNECTOR_SCOPES },
    });
    return c.json({ access_token: token, token_type: 'Bearer', scope: 'vault:read' }, 200, { 'Cache-Control': 'no-store' });
  });

  return app;
}

function protectedResource(c: Context) {
  const o = origin(c);
  return { resource: `${o}/mcp`, authorization_servers: [o], scopes_supported: ['vault:read'], bearer_methods_supported: ['header'] };
}

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><meta name="referrer" content="no-referrer">
<style>
  :root { color-scheme: light dark; --bg:#fbfaf7; --fg:#1d1c1a; --muted:#6b6861; --card:#fff; --line:#e6e2da; }
  @media (prefers-color-scheme: dark) { :root { --bg:#161513; --fg:#ece9e3; --muted:#a29e96; --card:#1f1e1b; --line:#34322e; } }
  body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui, sans-serif; }
  main { max-width:30rem; margin:12vh auto; padding:2rem; background:var(--card); border:1px solid var(--line); border-radius:12px; }
  h1 { font-size:1.25rem; margin:0 0 1rem; } .muted { color:var(--muted); font-size:.9rem; }
  button { font:inherit; padding:.4rem .9rem; border-radius:8px; border:1px solid var(--line); background:var(--bg); color:var(--fg); cursor:pointer; }
  .code { font:600 2rem/1.2 ui-monospace, monospace; letter-spacing:.08em; margin:.25rem 0 1rem; }
  @media (max-width:520px) { main { margin:0; border-radius:0; border:0; padding:1.5rem 16px; } }
</style></head><body><main><h1>${esc(title)}</h1>${body}</main></body></html>`;
}
