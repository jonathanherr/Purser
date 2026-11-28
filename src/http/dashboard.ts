import { Hono, type Context } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { z } from 'zod';
import { randomBytes } from 'node:crypto';
import { json, NOW, type Db } from '../db/index.js';
import type { KeyProvider } from '../crypto/envelope.js';
import { plaidErrorCode, type PlaidLike } from '../plaid/client.js';
import { hashToken, newToken } from '../crypto/tokens.js';
import { audit } from '../vault/audit.js';
import { openAccessToken, storeInstitution, syncInstitution } from '../plaid/sync.js';
import { DEFAULT_PRODUCTS } from '../plaid/link.js';
import { BROWSER_ASSERT, BROWSER_HELPERS, passkeyLoginOptions, verifyPasskeyAssertion } from './passkeys.js';

/**
 * The vault's dashboard at /app, for household members only. Today it manages connections
 * (link a bank with Plaid Link, see status and Plaid error codes, repair a connection, sync);
 * it is the place later dashboard views go.
 *
 * Sign-in is a passkey; the session is an HttpOnly cookie whose hash is in member_sessions
 * (migrations/0006). Every state-changing call is a POST that must carry the X-Purser header,
 * which a cross-site form cannot set, on top of SameSite=Lax.
 */

const COOKIE = '__Host-purser_session';
const SESSION_HOURS = 12;
const CHALLENGE_MINUTES = 5;
const PLAID_LINK_JS = 'https://cdn.plaid.com/link/v2/stable/link-initialize.js';
/** Plaid's free Trial plan allows this many connections, and removing one doesn't free it. */
const TRIAL_ITEMS = 10;

export interface DashboardDeps {
  db: Db;
  kp: KeyProvider;
  plaid?: PlaidLike;
  plaidEnv?: string;
  plaidWebhookUrl?: string;
  background?: (work: Promise<unknown>) => void;
}

type Member = { id: string; display_name: string };
type Env = { Variables: { member: Member } };

/** Where Plaid sends people back after a bank's own (OAuth) sign-in. Must be allowed in the Plaid Dashboard. */
export const oauthReturnUrl = (c: Context) => `${new URL(c.req.url).origin}/plaid/oauth`;

export function dashboardRoutes(deps: DashboardDeps) {
  const { db } = deps;
  const app = new Hono<Env>();

  // ---- Pages ----
  const shell = (c: Context) => c.html(dashboardHtml(), 200, { 'Cache-Control': 'no-store' });
  app.get('/app', shell);
  // Plaid returns here after a bank's own sign-in; the dashboard resumes Link from there.
  app.get('/plaid/oauth', shell);
  app.get('/link', (c) => c.redirect('/app', 302));

  // ---- Sign-in ----
  app.post('/app/api/login/options', csrf, async (c) => {
    const sid = randomBytes(32).toString('base64url');
    const options = await passkeyLoginOptions(c);
    // link_sessions doubles as the short-lived store for sign-in challenges.
    await db.query(
      `INSERT INTO link_sessions (id_hash, challenge, expires_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?3))`,
      [hashToken(sid), options.challenge, `+${CHALLENGE_MINUTES} minutes`],
    );
    return c.json({ sid, options });
  });

  app.post('/app/api/login/verify', csrf, async (c) => {
    const body = z.object({ sid: z.string(), response: z.object({ id: z.string() }).passthrough() }).safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: 'bad request' }, 400);
    // Take the challenge, so each one is good for a single attempt.
    const { rows } = await db.query<{ challenge: string }>(
      `UPDATE link_sessions SET used_at = ${NOW}
        WHERE id_hash = ?1 AND used_at IS NULL AND challenge IS NOT NULL AND expires_at > ${NOW}
        RETURNING challenge`,
      [hashToken(body.data.sid)],
    );
    const challenge = rows[0]?.challenge;
    if (!challenge) return c.json({ error: 'That took too long. Try again.' }, 400);
    const who = await verifyPasskeyAssertion(db, c, challenge, body.data.response);
    if ('error' in who) {
      await audit(db, {
        actor: who.memberId ? { type: 'member', id: who.memberId } : { type: 'system', id: 'dashboard' },
        action: 'dashboard.signin',
        outcome: 'denied',
      });
      return c.json({ error: who.error }, 400);
    }
    const token = newToken('pss');
    await db.query(
      `INSERT INTO member_sessions (token_hash, member_id, expires_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?3))`,
      [hashToken(token), who.memberId, `+${SESSION_HOURS} hours`],
    );
    await audit(db, { actor: { type: 'member', id: who.memberId }, action: 'dashboard.signin', outcome: 'ok' });
    setCookie(c, COOKIE, token, { path: '/', secure: true, httpOnly: true, sameSite: 'Lax', maxAge: SESSION_HOURS * 3600 });
    return c.json({ ok: true });
  });

  app.post('/app/api/logout', csrf, async (c) => {
    const token = getCookie(c, COOKIE);
    if (token) await db.query(`UPDATE member_sessions SET revoked_at = ${NOW} WHERE token_hash = ?1`, [hashToken(token)]);
    deleteCookie(c, COOKIE, { path: '/', secure: true });
    return c.json({ ok: true });
  });

  // ---- Everything below needs a signed-in member ----
  const signedIn = async (c: Context<Env>, next: () => Promise<void>) => {
    const token = getCookie(c, COOKIE);
    const { rows } = token
      ? await db.query<Member>(
          `SELECT m.id, m.display_name FROM member_sessions s JOIN members m ON m.id = s.member_id
            WHERE s.token_hash = ?1 AND s.revoked_at IS NULL AND s.expires_at > ${NOW}`,
          [hashToken(token)],
        )
      : { rows: [] };
    if (!rows[0]) return c.json({ error: 'signed out' }, 401);
    c.set('member', rows[0]);
    await next();
  };
  app.use('/app/api/me', signedIn);
  app.use('/app/api/connections', signedIn);
  app.use('/app/api/plaid/*', signedIn);

  app.get('/app/api/me', (c) => c.json({ member: { id: c.get('member').id, name: c.get('member').display_name } }));

  app.get('/app/api/connections', async (c) => {
    const me = c.get('member').id;
    const { rows } = await db.query<{
      id: string;
      name: string | null;
      owner_member_id: string;
      owner_name: string;
      status: string;
      last_error: string | null;
      last_synced_at: string | null;
      created_at: string;
      accounts: number;
    }>(
      `SELECT i.id, i.name, i.owner_member_id, m.display_name AS owner_name, i.status, i.last_error,
              i.last_synced_at, i.created_at,
              (SELECT count(*) FROM accounts a WHERE a.institution_id = i.id) AS accounts
         FROM institutions i JOIN members m ON m.id = i.owner_member_id
        WHERE i.status <> 'removed' ORDER BY i.created_at`,
    );
    const { rows: used } = await db.query<{ n: number }>(`SELECT count(*) AS n FROM institutions`);
    const { rows: events } = await db.query<{ at: string; detail: string | null }>(
      `SELECT at, detail FROM audit_log
        WHERE action = 'link.event' AND actor_id = ?1 AND outcome = 'error' ORDER BY id DESC LIMIT 5`,
      [me],
    );
    return c.json({
      plaid: { configured: !!deps.plaid, env: deps.plaidEnv ?? 'sandbox', itemsUsed: used[0]?.n ?? 0, itemLimit: TRIAL_ITEMS },
      connections: rows.map((r) => ({
        id: r.id,
        name: r.name ?? 'Unnamed bank',
        owner: r.owner_name,
        mine: r.owner_member_id === me,
        status: r.status,
        error: r.last_error,
        lastSyncedAt: r.last_synced_at,
        linkedAt: r.created_at,
        accounts: r.accounts,
      })),
      problems: events.map((e) => ({ at: e.at, ...(e.detail ? json<Record<string, string>>(e.detail) : {}) })),
    });
  });

  /** A Link token for a new connection, or update mode for one of the member's own connections. */
  app.post('/app/api/plaid/link-token', csrf, async (c) => {
    if (!deps.plaid) return c.json({ error: 'Plaid is not configured on this vault.' }, 503);
    const body = z.object({ institutionId: z.string().optional() }).safeParse(await c.req.json().catch(() => ({})));
    if (!body.success) return c.json({ error: 'bad request' }, 400);
    const me = c.get('member').id;
    let accessToken: string | undefined;
    if (body.data.institutionId) {
      if (!(await ownsInstitution(db, body.data.institutionId, me))) return c.json({ error: 'Only the owner can repair this connection.' }, 403);
      accessToken = await openAccessToken(db, deps.kp, body.data.institutionId);
    }
    try {
      const { linkToken } = await createLinkToken(deps.plaid, me, { webhook: deps.plaidWebhookUrl, redirectUri: oauthReturnUrl(c), accessToken });
      return c.json({ linkToken });
    } catch (e) {
      return c.json({ error: `Plaid refused to start (${plaidErrorCode(e) ?? 'unknown error'}).` }, 502);
    }
  });

  app.post('/app/api/plaid/exchange', csrf, async (c) => {
    if (!deps.plaid) return c.json({ error: 'Plaid is not configured on this vault.' }, 503);
    const body = z
      .object({ public_token: z.string().min(1), institution_name: z.string().max(200).optional(), institution_id: z.string().max(64).optional() })
      .safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: 'bad request' }, 400);
    const me = c.get('member').id;
    const { accessToken, itemId } = await deps.plaid.exchangePublicToken(body.data.public_token);
    const institutionId = await storeInstitution(db, deps.kp, {
      ownerMemberId: me,
      itemId,
      accessToken,
      products: DEFAULT_PRODUCTS,
      name: body.data.institution_name ?? null,
      plaidInstitutionId: body.data.institution_id ?? null,
    });
    later(deps, syncInstitution(db, deps.plaid, deps.kp, institutionId));
    return c.json({ ok: true, institutionId });
  });

  /** Sync now; also used after a repair in update mode, which needs no token exchange. */
  app.post('/app/api/plaid/sync', csrf, async (c) => {
    if (!deps.plaid) return c.json({ error: 'Plaid is not configured on this vault.' }, 503);
    const body = z.object({ institutionId: z.string() }).safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: 'bad request' }, 400);
    if (!(await ownsInstitution(db, body.data.institutionId, c.get('member').id))) return c.json({ error: 'Only the owner can sync this connection.' }, 403);
    const r = await syncInstitution(db, deps.plaid, deps.kp, body.data.institutionId);
    return c.json({ status: r.status, error: r.error ?? null, accounts: r.accounts, added: r.added });
  });

  // Plaid Link reports what went wrong in the browser. Keep the code and institution, never credentials.
  app.post('/app/api/plaid/event', csrf, async (c) => {
    const body = z
      .object({
        event: z.string().max(64),
        error_code: z.string().max(64).optional(),
        error_type: z.string().max(64).optional(),
        error_message: z.string().max(300).optional(),
        institution_id: z.string().max(64).optional(),
        institution_name: z.string().max(200).optional(),
        status: z.string().max(64).optional(),
        view: z.string().max(64).optional(),
      })
      .safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ ok: false }, 400);
    await audit(db, {
      actor: { type: 'member', id: c.get('member').id },
      action: 'link.event',
      outcome: body.data.error_code ? 'error' : 'ok',
      detail: body.data,
    });
    return c.json({ ok: true });
  });

  return app;
}

/** Rejects requests a cross-site form or link could make: they can't set custom headers. */
async function csrf(c: Context, next: () => Promise<void>) {
  if (c.req.header('x-purser') !== '1') return c.json({ error: 'missing X-Purser header' }, 403);
  await next();
}

async function ownsInstitution(db: Db, institutionId: string, memberId: string): Promise<boolean> {
  const { rows } = await db.query(`SELECT 1 FROM institutions WHERE id = ?1 AND owner_member_id = ?2 AND status <> 'removed'`, [institutionId, memberId]);
  return rows.length > 0;
}

function later(deps: DashboardDeps, work: Promise<unknown>) {
  const w = work.catch((e) => console.error('background sync failed', e));
  if (deps.background) deps.background(w);
}

/** Asks Plaid for a Link token, with the OAuth return page when the Dashboard allows it. */
async function createLinkToken(plaid: PlaidLike, memberId: string, opts: { webhook?: string; redirectUri: string; accessToken?: string }) {
  try {
    return await plaid.createLinkToken(memberId, opts);
  } catch (e) {
    // Until the return page is in "Allowed redirect URIs", Plaid rejects it. Most banks work without it.
    if (plaidErrorCode(e)?.startsWith('INVALID_')) return plaid.createLinkToken(memberId, { ...opts, redirectUri: undefined });
    throw e;
  }
}

// What Plaid's error codes mean for the person, and what to do. Anything else shows Plaid's own message.
const ERROR_HELP: Record<string, string> = {
  INVALID_CREDENTIALS: 'The bank rejected the username or password. Check you picked the right entry (for example SoFi Bank vs SoFi Invest).',
  INVALID_MFA: 'The verification code was wrong or expired. Try again and request a new code.',
  ITEM_LOGIN_REQUIRED: 'The bank needs you to sign in again. Use "Fix connection".',
  INSTITUTION_DOWN: 'The bank is having problems right now. Try again later.',
  INSTITUTION_NOT_RESPONDING: 'The bank is not responding. Try again later.',
  INSTITUTION_NOT_SUPPORTED: 'Plaid does not support this bank for the data Purser needs.',
  NO_ACCOUNTS: 'No eligible accounts were found at this bank.',
  INVALID_LINK_TOKEN: 'The session expired. Start again.',
  INSUFFICIENT_CREDENTIALS: 'The bank sign-in was not completed.',
  USER_SETUP_REQUIRED: 'The bank needs you to finish something in its own app or website first.',
  ITEM_LOCKED: 'The bank locked the account after too many attempts. Unlock it at the bank first.',
  PRODUCTS_NOT_SUPPORTED: 'This bank does not provide the data Purser asks for.',
};

function dashboardHtml(): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Purser</title><meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">
<style>
  :root { color-scheme: light dark; --bg:#f6f4ef; --fg:#1d1c1a; --muted:#6b6861; --card:#fffdf9; --line:#e4dfd5;
          --accent:#1f4d3a; --on-accent:#fff; --ok:#2f7a4f; --warn:#a86a12; --bad:#b03a2e; }
  @media (prefers-color-scheme: dark) { :root { --bg:#141412; --fg:#ece9e3; --muted:#a29e96; --card:#1d1c19; --line:#33312c;
          --accent:#8fc9a8; --on-accent:#10251a; --ok:#7cc59a; --warn:#e0a84c; --bad:#e88175; } }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 ui-sans-serif, system-ui, -apple-system, sans-serif; }
  header { display:flex; align-items:center; justify-content:space-between; gap:1rem; max-width:52rem; margin:0 auto; padding:1.25rem 16px; }
  .brand { font-weight:700; letter-spacing:.02em; font-size:1.05rem; } .brand span { color:var(--muted); font-weight:500; }
  main { max-width:52rem; margin:0 auto; padding:0 16px 4rem; }
  h2 { font-size:.8rem; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin:2rem 0 .75rem; font-weight:600; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:1rem 1.1rem; }
  .list { display:grid; gap:.6rem; }
  .row { display:flex; align-items:center; justify-content:space-between; gap:1rem; flex-wrap:wrap; }
  .name { font-weight:600; } .muted { color:var(--muted); font-size:.88rem; }
  .pill { display:inline-flex; align-items:center; gap:.35rem; font-size:.78rem; font-weight:600; padding:.15rem .55rem; border-radius:99px; border:1px solid currentColor; }
  .pill::before { content:''; width:.45rem; height:.45rem; border-radius:50%; background:currentColor; }
  .ok { color:var(--ok); } .warn { color:var(--warn); } .bad { color:var(--bad); }
  button { font:inherit; font-size:.9rem; padding:.45rem .9rem; border-radius:8px; border:1px solid var(--line); background:transparent; color:var(--fg); cursor:pointer; }
  button:hover { border-color:var(--muted); } button:disabled { opacity:.5; cursor:default; }
  button.primary { background:var(--accent); color:var(--on-accent); border-color:var(--accent); font-weight:600; }
  .actions { display:flex; gap:.5rem; flex-wrap:wrap; }
  .hero { text-align:center; padding:3rem 1rem; } .hero p { color:var(--muted); max-width:28rem; margin:.5rem auto 1.5rem; }
  .meter { height:6px; background:var(--line); border-radius:99px; overflow:hidden; margin-top:.5rem; } .meter > div { height:100%; background:var(--accent); }
  #toast { position:fixed; left:50%; bottom:1.25rem; transform:translateX(-50%); max-width:calc(100% - 32px); background:var(--fg); color:var(--bg);
           padding:.6rem 1rem; border-radius:10px; font-size:.9rem; opacity:0; transition:opacity .2s; pointer-events:none; }
  #toast.show { opacity:1; }
  code { font:600 .82rem ui-monospace, monospace; }
  [hidden] { display:none !important; }
</style></head><body>
<header><div class="brand">Purser <span>vault</span></div><div class="row" id="who" hidden><span class="muted" id="whoName"></span><button id="signout" type="button">Sign out</button></div></header>
<main>
  <section id="signin" class="card hero" hidden>
    <h1 style="font-size:1.3rem;margin:0">Sign in to your vault</h1>
    <p>Use the passkey you set up for Purser (Face ID, Touch ID or your device PIN). Only household members can sign in.</p>
    <button class="primary" id="signinBtn" type="button">Sign in with passkey</button>
  </section>

  <section id="dash" hidden>
    <div class="row"><h2 style="margin:1rem 0 .75rem">Connections</h2><button class="primary" id="linkBtn" type="button">Link an account</button></div>
    <div id="conns" class="list"></div>

    <div id="problemsWrap" hidden><h2>Recent linking problems</h2><div id="problems" class="list"></div></div>

    <h2>Plaid</h2>
    <div class="card" id="plaid"></div>
  </section>
</main>
<div id="toast" role="status" aria-live="polite"></div>
<script src="${PLAID_LINK_JS}"></script>
<script>
  ${BROWSER_HELPERS}
  ${BROWSER_ASSERT}
  const HELP = ${JSON.stringify(ERROR_HELP)};
  const $ = (id) => document.getElementById(id);
  const api = async (path, body) => {
    const r = await fetch(path, body === undefined ? { cache: 'no-store' } :
      { method: 'POST', headers: { 'content-type': 'application/json', 'x-purser': '1' }, body: JSON.stringify(body) });
    const b = await r.json().catch(() => ({}));
    if (r.status === 401) { show('signin'); throw new Error('signed out'); }
    return b;
  };
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => '&#' + ch.charCodeAt(0) + ';');
  let toastTimer;
  const toast = (m) => { const t = $('toast'); t.textContent = m; t.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 5000); };
  const ago = (iso) => { if (!iso) return 'never'; const s = (Date.now() - Date.parse(iso)) / 1000;
    if (s < 90) return 'just now'; if (s < 5400) return Math.round(s / 60) + ' min ago'; if (s < 129600) return Math.round(s / 3600) + ' h ago'; return Math.round(s / 86400) + ' days ago'; };
  function show(which) { $('signin').hidden = which !== 'signin'; $('dash').hidden = which !== 'dash'; $('who').hidden = which !== 'dash'; }

  const STATUS = { active: ['Connected', 'ok'], needs_relink: ['Needs sign-in', 'warn'], error: ['Error', 'bad'] };
  function render(d) {
    const conns = d.connections;
    $('conns').innerHTML = conns.length ? conns.map((c) => {
      const [label, cls] = STATUS[c.status] || [c.status, 'warn'];
      const fix = c.mine && c.status !== 'active' ? '<button class="primary" data-fix="' + esc(c.id) + '">Fix connection</button>' : '';
      const sync = c.mine ? '<button data-sync="' + esc(c.id) + '">Sync now</button>' : '';
      const err = c.error ? '<div class="muted">' + esc(HELP[c.error] || 'Plaid reported an error.') + ' <code>' + esc(c.error) + '</code></div>' : '';
      return '<div class="card"><div class="row"><div><div class="name">' + esc(c.name) + '</div>' +
        '<div class="muted">' + c.accounts + ' account' + (c.accounts === 1 ? '' : 's') + ' · synced ' + ago(c.lastSyncedAt) +
        (c.mine ? '' : ' · ' + esc(c.owner) + '\\'s') + '</div></div>' +
        '<span class="pill ' + cls + '">' + label + '</span></div>' + err +
        ((fix || sync) ? '<div class="actions" style="margin-top:.75rem">' + fix + sync + '</div>' : '') + '</div>';
    }).join('') : '<div class="card hero" style="padding:2rem 1rem"><div class="name">No accounts linked yet</div><p>Link your bank or brokerage through Plaid. Your bank password goes only to Plaid and the bank.</p></div>';

    $('problemsWrap').hidden = !d.problems.length;
    $('problems').innerHTML = d.problems.map((p) =>
      '<div class="card"><div class="row"><div class="name">' + esc(p.institution_name || 'Plaid Link') + '</div><span class="muted">' + ago(p.at) + '</span></div>' +
      '<div class="muted">' + esc(HELP[p.error_code] || p.error_message || 'Linking stopped.') + ' <code>' + esc(p.error_code) + '</code></div></div>').join('');

    const p = d.plaid;
    const pct = Math.min(100, Math.round(100 * p.itemsUsed / p.itemLimit));
    $('plaid').innerHTML = !p.configured ? '<span class="muted">Plaid is not configured on this vault.</span>' :
      '<div class="row"><div><div class="name">' + (p.env === 'production' ? 'Production' : 'Sandbox (test data)') + '</div>' +
      '<div class="muted">' + p.itemsUsed + ' of ' + p.itemLimit + ' Trial plan connections used. Removing one does not free a slot.</div></div></div>' +
      '<div class="meter"><div style="width:' + pct + '%"></div></div>';
    $('linkBtn').disabled = !p.configured;
  }

  async function refresh() {
    const me = await api('/app/api/me');
    $('whoName').textContent = me.member.name;
    render(await api('/app/api/connections'));
    show('dash');
  }

  // ---- Plaid Link ----
  const store = { get: (k) => { try { return sessionStorage.getItem(k); } catch (e) { return null; } },
                  set: (k, v) => { try { sessionStorage.setItem(k, v); } catch (e) {} },
                  del: (k) => { try { sessionStorage.removeItem(k); } catch (e) {} } };
  function openLink(token, fixing, receivedRedirectUri) {
    const handler = Plaid.create({
      token, receivedRedirectUri,
      onSuccess: async (public_token, meta) => {
        store.del('purser.link');
        if (fixing) { toast('Reconnected. Syncing...'); await api('/app/api/plaid/sync', { institutionId: fixing }); }
        else {
          toast('Saving the connection...');
          const r = await api('/app/api/plaid/exchange', { public_token,
            institution_name: meta && meta.institution ? meta.institution.name : undefined,
            institution_id: meta && meta.institution ? meta.institution.institution_id : undefined });
          toast(r.ok ? 'Linked. The first sync is running.' : (r.error || 'Saving failed.'));
        }
        refresh();
        setTimeout(refresh, 8000);
      },
      onEvent: (event, m) => {
        if (!['ERROR', 'EXIT', 'FAIL_OAUTH', 'SELECT_INSTITUTION', 'HANDOFF'].includes(event)) return;
        api('/app/api/plaid/event', { event, error_code: m.error_code || undefined, error_type: m.error_type || undefined,
          error_message: m.error_message || undefined, institution_id: m.institution_id || undefined,
          institution_name: m.institution_name || undefined, status: m.exit_status || undefined, view: m.view_name || undefined }).catch(() => {});
      },
      onExit: (err) => { store.del('purser.link'); if (err) toast((HELP[err.error_code] || err.display_message || err.error_message || 'Plaid stopped.') + ' (' + err.error_code + ')'); refresh(); },
    });
    handler.open();
  }
  async function startLink(institutionId) {
    const r = await api('/app/api/plaid/link-token', institutionId ? { institutionId } : {});
    if (r.error) return toast(r.error);
    // Kept for the return from a bank's own sign-in page (/plaid/oauth).
    store.set('purser.link', JSON.stringify({ token: r.linkToken, fixing: institutionId || null }));
    openLink(r.linkToken, institutionId || null);
  }

  $('linkBtn').addEventListener('click', () => startLink());
  $('conns').addEventListener('click', async (e) => {
    const fix = e.target.closest('[data-fix]'), sync = e.target.closest('[data-sync]');
    if (fix) startLink(fix.dataset.fix);
    if (sync) { sync.disabled = true; const r = await api('/app/api/plaid/sync', { institutionId: sync.dataset.sync });
      toast(r.status === 'ok' ? 'Synced: ' + r.added + ' new transactions.' : (HELP[r.error] || 'Sync failed.') + ' (' + r.error + ')'); refresh(); }
  });

  // ---- Sign-in ----
  $('signinBtn').addEventListener('click', async () => {
    if (!passkeysWork()) return toast('This browser cannot use passkeys. Try Safari or Chrome.');
    try {
      const o = await api('/app/api/login/options', {});
      const response = await assertPasskey(o.options);
      const v = await api('/app/api/login/verify', { sid: o.sid, response });
      if (v.error) return toast(v.error);
      await boot();
    } catch (e) { if (e.message !== 'signed out') toast('The passkey prompt was cancelled. Try again.'); }
  });
  $('signout').addEventListener('click', async () => { await api('/app/api/logout', {}); show('signin'); });

  async function boot() {
    try { await refresh(); } catch (e) { return; }
    const pending = store.get('purser.link');
    if (location.pathname === '/plaid/oauth' && location.search.includes('oauth_state_id') && pending) {
      const p = JSON.parse(pending);
      const here = location.href;
      history.replaceState(null, '', '/app');
      openLink(p.token, p.fixing, here);
    }
  }
  boot();
</script></body></html>`;
}


