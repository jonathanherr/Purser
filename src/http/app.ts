import { Hono, type Context } from 'hono';
import { z } from 'zod';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { json, NOW, type Db } from '../db/index.js';
import type { KeyProvider } from '../crypto/envelope.js';
import type { PlaidLike } from '../plaid/client.js';
import { authenticateAgent, authenticateMember, parseBearer, type Member } from '../vault/auth.js';
import { audit } from '../vault/audit.js';
import { buildMcpServer } from '../mcp/server.js';
import { oauthRoutes, resourceMetadataUrl } from './oauth.js';
import { decide } from '../vault/proposals.js';
import { renderProposal } from '../vault/render.js';
import { verifyPlaidWebhook } from '../plaid/webhook.js';
import { syncInstitution } from '../plaid/sync.js';
import { linkSandboxInstitution, linkWithPublicToken, DEFAULT_PRODUCTS } from '../plaid/link.js';

export interface AppDeps {
  db: Db;
  kp: KeyProvider;
  plaid?: PlaidLike;
  plaidWebhookUrl?: string;
  /** Tests can replace webhook verification. Production always uses Plaid's signed JWT. */
  verifyWebhook?: (rawBody: string, jwt: string | undefined) => Promise<boolean>;
  /**
   * Runs work after the response is sent. On Node a dangling promise is fine; on Workers it
   * must go to ctx.waitUntil or the runtime cancels it when the response returns.
   */
  background?: (work: Promise<unknown>) => void;
}

type Env = { Variables: { member: Member } };

export function createApp(deps: AppDeps) {
  const { db, kp } = deps;
  const app = new Hono<Env>();

  app.get('/healthz', (c) => c.json({ ok: true }));
  app.route('/', oauthRoutes(db));

  // ---- Agents: MCP over Streamable HTTP, stateless, one server per request ----
  app.all('/mcp', async (c) => {
    const agent = await authenticateAgent(db, parseBearer(c.req.header('authorization')));
    if (!agent) {
      await audit(db, { actor: { type: 'agent', id: 'unknown' }, action: 'mcp.auth', outcome: 'denied' });
      // Points OAuth clients (Claude connectors) at the sign-in flow in ./oauth.ts.
      return c.json({ error: 'unauthorized' }, 401, {
        'WWW-Authenticate': `Bearer realm="purser", resource_metadata="${resourceMetadataUrl(c.req.url)}"`,
      });
    }
    const server = buildMcpServer(db, agent, kp.fields);
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    await server.connect(transport);
    return transport.handleRequest(c.req.raw);
  });

  // ---- Plaid webhooks ----
  app.post('/plaid/webhook', async (c) => {
    const raw = await c.req.text();
    const verify =
      deps.verifyWebhook ??
      (deps.plaid ? (body: string, jwt: string | undefined) => verifyPlaidWebhook(deps.plaid!, body, jwt) : null);
    if (!verify || !(await verify(raw, c.req.header('plaid-verification')))) {
      await audit(db, { actor: { type: 'system', id: 'plaid-webhook' }, action: 'webhook.verify', outcome: 'denied' });
      return c.json({ error: 'invalid signature' }, 401);
    }
    const body = JSON.parse(raw) as { webhook_type?: string; webhook_code?: string; item_id?: string };
    const triggers =
      (body.webhook_type === 'TRANSACTIONS' && body.webhook_code === 'SYNC_UPDATES_AVAILABLE') ||
      (body.webhook_type === 'HOLDINGS' && body.webhook_code === 'DEFAULT_UPDATE');
    if (triggers && body.item_id && deps.plaid) {
      const { rows } = await db.query<{ id: string }>(`SELECT id FROM institutions WHERE plaid_item_id = ?1`, [body.item_id]);
      const id = rows[0]?.id;
      // Answer Plaid quickly; the sync runs in the background.
      if (id) {
        const work = syncInstitution(db, deps.plaid, kp, id).catch((e) => console.error('webhook sync failed', e));
        if (deps.background) deps.background(work);
        else void work;
      }
    }
    return c.json({ ok: true });
  });

  // ---- People: phase 1 uses bearer tokens; passkeys replace them in phase 1c ----
  const people = new Hono<Env>();
  people.use('*', async (c, next) => {
    const member = await authenticateMember(db, parseBearer(c.req.header('authorization')));
    if (!member) return c.json({ error: 'unauthorized' }, 401);
    c.set('member', member);
    await next();
  });

  people.get('/proposals', async (c) => {
    const status = c.req.query('status') ?? 'pending';
    const { rows } = await db.query<{ id: string; kind: string; payload: string; reason: string; status: string; approvals_required: number; expires_at: string; agent: string }>(
      `SELECT p.id, p.kind, p.payload, p.reason, p.status, p.approvals_required, p.expires_at, ac.name AS agent
         FROM proposals p JOIN agent_clients ac ON ac.id = p.agent_id
        WHERE p.status = ?1 ORDER BY p.created_at DESC LIMIT 100`,
      [status],
    );
    const out = [];
    for (const r of rows) {
      // People see the vault's own rendering of the action, built from structured fields.
      // The agent's free-text reason is shown separately and labelled as such.
      const payload = json(r.payload);
      out.push({ ...r, payload, summary: await renderProposal(db, kp.fields, payload), agent_reason: r.reason });
    }
    return c.json(out);
  });

  people.post('/proposals/:id/decision', async (c) => {
    const body = z.object({ decision: z.enum(['approve', 'reject']) }).safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: 'decision must be approve or reject' }, 400);
    const id = c.req.param('id');
    if (!z.string().uuid().safeParse(id).success) return c.json({ error: 'not_found' }, 404);
    const result = await decide(db, c.get('member'), id, body.data.decision);
    if (!result.ok) return c.json(result, result.error === 'not_found' ? 404 : 409);
    return c.json(result);
  });

  people.patch('/accounts/:id', async (c) => {
    const body = z.object({ visibility: z.enum(['shared', 'private', 'hidden']) }).safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: 'visibility must be shared, private or hidden' }, 400);
    const member = c.get('member');
    const id = c.req.param('id');
    if (!z.string().uuid().safeParse(id).success) return c.json({ error: 'not_found' }, 404);
    const { rows } = await db.query(
      `UPDATE accounts SET visibility = ?3, updated_at = ${NOW} WHERE id = ?1 AND owner_member_id = ?2 RETURNING id`,
      [id, member.id, body.data.visibility],
    );
    await audit(db, {
      actor: { type: 'member', id: member.id },
      action: 'account.visibility',
      outcome: rows.length ? 'ok' : 'denied',
      detail: { accountId: id, visibility: body.data.visibility },
    });
    return rows.length ? c.json({ ok: true }) : c.json({ error: 'only the owner can change visibility' }, 403);
  });

  people.post('/freeze', async (c) => {
    const member = c.get('member');
    await db.query(`UPDATE settings SET value = 'true' WHERE key = 'execution_frozen'`);
    await audit(db, { actor: { type: 'member', id: member.id }, action: 'kill_switch.freeze', outcome: 'ok' });
    return c.json({ frozen: true });
  });

  const needPlaid = (c: Context) => (deps.plaid ? null : c.json({ error: 'Plaid is not configured' }, 503));

  people.post('/link/token', async (c) => {
    const missing = needPlaid(c);
    if (missing) return missing;
    return c.json(await deps.plaid!.createLinkToken(c.get('member').id, deps.plaidWebhookUrl));
  });

  people.post('/link/exchange', async (c) => {
    const missing = needPlaid(c);
    if (missing) return missing;
    const body = z.object({ public_token: z.string().min(1), institution_name: z.string().optional() }).safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: 'public_token required' }, 400);
    const result = await linkWithPublicToken(db, deps.plaid!, kp, {
      memberId: c.get('member').id,
      publicToken: body.data.public_token,
      products: DEFAULT_PRODUCTS,
      name: body.data.institution_name,
    });
    return c.json(result);
  });

  people.post('/sandbox/link', async (c) => {
    const missing = needPlaid(c);
    if (missing) return missing;
    const body = z.object({ institution_id: z.string().optional() }).parse(await c.req.json().catch(() => ({})));
    return c.json(await linkSandboxInstitution(db, deps.plaid!, kp, { memberId: c.get('member').id, institutionId: body.institution_id }));
  });

  app.route('/me', people);
  return app;
}
