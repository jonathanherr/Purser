import { z } from 'zod';
import { json, NOW, type Db } from '../db/index.js';
import type { AgentClient, Member } from './auth.js';
import { accountFilter } from './visibility.js';
import { audit } from './audit.js';
import { DEFAULT_GUARDRAILS, type Guardrails } from './guardrails.js';

export const TransferChange = z.object({
  kind: z.literal('transfer_change'),
  from_account_id: z.string().uuid(),
  to_account_id: z.string().uuid(),
  new_amount_usd: z.number().positive().multipleOf(0.01),
  frequency: z.enum(['weekly', 'biweekly', 'monthly']),
});

export const Trade = z.object({
  kind: z.literal('trade'),
  account_id: z.string().uuid(),
  side: z.literal('buy'),
  ticker: z.string().regex(/^[A-Z.]{1,10}$/),
  notional_usd: z.number().positive().multipleOf(0.01),
});

export const ProposalPayload = z.discriminatedUnion('kind', [TransferChange, Trade]);
export type ProposalPayload = z.infer<typeof ProposalPayload>;

export interface Violation {
  rule: string;
  message: string;
}

export interface CreatedProposal {
  id: string;
  status: 'pending' | 'blocked';
  approvals_required: number;
  expires_at: string;
  violations: Violation[];
}

const amountOf = (p: ProposalPayload) => (p.kind === 'transfer_change' ? p.new_amount_usd : p.notional_usd);

/** Checks a proposal against every guardrail. Executors run the same check again before acting. */
export async function precheck(
  db: Db,
  agent: AgentClient,
  p: ProposalPayload,
  g: Guardrails = DEFAULT_GUARDRAILS,
): Promise<Violation[]> {
  const v: Violation[] = [];

  const frozen = await db.query<{ value: string }>(`SELECT value FROM settings WHERE key = 'execution_frozen'`);
  if (json(frozen.rows[0]?.value ?? 'false') === true) v.push({ rule: 'kill_switch', message: 'Execution is frozen' });

  const amount = amountOf(p);
  if (p.kind === 'transfer_change' && amount > g.perTransferCapUsd)
    v.push({ rule: 'per_transfer_cap', message: `Over the $${g.perTransferCapUsd} per-transfer cap` });
  if (p.kind === 'trade' && amount > g.perTradeCapUsd)
    v.push({ rule: 'per_trade_cap', message: `Over the $${g.perTradeCapUsd} per-trade cap` });

  const month = await db.query<{ total: number | null }>(
    `SELECT coalesce(sum(coalesce(json_extract(payload, '$.new_amount_usd'), json_extract(payload, '$.notional_usd'))), 0) AS total
       FROM proposals WHERE status = 'executed' AND created_at >= strftime('%Y-%m-01T00:00:00.000Z', 'now')`,
  );
  if (Number(month.rows[0]?.total ?? 0) + amount > g.monthlyCapUsd)
    v.push({ rule: 'monthly_cap', message: `Would exceed the $${g.monthlyCapUsd} monthly cap` });

  const today = await db.query<{ n: number }>(
    `SELECT count(*) AS n FROM proposals WHERE agent_id = ?1 AND created_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')`,
    [agent.id],
  );
  if ((today.rows[0]?.n ?? 0) >= g.maxProposalsPerAgentPerDay)
    v.push({ rule: 'rate_limit', message: 'Too many proposals from this agent today' });

  // Every account in a proposal must already be in the ledger and visible to the agent in detail.
  // There is no way to name a new payee: destinations can only be the household's own accounts.
  const ids = p.kind === 'transfer_change' ? [p.from_account_id, p.to_account_id] : [p.account_id];
  const f = accountFilter(agent.viewer, 'detail', 'a', 2);
  const accts = await db.query<{ id: string; type: string }>(
    `SELECT a.id, a.type FROM accounts a WHERE a.id IN (SELECT value FROM json_each(?1)) AND ${f.sql}`,
    [ids, ...f.params],
  );
  const byId = new Map(accts.rows.map((r) => [r.id, r.type]));
  for (const id of ids) {
    if (!byId.has(id)) v.push({ rule: 'unknown_account', message: `Account ${id} is not a visible household account` });
  }
  if (p.kind === 'transfer_change') {
    if (p.from_account_id === p.to_account_id)
      v.push({ rule: 'same_account', message: 'Source and destination are the same account' });
    const destType = byId.get(p.to_account_id);
    if (destType && !g.allowedDestinationTypes.includes(destType))
      v.push({ rule: 'destination_type', message: `Destination type ${destType} is not allowed` });
  } else {
    if (byId.has(p.account_id) && byId.get(p.account_id) !== 'investment')
      v.push({ rule: 'not_brokerage', message: 'Trades must target an investment account' });
    if (!g.allowedTickers.includes(p.ticker))
      v.push({ rule: 'ticker_allowlist', message: `${p.ticker} is not on the allowlist` });
  }
  return v;
}

/** Records an agent's proposal. It never executes: at best it waits for people to approve it. */
export async function createProposal(
  db: Db,
  agent: AgentClient,
  payload: ProposalPayload,
  reason: string,
  g: Guardrails = DEFAULT_GUARDRAILS,
): Promise<CreatedProposal> {
  const violations = await precheck(db, agent, payload, g);
  const status = violations.length ? 'blocked' : 'pending';
  const needsTwo =
    amountOf(payload) > g.twoPersonThresholdUsd ||
    (payload.kind === 'transfer_change' && g.twoPersonForRecurringTransfers);
  const { rows } = await db.query<{ id: string; expires_at: string }>(
    `INSERT INTO proposals (agent_id, kind, payload, reason, status, precheck, approvals_required, expires_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?8))
     RETURNING id, expires_at`,
    [agent.id, payload.kind, JSON.stringify(payload), reason, status, JSON.stringify({ violations }), needsTwo ? 2 : 1, `+${g.proposalTtlHours} hours`],
  );
  const row = rows[0]!;
  await audit(db, {
    actor: { type: 'agent', id: agent.id },
    action: 'proposal.create',
    args: payload,
    outcome: 'ok',
    detail: { proposalId: row.id, status, rules: violations.map((x) => x.rule) },
  });
  return {
    id: row.id,
    status,
    approvals_required: needsTwo ? 2 : 1,
    expires_at: new Date(row.expires_at).toISOString(),
    violations,
  };
}

export async function expireProposals(db: Db): Promise<number> {
  const { rows } = await db.query<{ id: string }>(
    `UPDATE proposals SET status = 'expired', decided_at = ${NOW}
      WHERE status = 'pending' AND expires_at < ${NOW} RETURNING id`,
  );
  for (const r of rows) {
    await audit(db, { actor: { type: 'system', id: 'expiry' }, action: 'proposal.expire', outcome: 'ok', detail: { proposalId: r.id } });
  }
  return rows.length;
}

export type DecisionResult =
  | { ok: true; status: 'pending' | 'approved' | 'rejected'; approvals: number; approvals_required: number }
  | { ok: false; error: 'not_found' | 'not_pending' | 'expired' | 'already_decided' };

/**
 * A person approves or rejects a proposal. One rejection closes it. It is approved once enough
 * different people approve. In phase 1 an approved proposal stays approved: no executor exists.
 */
export async function decide(db: Db, member: Member, proposalId: string, decision: 'approve' | 'reject'): Promise<DecisionResult> {
  // D1 has no interactive transactions, so each step is a single statement that is safe to race:
  // the decisions table's primary key stops a person deciding twice, and every status change is
  // conditional on the proposal still being pending.
  const result = await (async (): Promise<DecisionResult> => {
    const { rows } = await db.query<{ status: string; expired: number; approvals_required: number }>(
      `SELECT status, expires_at < ${NOW} AS expired, approvals_required FROM proposals WHERE id = ?1`,
      [proposalId],
    );
    const p = rows[0];
    if (!p) return { ok: false, error: 'not_found' };
    if (p.status !== 'pending') return { ok: false, error: 'not_pending' };
    if (p.expired) {
      await db.query(`UPDATE proposals SET status = 'expired', decided_at = ${NOW} WHERE id = ?1 AND status = 'pending'`, [proposalId]);
      return { ok: false, error: 'expired' };
    }
    const ins = await db.query(
      `INSERT INTO proposal_decisions (proposal_id, member_id, decision) VALUES (?1, ?2, ?3)
       ON CONFLICT DO NOTHING RETURNING proposal_id`,
      [proposalId, member.id, decision],
    );
    if (!ins.rows.length) return { ok: false, error: 'already_decided' };

    const counts = await db.query<{ n: number }>(
      `SELECT count(*) AS n FROM proposal_decisions WHERE proposal_id = ?1 AND decision = 'approve'`,
      [proposalId],
    );
    const approvals = counts.rows[0]?.n ?? 0;
    let status: 'pending' | 'approved' | 'rejected' = 'pending';
    if (decision === 'reject') status = 'rejected';
    else if (approvals >= p.approvals_required) status = 'approved';
    if (status !== 'pending') {
      const upd = await db.query(
        `UPDATE proposals SET status = ?2, decided_at = ${NOW} WHERE id = ?1 AND status = 'pending' RETURNING id`,
        [proposalId, status],
      );
      // Someone else closed it between our read and this write (a rejection, or expiry).
      if (!upd.rows.length) return { ok: false, error: 'not_pending' };
    }
    return { ok: true, status, approvals, approvals_required: p.approvals_required };
  })();
  await audit(db, {
    actor: { type: 'member', id: member.id },
    action: `proposal.${decision}`,
    outcome: result.ok ? 'ok' : 'denied',
    detail: { proposalId, ...result },
  });
  return result;
}
