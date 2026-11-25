import type { Db } from '../db/index.js';
import { ProposalPayload } from './proposals.js';

const usd = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD' });

async function accountLabel(db: Db, id: string): Promise<string> {
  const { rows } = await db.query<{ name: string; mask: string | null }>(`SELECT name, mask FROM accounts WHERE id = $1`, [id]);
  const a = rows[0];
  return a ? `${a.name}${a.mask ? ` (…${a.mask})` : ''}` : 'an unknown account';
}

/**
 * The sentence a person sees on an approval card. It is built only from validated, structured
 * fields and ledger names, so an agent cannot word its way into a misleading approval.
 */
export async function renderProposal(db: Db, payload: unknown): Promise<string> {
  const parsed = ProposalPayload.safeParse(payload);
  if (!parsed.success) return 'Unreadable proposal: do not approve';
  const p = parsed.data;
  if (p.kind === 'transfer_change') {
    return `Change the ${p.frequency} transfer from ${await accountLabel(db, p.from_account_id)} to ${await accountLabel(db, p.to_account_id)} to ${usd(p.new_amount_usd)}`;
  }
  return `Buy ${usd(p.notional_usd)} of ${p.ticker} in ${await accountLabel(db, p.account_id)}`;
}
