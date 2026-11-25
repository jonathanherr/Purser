import type { Db } from '../db/index.js';
import { ProposalPayload } from './proposals.js';
import { rowId, type AccountFields, type FieldCipher } from '../crypto/fields.js';

const usd = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD' });

async function accountLabel(db: Db, fc: FieldCipher, id: string): Promise<string> {
  const { rows } = await db.query<{ plaid_account_id: string; sealed: string }>(
    `SELECT plaid_account_id, sealed FROM accounts WHERE id = ?1`,
    [id],
  );
  const r = rows[0];
  if (!r) return 'an unknown account';
  const a = fc.open<AccountFields>(r.sealed, rowId.account(r.plaid_account_id));
  return `${a.name}${a.mask ? ` (…${a.mask})` : ''}`;
}

/**
 * The sentence a person sees on an approval card. It is built only from validated, structured
 * fields and ledger names, so an agent cannot word its way into a misleading approval.
 */
export async function renderProposal(db: Db, fc: FieldCipher, payload: unknown): Promise<string> {
  const parsed = ProposalPayload.safeParse(payload);
  if (!parsed.success) return 'Unreadable proposal: do not approve';
  const p = parsed.data;
  if (p.kind === 'transfer_change') {
    return `Change the ${p.frequency} transfer from ${await accountLabel(db, fc, p.from_account_id)} to ${await accountLabel(db, fc, p.to_account_id)} to ${usd(p.new_amount_usd)}`;
  }
  return `Buy ${usd(p.notional_usd)} of ${p.ticker} in ${await accountLabel(db, fc, p.account_id)}`;
}
