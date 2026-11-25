import type { Db } from '../db/index.js';
import type { KeyProvider } from '../crypto/envelope.js';
import type { PlaidLike } from './client.js';
import { storeInstitution, syncInstitution, type SyncResult } from './sync.js';

export const DEFAULT_PRODUCTS = ['transactions', 'investments'];

/** Exchanges a public token from Plaid Link, stores the sealed access token, and runs a first sync. */
export async function linkWithPublicToken(
  db: Db,
  plaid: PlaidLike,
  kp: KeyProvider,
  args: { memberId: string; publicToken: string; products: string[]; name?: string; plaidInstitutionId?: string },
): Promise<{ institutionId: string; sync: SyncResult }> {
  const { accessToken, itemId } = await plaid.exchangePublicToken(args.publicToken);
  const institutionId = await storeInstitution(db, kp, {
    ownerMemberId: args.memberId,
    itemId,
    accessToken,
    products: args.products,
    name: args.name ?? null,
    plaidInstitutionId: args.plaidInstitutionId ?? null,
  });
  return { institutionId, sync: await syncInstitution(db, plaid, kp, institutionId) };
}

/**
 * Sandbox only: links a Plaid test institution without the Link UI. ins_109508 is
 * "First Platypus Bank", which has both transactions and investments test data.
 */
export async function linkSandboxInstitution(
  db: Db,
  plaid: PlaidLike,
  kp: KeyProvider,
  args: { memberId: string; institutionId?: string; products?: string[] },
) {
  const plaidInstitutionId = args.institutionId ?? 'ins_109508';
  const products = args.products ?? DEFAULT_PRODUCTS;
  const publicToken = await plaid.createSandboxPublicToken(plaidInstitutionId, products);
  return linkWithPublicToken(db, plaid, kp, {
    memberId: args.memberId,
    publicToken,
    products,
    plaidInstitutionId,
    name: `Sandbox ${plaidInstitutionId}`,
  });
}
