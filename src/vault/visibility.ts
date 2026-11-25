import type { Viewer } from './auth.js';

/**
 * Household visibility, enforced in SQL on every query.
 *
 * - detail: individual transactions and holdings. Shared accounts, plus the viewer's own.
 * - summary: balances and category totals. Everything except the partner's hidden accounts.
 *   A household-wide viewer gets shared and private accounts at summary level, never hidden ones.
 *
 * Returns a SQL predicate on the accounts alias and the parameters it needs, numbered from `next`.
 */
export function accountFilter(
  viewer: Viewer,
  level: 'detail' | 'summary',
  alias: string,
  next: number,
): { sql: string; params: unknown[] } {
  if (viewer.kind === 'household') {
    return level === 'detail'
      ? { sql: `${alias}.visibility = 'shared'`, params: [] }
      : { sql: `${alias}.visibility IN ('shared', 'private')`, params: [] };
  }
  return level === 'detail'
    ? { sql: `(${alias}.visibility = 'shared' OR ${alias}.owner_member_id = ?${next})`, params: [viewer.memberId] }
    : { sql: `(${alias}.visibility <> 'hidden' OR ${alias}.owner_member_id = ?${next})`, params: [viewer.memberId] };
}
