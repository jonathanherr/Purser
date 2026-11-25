import { json, type Db } from '../db/index.js';
import { hashToken } from '../crypto/tokens.js';

export const SCOPES = [
  'read:accounts',
  'read:transactions',
  'read:investments',
  'read:budgets',
  'read:flags',
  'write:categories',
  'write:flags',
  'propose',
] as const;
export type Scope = (typeof SCOPES)[number];

/** Who an agent run is acting for. A household viewer sees only shared detail. */
export type Viewer = { kind: 'household' } | { kind: 'member'; memberId: string };

export interface AgentClient {
  id: string;
  name: string;
  scopes: Scope[];
  viewer: Viewer;
}

export interface Member {
  id: string;
  displayName: string;
  role: 'owner' | 'member';
}

export function parseBearer(header: string | undefined | null): string | null {
  const m = header?.match(/^Bearer\s+(\S+)$/i);
  return m?.[1] ?? null;
}

export async function authenticateAgent(db: Db, token: string | null): Promise<AgentClient | null> {
  if (!token) return null;
  const { rows } = await db.query<{ id: string; name: string; scopes: string; acts_for: string }>(
    `SELECT id, name, scopes, acts_for FROM agent_clients WHERE token_hash = ?1 AND revoked_at IS NULL`,
    [hashToken(token)],
  );
  const r = rows[0];
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    scopes: json<string[]>(r.scopes).filter((s): s is Scope => (SCOPES as readonly string[]).includes(s)),
    viewer: r.acts_for === 'household' ? { kind: 'household' } : { kind: 'member', memberId: r.acts_for },
  };
}

export async function authenticateMember(db: Db, token: string | null): Promise<Member | null> {
  if (!token) return null;
  const { rows } = await db.query<{ id: string; display_name: string; role: 'owner' | 'member' }>(
    `SELECT id, display_name, role FROM members WHERE token_hash = ?1`,
    [hashToken(token)],
  );
  const r = rows[0];
  return r ? { id: r.id, displayName: r.display_name, role: r.role } : null;
}
