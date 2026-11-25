import type { Db } from '../db/index.js';
import { hashToken, newToken } from '../crypto/tokens.js';
import { SCOPES, type Scope } from '../vault/auth.js';
import { audit } from '../vault/audit.js';

/** Default scopes for each agent role, matching the architecture doc. */
export const AGENT_PRESETS: Record<string, Scope[]> = {
  categorizer: ['read:transactions', 'write:categories', 'write:flags'],
  'budget-keeper': ['read:transactions', 'read:budgets', 'write:flags'],
  watchdog: ['read:accounts', 'read:transactions', 'read:investments', 'write:flags'],
  planner: ['read:accounts', 'read:transactions', 'read:investments', 'read:budgets', 'propose'],
  coordinator: ['read:accounts', 'read:budgets', 'read:flags'],
};

export async function createMember(db: Db, id: string, displayName: string, role: 'owner' | 'member') {
  const token = newToken('pm');
  await db.query(
    `INSERT INTO members (id, display_name, role, token_hash) VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name, role = EXCLUDED.role, token_hash = EXCLUDED.token_hash`,
    [id, displayName, role, hashToken(token)],
  );
  await audit(db, { actor: { type: 'system', id: 'admin' }, action: 'member.create', outcome: 'ok', detail: { id, role } });
  return token;
}

export async function createAgent(db: Db, id: string, scopes: Scope[], actsFor: string) {
  for (const s of scopes) if (!(SCOPES as readonly string[]).includes(s)) throw new Error(`unknown scope ${s}`);
  if (actsFor !== 'household') {
    const { rows } = await db.query(`SELECT 1 FROM members WHERE id = ?1`, [actsFor]);
    if (!rows.length) throw new Error(`no member ${actsFor}`);
  }
  const token = newToken('pa');
  await db.query(
    `INSERT INTO agent_clients (id, name, token_hash, scopes, acts_for) VALUES (?1, ?1, ?2, ?3, ?4)
     ON CONFLICT (id) DO UPDATE SET token_hash = EXCLUDED.token_hash, scopes = EXCLUDED.scopes,
       acts_for = EXCLUDED.acts_for, revoked_at = NULL`,
    [id, hashToken(token), scopes, actsFor],
  );
  await audit(db, { actor: { type: 'system', id: 'admin' }, action: 'agent.create', outcome: 'ok', detail: { id, scopes, actsFor } });
  return token;
}
