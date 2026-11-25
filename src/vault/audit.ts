import type { Db } from '../db/index.js';
import { sha256Hex } from '../crypto/tokens.js';

export type Actor = { type: 'agent' | 'member' | 'system'; id: string };

export interface AuditEntry {
  actor: Actor;
  action: string;
  args?: unknown;
  outcome: 'ok' | 'denied' | 'error';
  resultRows?: number;
  detail?: Record<string, unknown>;
}

/**
 * Records one entry. Arguments are stored as a hash, not verbatim, so the log can be shared for
 * review without copying financial data into it.
 */
export async function audit(db: Db, e: AuditEntry): Promise<void> {
  await db.query(
    `INSERT INTO audit_log (actor_type, actor_id, action, args_hash, outcome, result_rows, detail)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
    [
      e.actor.type,
      e.actor.id,
      e.action,
      e.args === undefined ? null : sha256Hex(JSON.stringify(e.args)),
      e.outcome,
      e.resultRows ?? null,
      e.detail ? JSON.stringify(e.detail) : null,
    ],
  );
}
