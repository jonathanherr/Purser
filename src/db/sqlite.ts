import { DatabaseSync } from 'node:sqlite';
import { bindable, type Db } from './index.js';

/**
 * Node's built-in SQLite behind the vault's Db interface, for local development and tests.
 * Kept out of db/index.ts so the Worker bundle never imports node:sqlite.
 * Foreign keys are switched on to match D1, which enforces them.
 */
export function sqliteDb(path = ':memory:'): Db {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
  const run = (sql: string, params: unknown[] = []) =>
    db.prepare(sql).all(...(params.map(bindable) as never[])) as Record<string, unknown>[];
  return {
    query: async <T>(sql: string, params?: unknown[]) => ({ rows: run(sql, params).map((r) => ({ ...r })) as T[] }),
    batch: async (stmts) => {
      db.exec('BEGIN');
      try {
        for (const s of stmts) run(s.sql, s.params);
        db.exec('COMMIT');
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
    },
    exec: async (sql) => {
      db.exec(sql);
    },
    close: async () => {
      db.close();
    },
  };
}
