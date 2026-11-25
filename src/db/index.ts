import pg from 'pg';

/**
 * A minimal database handle. Both node-postgres and PGlite (used in tests) fit behind it,
 * so every query in the vault is plain, parameterised SQL.
 */
export interface Db {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
  /** Runs several statements with no parameters (migrations). */
  exec(sql: string): Promise<void>;
  /** Runs fn inside one transaction. Nested calls reuse the outer transaction. */
  tx<T>(fn: (db: Db) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/**
 * On Node one pool lives for the whole process. On Workers, open one per request (through
 * Hyperdrive, which does the real pooling) with a small max, and close it when the request ends.
 */
export function pgDb(connectionString: string, opts: { max?: number } = {}): Db {
  const pool = new pg.Pool({ connectionString, max: opts.max ?? 10 });
  // Return numerics as strings would leak into JSON as strings; parse them to numbers.
  pg.types.setTypeParser(1700, (v) => Number(v));
  pg.types.setTypeParser(20, (v) => Number(v));
  const fromClient = (client: pg.PoolClient): Db => ({
    query: async (sql, params) => ({ rows: (await client.query(sql, params as unknown[])).rows }),
    exec: async (sql) => {
      await client.query(sql);
    },
    tx: (fn) => fn(fromClient(client)),
    close: async () => {},
  });
  return {
    query: async (sql, params) => ({ rows: (await pool.query(sql, params as unknown[])).rows }),
    exec: async (sql) => {
      await pool.query(sql);
    },
    tx: async (fn) => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn(fromClient(client));
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    },
    close: () => pool.end(),
  };
}
