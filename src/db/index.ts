/**
 * The vault's database handle. Production is Cloudflare D1; local development and tests use
 * Node's built-in SQLite. Both run the same SQLite SQL, so every query in the vault is plain,
 * parameterised SQL with numbered placeholders (?1, ?2, ...).
 *
 * D1 has no interactive transactions. Writes that must land together go through batch(),
 * which is atomic on both backends (and counts as one query against D1's per-request limit).
 */
export interface Stmt {
  sql: string;
  params?: unknown[];
}

export interface Db {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
  /** Runs the statements atomically: all of them or none. */
  batch(stmts: Stmt[]): Promise<void>;
  /** Runs several statements with no parameters (migrations). */
  exec(sql: string): Promise<void>;
  close(): Promise<void>;
}

/** SQL for "now" as an ISO-8601 UTC timestamp. Every stored timestamp uses this format, so they compare as text. */
export const NOW = `strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`;

/** SQLite can't bind booleans, arrays or objects. Booleans become 0/1; arrays and objects become JSON text. */
export function bindable(v: unknown): unknown {
  if (v === undefined || v === null) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (v instanceof Date) return v.toISOString();
  if (typeof v === 'object' && !(v instanceof Uint8Array)) return JSON.stringify(v);
  return v;
}

/** Parses a JSON text column, passing through values that are already parsed. */
export function json<T = unknown>(v: unknown): T {
  return (typeof v === 'string' ? JSON.parse(v) : v) as T;
}

// ---- Cloudflare D1 (inside a Worker) ----

/** The slice of the D1 binding the vault uses. */
export interface D1Like {
  prepare(sql: string): D1StatementLike;
  batch(stmts: D1StatementLike[]): Promise<unknown>;
  exec(sql: string): Promise<unknown>;
}
export interface D1StatementLike {
  bind(...values: unknown[]): D1StatementLike;
  all<T>(): Promise<{ results: T[] }>;
}

export function d1Db(d1: D1Like): Db {
  const prep = (sql: string, params: unknown[] = []) => d1.prepare(sql).bind(...params.map(bindable));
  return {
    query: async <T>(sql: string, params?: unknown[]) => ({ rows: (await prep(sql, params).all<T>()).results }),
    batch: async (stmts) => {
      if (stmts.length) await d1.batch(stmts.map((s) => prep(s.sql, s.params)));
    },
    exec: async (sql) => {
      await d1.exec(sql);
    },
    close: async () => {},
  };
}

// ---- D1 over Cloudflare's HTTP API (admin CLI against the production database) ----

export function d1HttpDb(opts: { accountId: string; databaseId: string; apiToken: string }): Db {
  const url = `https://api.cloudflare.com/client/v4/accounts/${opts.accountId}/d1/database/${opts.databaseId}/query`;
  const run = async <T>(sql: string, params: unknown[] = []): Promise<T[]> => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { authorization: `Bearer ${opts.apiToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ sql, params: params.map(bindable) }),
    });
    const body = (await res.json()) as {
      success: boolean;
      errors?: { message: string }[];
      result?: { results: T[]; success: boolean }[];
    };
    if (!res.ok || !body.success) {
      throw new Error(`D1 API ${res.status}: ${(body.errors ?? []).map((e) => e.message).join('; ')}`);
    }
    return body.result?.at(-1)?.results ?? [];
  };
  return {
    query: async <T>(sql: string, params?: unknown[]) => ({ rows: await run<T>(sql, params) }),
    // The HTTP API runs one statement per call. Admin commands only issue single statements;
    // anything that needs atomic writes runs inside the Worker, where batch() is real.
    batch: async (stmts) => {
      for (const s of stmts) await run(s.sql, s.params);
    },
    exec: async (sql) => {
      await run(sql);
    },
    close: async () => {},
  };
}
