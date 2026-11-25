import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type { Db } from './index.js';

// Kept apart from db/index.ts so the Workers bundle never touches the filesystem.
// Migrations run from Node (the CLI or the deploy workflow), not from the Worker.
const MIGRATIONS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../migrations');

export async function migrate(db: Db, dir = MIGRATIONS_DIR): Promise<string[]> {
  await db.exec(
    'CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())',
  );
  const applied = new Set(
    (await db.query<{ name: string }>('SELECT name FROM schema_migrations')).rows.map((r) => r.name),
  );
  const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
  const ran: string[] = [];
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = await readFile(path.join(dir, file), 'utf8');
    await db.tx(async (t) => {
      await t.exec(sql);
      await t.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
    });
    ran.push(file);
  }
  return ran;
}
