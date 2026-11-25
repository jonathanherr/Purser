import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type { Db } from './index.js';

// Local and test databases only. Production D1 is migrated by `wrangler d1 migrations apply`,
// which reads the same migrations/ folder. Kept apart from db/index.ts so the Worker bundle
// never touches the filesystem.
const MIGRATIONS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../migrations');

export async function migrate(db: Db, dir = MIGRATIONS_DIR): Promise<string[]> {
  await db.exec(
    `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))`,
  );
  const applied = new Set(
    (await db.query<{ name: string }>('SELECT name FROM schema_migrations')).rows.map((r) => r.name),
  );
  const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
  const ran: string[] = [];
  for (const file of files) {
    if (applied.has(file)) continue;
    if (!/^[\w.-]+$/.test(file)) throw new Error(`unexpected migration file name ${file}`);
    const sql = await readFile(path.join(dir, file), 'utf8');
    try {
      await db.exec(`BEGIN;\n${sql}\n;INSERT INTO schema_migrations (name) VALUES ('${file}');\nCOMMIT;`);
    } catch (err) {
      await db.exec('ROLLBACK').catch(() => {});
      throw err;
    }
    ran.push(file);
  }
  return ran;
}
