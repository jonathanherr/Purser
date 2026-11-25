/**
 * Finds the D1 database named D1_DATABASE_NAME (default purser), creating it if it doesn't
 * exist, and prints its id. Used by the deploy workflow so the whole Cloudflare setup happens in
 * GitHub Actions. Idempotent: an existing database is left as is.
 *
 * Env: CLOUDFLARE_API_TOKEN (D1: Edit), CLOUDFLARE_ACCOUNT_ID.
 * With GITHUB_OUTPUT set, also writes `id=<id>` there.
 */
import { appendFile } from 'node:fs/promises';

const { CLOUDFLARE_API_TOKEN: token, CLOUDFLARE_ACCOUNT_ID: account } = process.env;
const name = process.env.D1_DATABASE_NAME || 'purser';
if (!token || !account) throw new Error('Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID');

const base = `https://api.cloudflare.com/client/v4/accounts/${account}/d1/database`;
const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };

async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, headers });
  const body = (await res.json()) as { success: boolean; result: T; errors?: { message: string }[] };
  if (!res.ok || !body.success) {
    throw new Error(`Cloudflare API ${res.status}: ${(body.errors ?? []).map((e) => e.message).join('; ')}`);
  }
  return body.result;
}

const found = await call<{ uuid: string; name: string }[]>(`${base}?name=${encodeURIComponent(name)}`);
let id = found.find((d) => d.name === name)?.uuid;
if (id) {
  console.log(`D1 database ${name} exists`);
} else {
  id = (await call<{ uuid: string }>(base, { method: 'POST', body: JSON.stringify({ name }) })).uuid;
  console.log(`Created D1 database ${name}`);
}
console.log(id);
if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `id=${id}\n`);
