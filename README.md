# Purser

Purser is a household budgeting system where AI agents get deep read access to bank and brokerage
accounts, but only through one service we control: **the vault**. Agents never hold credentials,
never call a bank, and can never move money on their own.

This repository is the phase-1 vault: read-only, Plaid sandbox only.

Architecture doc: https://claude.ai/artifact/8CUNYARkDSuECRkHCHsVoR

## What's here

| Part | Where | What it does |
| --- | --- | --- |
| Ledger | `migrations/0001_init.sql` | SQLite schema (Cloudflare D1 in production): accounts, transactions, holdings, budgets, flags, proposals, append-only audit log |
| Sync | `src/plaid/sync.ts` | Cursor-based `/transactions/sync`, accounts and balances, investment holdings |
| Secrets | `src/crypto/envelope.ts` | Plaid access tokens sealed with AES-256-GCM per-row data keys, wrapped by a master key (KMS in production) |
| Visibility | `src/vault/visibility.ts` | Per-account `shared` / `private` / `hidden`, enforced in SQL on every query |
| Tools | `src/vault/tools.ts` | The whole agent tool surface. No tool executes anything or returns a credential |
| MCP server | `src/mcp/server.ts`, `src/http/app.ts` | Streamable HTTP at `/mcp`; each agent sees only the tools its scopes allow; every call is audited |
| Proposals | `src/vault/proposals.ts` | Agents propose, the vault pre-checks guardrails, people approve. No executors exist in phase 1 |
| Guardrails | `src/vault/guardrails.ts` | Caps, allowlists, two-person threshold, expiry, kill switch: in code, not in prompts |

## Run it locally

Needs Node 22.13 or later (it uses Node's built-in SQLite). Get free sandbox keys from https://dashboard.plaid.com.

```sh
npm install
cp .env.example .env            # fill in VAULT_MASTER_KEY, PLAID_CLIENT_ID, PLAID_SECRET
# generate a master key:  node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
set -a; . ./.env; set +a

npm run migrate                                                              # creates purser.db
npm run purser -- member:create --id jonathan --name Jonathan --role owner   # prints a token once
npm run purser -- sandbox:link --member jonathan                            # links First Platypus Bank (sandbox)
npm run purser -- agent:create --id watchdog --acts-for jonathan             # prints the agent's MCP token once
npm run dev                                                                  # vault on :8787
```

Point any MCP client at `http://localhost:8787/mcp` with `Authorization: Bearer <agent token>`.

Agent presets (`--preset` or the agent id): `categorizer`, `budget-keeper`, `watchdog`, `planner`,
`coordinator`. `--acts-for` is a member id, or `household` for runs that should see only shared
detail.

## People API (phase 1)

Bearer member token. Passkeys replace these in phase 1c.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/me/proposals?status=pending` | Proposals with the vault's own one-line summary |
| POST | `/me/proposals/:id/decision` | `{"decision": "approve" \| "reject"}` |
| PATCH | `/me/accounts/:id` | `{"visibility": "shared" \| "private" \| "hidden"}` (owner only) |
| POST | `/me/freeze` | Kill switch: blocks every new proposal |
| POST | `/me/link/token`, `/me/link/exchange` | Plaid Link flow for a future web UI |
| POST | `/me/sandbox/link` | Link a sandbox institution without the Link UI |

`POST /plaid/webhook` accepts Plaid webhooks, verified against Plaid's signed JWT, and triggers a sync.

## Deploy to Cloudflare

The vault runs as a Cloudflare Worker (`src/worker.ts`, config in `wrangler.jsonc`) on **D1**,
Cloudflare's SQLite database. Local development and tests use Node's built-in SQLite, so the
same SQL runs everywhere.

| Node (local) | Worker (production) |
| --- | --- |
| SQLite file through `node:sqlite` | D1, bound as `env.DB` |
| `setInterval` sync and expiry | Cron Triggers: expiry every 15 minutes, Plaid sync every 6 hours |
| `npm run migrate` | `wrangler d1 migrations apply`, in the deploy workflow before each deploy |
| Background webhook sync | `ctx.waitUntil` |

D1 has no interactive transactions. Writes that must land together (everything one Plaid sync
writes, cursor included) go through `db.batch()`, which is atomic and counts as one query
against D1's per-request limit. Approvals are single statements that are safe to race.

Everything fits the Workers Free plan. The Worker ships with no public URL (`workers_dev: false`,
`preview_urls: false`); turn one on when you want Plaid webhooks and remote agents to reach it.

### Set up and deploy from GitHub Actions

`.github/workflows/deploy.yml` does the whole Cloudflare setup, and every step is safe to re-run:
tests, find or create the `purser` D1 database, apply migrations, upload the Worker secrets, and
deploy. It runs on every push to `main` (and by hand from the Actions tab), but only after you
turn it on:

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `CLOUDFLARE_API_TOKEN` | a token with **Workers Scripts: Edit** and **D1: Edit** on your account |
| Secret | `CLOUDFLARE_ACCOUNT_ID` | your account id |
| Secret | `VAULT_MASTER_KEY` | 32 random bytes, base64 (`node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`) |
| Secret | `PLAID_CLIENT_ID`, `PLAID_SECRET` | sandbox keys (optional; without them Plaid is off) |
| Variable | `PURSER_DEPLOY` | `enabled` |

Then run the workflow from the Actions tab, or merge to `main`. Add required reviewers to the
`production` environment if you want to approve each deploy.

Keep a copy of `VAULT_MASTER_KEY` somewhere safe: it is the only way to open the Plaid access
tokens stored in D1 (sandbox items can always be re-linked). It moves to a KMS in phase 1c.

### Admin commands against production

Members and agents are created from your machine, straight into D1 through Cloudflare's API.
Admin commands are never exposed over HTTP.

```sh
export PURSER_DB=remote CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_API_TOKEN=... D1_DATABASE_ID=...
npm run purser -- member:create --id jonathan --name Jonathan --role owner
npm run purser -- agent:create --id watchdog --acts-for jonathan
```

Link sandbox banks through the Worker (`POST /me/sandbox/link` with a member token), so the
master key stays in the Worker. While the Worker has no public URL, run the **Vault admin**
workflow from the Actions tab instead: `sandbox-link` links a Plaid test bank for a member and
runs a first sync, and `sync` syncs every linked bank. It uses the deploy's repository secrets.

### Local Worker

```sh
echo "VAULT_MASTER_KEY=..." > .dev.vars   # git-ignored; add PLAID_* too if you have them
npx wrangler d1 migrations apply DB --local
npx wrangler dev
```

## Tests

```sh
npm test          # Vitest on in-memory SQLite, plus a suite on the real D1 engine (Miniflare); no network or Plaid keys
npm run typecheck
npx wrangler deploy --dry-run --outdir dist   # bundles the Worker, uploads nothing
```

## Not yet done

- KMS key provider (the `KeyProvider` interface is ready; `LocalKeyProvider` is for dev only, and the
  Worker uses it too, with the master key as a Worker secret, until a KMS provider exists)
- Passkey sign-in and the approval PWA
- The agents themselves and the weekly digest (phase 1b)
- Executors for transfers and trades (phase 2). Keep them in a separate deploy with separate credentials
