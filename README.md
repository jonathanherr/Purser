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

### Connect Claude (custom connector)

The vault's MCP endpoint is an OAuth-protected remote MCP server, so it can be added to Claude
as a custom connector. Connections are **read-only** (accounts, transactions, investments,
budgets, flags) and act for one member, so visibility rules apply as usual.

**Once per member, add a passkey.** An admin creates a one-time link (it works once, for 24
hours; it is a secret, so don't run this in public Actions logs):

```sh
PURSER_DB=remote npm run purser -- passkey:link --member jonathan --url https://<vault host>
```

The member opens it on their phone or computer and taps **Create passkey** (Face ID, Touch ID
or device PIN). Only the passkey's public key is stored (`member_passkeys`).

**Connecting:**

1. In Claude, add a custom connector with the URL `https://<vault host>/mcp`.
2. Claude opens the Purser sign-in page. Tap **Approve with passkey**. Claude is connected.
   This finishes in one visit, so it works in the Claude mobile app.

**Fallback without a passkey:** the same page shows a pairing code such as `K7QM-3XPA`. Approve
it within 15 minutes from Actions → **Vault admin** → `connect-approve`, with the code and the
member id, while the page stays open; it then continues by itself.

Each connection is an `agent_clients` row named `connector-<member>-…`; set its `revoked_at` to
disconnect it. Set a passkey's `revoked_at` to stop it approving sign-ins. Only Claude's own
callback URLs can register (see `src/http/oauth.ts`).

### Link a real account

1. Get Plaid production keys: in the Plaid Dashboard apply for the free **Trial plan** (choose
   "Personal use"; up to 10 connections). Set the secret with `gh secret set PLAID_SECRET_PRODUCTION`.
   While that secret exists, deploys and the Vault admin workflow use Plaid production.
2. In the Plaid Dashboard, add `https://<vault host>/plaid/oauth` to **Allowed redirect URIs**
   (needed for banks that use their own sign-in screen).
3. Open `https://<vault host>/link`, sign in with your passkey and pick your bank in Plaid's
   window. Bank credentials go only to Plaid and the bank. The first sync starts right away.

### Local Worker

```sh
echo "VAULT_MASTER_KEY=..." > .dev.vars   # git-ignored; add PLAID_* too if you have them
npx wrangler d1 migrations apply DB --local
npx wrangler dev
```

## Data at rest

- **Encrypted ledger.** Amounts, merchant names, account names and numbers, balances and
  positions are stored as one AES-256-GCM ciphertext per row (`sealed` columns), with a key
  derived from `VAULT_MASTER_KEY`. Ids, dates, categories and account types stay in the clear so
  the vault can find rows. Each ciphertext is bound to its row. Plaid access tokens were already
  envelope-encrypted. See `src/crypto/fields.ts`.
- **13 months of history.** Older transactions are never stored, and the scheduled sync prunes
  transactions, balance history and holdings snapshots as they age out.
- **What this protects against:** a database export or backup, a leaked D1 API token, or anyone
  browsing D1 in the Cloudflare dashboard. **What it doesn't:** someone in control of the whole
  Cloudflare account, who could deploy code that reads the Worker's secret. A KMS key provider
  outside Cloudflare closes that gap (see "Not yet done").
- Totals and budgets are computed in the Worker after decrypting. A year of a household's
  transactions is a few thousand rows, which decrypts in a few milliseconds.

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
