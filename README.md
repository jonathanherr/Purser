# Purser

Purser is a household budgeting system where AI agents get deep read access to bank and brokerage
accounts, but only through one service we control: **the vault**. Agents never hold credentials,
never call a bank, and can never move money on their own.

This repository is the phase-1 vault: read-only, Plaid sandbox only.

Architecture doc: https://claude.ai/artifact/8CUNYARkDSuECRkHCHsVoR

## What's here

| Part | Where | What it does |
| --- | --- | --- |
| Ledger | `migrations/001_init.sql` | Postgres schema: accounts, transactions, holdings, budgets, flags, proposals, append-only audit log |
| Sync | `src/plaid/sync.ts` | Cursor-based `/transactions/sync`, accounts and balances, investment holdings |
| Secrets | `src/crypto/envelope.ts` | Plaid access tokens sealed with AES-256-GCM per-row data keys, wrapped by a master key (KMS in production) |
| Visibility | `src/vault/visibility.ts` | Per-account `shared` / `private` / `hidden`, enforced in SQL on every query |
| Tools | `src/vault/tools.ts` | The whole agent tool surface. No tool executes anything or returns a credential |
| MCP server | `src/mcp/server.ts`, `src/http/app.ts` | Streamable HTTP at `/mcp`; each agent sees only the tools its scopes allow; every call is audited |
| Proposals | `src/vault/proposals.ts` | Agents propose, the vault pre-checks guardrails, people approve. No executors exist in phase 1 |
| Guardrails | `src/vault/guardrails.ts` | Caps, allowlists, two-person threshold, expiry, kill switch: in code, not in prompts |

## Run it locally

Needs Node 22 and a Postgres database. Get free sandbox keys from https://dashboard.plaid.com.

```sh
npm install
cp .env.example .env            # fill in DATABASE_URL, PLAID_CLIENT_ID, PLAID_SECRET
# generate a master key:  node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
set -a; . ./.env; set +a

npm run migrate
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

## Tests

```sh
npm test          # Vitest with PGlite (in-process Postgres); no network or Plaid keys needed
npm run typecheck
```

## Not yet done

- KMS key provider (the `KeyProvider` interface is ready; `LocalKeyProvider` is for dev only)
- Passkey sign-in and the approval PWA
- The agents themselves and the weekly digest (phase 1b)
- Executors for transfers and trades (phase 2). Keep them in a separate deploy with separate credentials
