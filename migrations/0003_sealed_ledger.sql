-- Encrypts the ledger at rest and caps it at 13 months (see src/crypto/fields.ts).
--
-- Amounts, merchant names, account names and numbers, balances and positions move into one
-- AES-256-GCM `sealed` column per row. SQL can't encrypt, so this migration drops the synced
-- ledger tables and recreates them empty, and resets every institution's transactions cursor:
-- the next sync pulls everything again and writes it sealed. Linked banks (institutions, with
-- their sealed Plaid tokens), members, agents, budgets, flags and the audit log are kept.
-- Account visibility settings reset to the default (private).

DROP TABLE holdings;
DROP TABLE balances;
DROP TABLE transactions;
DROP TABLE accounts;

CREATE TABLE accounts (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))), 2) || '-' || substr('89ab', 1 + (abs(random()) % 4), 1) || substr(lower(hex(randomblob(2))), 2) || '-' || lower(hex(randomblob(6)))),
  institution_id    TEXT NOT NULL REFERENCES institutions(id),
  plaid_account_id  TEXT NOT NULL UNIQUE,
  owner_member_id   TEXT NOT NULL REFERENCES members(id),
  type              TEXT NOT NULL,
  subtype           TEXT,
  -- shared: both people see everything. private: the partner sees balances and category totals only.
  -- hidden: the partner sees nothing.
  visibility        TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('shared', 'private', 'hidden')),
  -- name, official_name, mask, current_balance, available_balance, currency
  sealed            TEXT NOT NULL,
  updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE balances (
  account_id  TEXT NOT NULL REFERENCES accounts(id),
  as_of       TEXT NOT NULL,
  sealed      TEXT NOT NULL,                      -- current, available
  PRIMARY KEY (account_id, as_of)
);

CREATE TABLE transactions (
  id                    TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))), 2) || '-' || substr('89ab', 1 + (abs(random()) % 4), 1) || substr(lower(hex(randomblob(2))), 2) || '-' || lower(hex(randomblob(6)))),
  plaid_transaction_id  TEXT NOT NULL UNIQUE,
  account_id            TEXT NOT NULL REFERENCES accounts(id),
  date                  TEXT NOT NULL,
  pending               INTEGER NOT NULL DEFAULT 0 CHECK (pending IN (0, 1)),
  category_id           TEXT REFERENCES categories(id),
  category_source       TEXT CHECK (category_source IN ('plaid', 'agent', 'rule', 'member')),
  -- amount (Plaid convention: positive = money out), authorized_date, currency, merchant_name,
  -- raw_name, plaid_category
  sealed                TEXT NOT NULL,
  removed_at            TEXT,
  created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX transactions_account_date ON transactions (account_id, date DESC);
CREATE INDEX transactions_date ON transactions (date DESC);

CREATE TABLE holdings (
  account_id        TEXT NOT NULL REFERENCES accounts(id),
  plaid_security_id TEXT NOT NULL REFERENCES securities(plaid_security_id),
  as_of             TEXT NOT NULL,
  sealed            TEXT NOT NULL,                -- quantity, cost_basis, market_value
  PRIMARY KEY (account_id, plaid_security_id, as_of)
);

UPDATE institutions SET transactions_cursor = NULL;
