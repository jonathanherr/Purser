-- Purser vault schema, phase 1 (read-only, proposals recorded but never executed).

CREATE TABLE members (
  id            text PRIMARY KEY,
  display_name  text NOT NULL,
  role          text NOT NULL CHECK (role IN ('owner', 'member')),
  -- Phase 1 sign-in is a bearer token (stored hashed). Passkeys replace this in phase 1c.
  token_hash    text UNIQUE,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- One row per Plaid Item (one login at one institution).
CREATE TABLE institutions (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_member_id   text NOT NULL REFERENCES members(id),
  plaid_item_id     text NOT NULL UNIQUE,
  plaid_institution_id text,
  name              text,
  -- Envelope-encrypted Plaid access token. Only the sync worker decrypts it.
  access_token_ct   text NOT NULL,
  wrapped_dek       text NOT NULL,
  key_id            text NOT NULL,
  transactions_cursor text,
  products          text[] NOT NULL DEFAULT '{}',
  status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'needs_relink', 'error', 'removed')),
  last_error        text,
  last_synced_at    timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE accounts (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  institution_id    uuid NOT NULL REFERENCES institutions(id),
  plaid_account_id  text NOT NULL UNIQUE,
  owner_member_id   text NOT NULL REFERENCES members(id),
  name              text NOT NULL,
  official_name     text,
  type              text NOT NULL,
  subtype           text,
  mask              text,
  -- shared: both people see everything. private: the partner sees balances and category totals only.
  -- hidden: the partner sees nothing.
  visibility        text NOT NULL DEFAULT 'private' CHECK (visibility IN ('shared', 'private', 'hidden')),
  current_balance   numeric(16, 2),
  available_balance numeric(16, 2),
  iso_currency_code text,
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE balances (
  account_id  uuid NOT NULL REFERENCES accounts(id),
  as_of       timestamptz NOT NULL,
  current     numeric(16, 2),
  available   numeric(16, 2),
  PRIMARY KEY (account_id, as_of)
);

CREATE TABLE categories (
  id         text PRIMARY KEY,
  name       text NOT NULL,
  parent_id  text REFERENCES categories(id)
);

CREATE TABLE budgets (
  category_id text NOT NULL REFERENCES categories(id),
  month       date NOT NULL CHECK (extract(day FROM month) = 1),
  amount      numeric(14, 2) NOT NULL CHECK (amount >= 0),
  PRIMARY KEY (category_id, month)
);

CREATE TABLE transactions (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  plaid_transaction_id  text NOT NULL UNIQUE,
  account_id            uuid NOT NULL REFERENCES accounts(id),
  date                  date NOT NULL,
  authorized_date       date,
  -- Plaid convention: positive = money leaving the account.
  amount                numeric(14, 2) NOT NULL,
  iso_currency_code     text,
  merchant_name         text,
  raw_name              text,
  pending               boolean NOT NULL DEFAULT false,
  plaid_category        text,
  category_id           text REFERENCES categories(id),
  category_source       text CHECK (category_source IN ('plaid', 'agent', 'rule', 'member')),
  raw                   jsonb,
  removed_at            timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX transactions_account_date ON transactions (account_id, date DESC);
CREATE INDEX transactions_date ON transactions (date DESC);

CREATE TABLE securities (
  plaid_security_id text PRIMARY KEY,
  name              text,
  ticker            text,
  type              text,
  close_price       numeric(18, 6),
  close_price_as_of date
);

CREATE TABLE holdings (
  account_id        uuid NOT NULL REFERENCES accounts(id),
  plaid_security_id text NOT NULL REFERENCES securities(plaid_security_id),
  as_of             date NOT NULL,
  quantity          numeric(20, 8) NOT NULL,
  cost_basis        numeric(16, 2),
  institution_value numeric(16, 2),
  PRIMARY KEY (account_id, plaid_security_id, as_of)
);

CREATE TABLE agent_clients (
  id          text PRIMARY KEY,
  name        text NOT NULL,
  token_hash  text NOT NULL UNIQUE,
  scopes      text[] NOT NULL,
  -- A member id, or 'household' for runs that should see only shared detail.
  acts_for    text NOT NULL,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE flags (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id      text NOT NULL REFERENCES agent_clients(id),
  kind          text NOT NULL,
  severity      text NOT NULL CHECK (severity IN ('info', 'warn', 'alert')),
  subject_type  text CHECK (subject_type IN ('transaction', 'account', 'holding', 'budget')),
  subject_id    text,
  note          text NOT NULL,
  status        text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'dismissed', 'resolved')),
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE proposals (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id    text NOT NULL REFERENCES agent_clients(id),
  kind        text NOT NULL CHECK (kind IN ('transfer_change', 'trade')),
  payload     jsonb NOT NULL,
  reason      text NOT NULL,
  status      text NOT NULL CHECK (status IN ('blocked', 'pending', 'approved', 'rejected', 'expired', 'executed', 'failed')),
  precheck    jsonb NOT NULL,
  approvals_required int NOT NULL DEFAULT 1,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  decided_at  timestamptz
);

CREATE TABLE proposal_decisions (
  proposal_id uuid NOT NULL REFERENCES proposals(id),
  member_id   text NOT NULL REFERENCES members(id),
  decision    text NOT NULL CHECK (decision IN ('approve', 'reject')),
  decided_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (proposal_id, member_id)
);

CREATE TABLE settings (
  key    text PRIMARY KEY,
  value  jsonb NOT NULL
);
INSERT INTO settings (key, value) VALUES ('execution_frozen', 'false');

CREATE TABLE audit_log (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  actor_type  text NOT NULL CHECK (actor_type IN ('agent', 'member', 'system')),
  actor_id    text NOT NULL,
  action      text NOT NULL,
  args_hash   text,
  outcome     text NOT NULL CHECK (outcome IN ('ok', 'denied', 'error')),
  result_rows int,
  detail      jsonb
);

-- The audit log is append-only, even for the application's own database role.
CREATE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- Starter categories. Agents and people can add more.
INSERT INTO categories (id, name, parent_id) VALUES
  ('income', 'Income', NULL),
  ('housing', 'Housing', NULL),
  ('utilities', 'Utilities', NULL),
  ('groceries', 'Groceries', NULL),
  ('dining', 'Dining out', NULL),
  ('transport', 'Transport', NULL),
  ('health', 'Health', NULL),
  ('shopping', 'Shopping', NULL),
  ('subscriptions', 'Subscriptions', NULL),
  ('travel', 'Travel', NULL),
  ('fees', 'Fees and interest', NULL),
  ('transfers', 'Transfers', NULL),
  ('investing', 'Investing', NULL),
  ('other', 'Other', NULL);
