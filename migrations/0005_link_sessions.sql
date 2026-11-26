-- Short sessions for the "Link an account" page: a member signs in with a passkey, then
-- Plaid Link runs in the browser and hands back a public token that the vault exchanges.
-- The bank password goes only to Plaid and the bank; the vault never sees it.
CREATE TABLE link_sessions (
  id_hash      TEXT PRIMARY KEY,                -- sha256 of the handle the page holds
  member_id    TEXT REFERENCES members(id),     -- set once the passkey checks out
  challenge    TEXT,                            -- WebAuthn challenge, single use
  authed_at    TEXT,
  used_at      TEXT,                            -- set when a public token is exchanged
  expires_at   TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX link_sessions_expires ON link_sessions (expires_at);
