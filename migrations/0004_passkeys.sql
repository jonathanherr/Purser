-- Passkeys let a member approve a Claude connector sign-in on the sign-in page itself, with
-- Face ID, Touch ID or a security key, instead of reading a pairing code out to someone else.
-- The vault stores only each passkey's public key. Pairing codes stay as a fallback.

CREATE TABLE member_passkeys (
  credential_id  TEXT PRIMARY KEY,                       -- base64url, from the authenticator
  member_id      TEXT NOT NULL REFERENCES members(id),
  public_key     TEXT NOT NULL,                          -- base64url COSE public key
  counter        INTEGER NOT NULL DEFAULT 0,
  transports     TEXT CHECK (transports IS NULL OR json_valid(transports)),
  label          TEXT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_used_at   TEXT,
  revoked_at     TEXT
);
CREATE INDEX member_passkeys_member ON member_passkeys (member_id);

-- One-time links that let a member add a passkey. Created by an admin (CLI), used once,
-- short-lived, and stored hashed so a database copy can't be used to add a passkey.
CREATE TABLE passkey_setups (
  token_hash   TEXT PRIMARY KEY,
  member_id    TEXT NOT NULL REFERENCES members(id),
  challenge    TEXT,                                     -- current WebAuthn challenge
  expires_at   TEXT NOT NULL,
  used_at      TEXT,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- The WebAuthn challenge for approving a sign-in with a passkey.
ALTER TABLE oauth_requests ADD COLUMN webauthn_challenge TEXT;
