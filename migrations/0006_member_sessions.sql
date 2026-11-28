-- Browser sessions for the vault's dashboard (/app). A member signs in with a passkey and gets
-- an HttpOnly cookie; only its hash is stored. Sessions end after 12 hours or on sign-out.
CREATE TABLE member_sessions (
  token_hash   TEXT PRIMARY KEY,
  member_id    TEXT NOT NULL REFERENCES members(id),
  expires_at   TEXT NOT NULL,
  revoked_at   TEXT,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX member_sessions_expires ON member_sessions (expires_at);
