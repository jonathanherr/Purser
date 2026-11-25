-- OAuth for remote MCP clients (Claude custom connectors). Read-only, one connection per member.
--
-- Sign-in is a pairing flow, so no password or secret ever has to be sent to anyone: the
-- browser shows a short pairing code, and a member approves that code from a channel that
-- already knows who they are (the "Vault admin" workflow, which only repo admins can run).
-- The access token handed to the client is an ordinary agent_clients row acting for that
-- member with read-only scopes, so /mcp, visibility rules and the audit log work unchanged,
-- and revoking the row (revoked_at) disconnects the client.

-- Clients registered through dynamic client registration (RFC 7591). Public clients, PKCE only.
CREATE TABLE oauth_clients (
  client_id      TEXT PRIMARY KEY,
  client_name    TEXT,
  redirect_uris  TEXT NOT NULL CHECK (json_valid(redirect_uris)),
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- One sign-in attempt, from /authorize until its code is exchanged or it expires.
CREATE TABLE oauth_requests (
  id              TEXT PRIMARY KEY,               -- random handle held by the sign-in page
  pairing_code    TEXT NOT NULL UNIQUE,           -- shown to the person, approved out of band
  client_id       TEXT NOT NULL REFERENCES oauth_clients(client_id),
  redirect_uri    TEXT NOT NULL,
  state           TEXT,
  code_challenge  TEXT NOT NULL,                  -- PKCE S256
  member_id       TEXT REFERENCES members(id),    -- set on approval
  approved_at     TEXT,
  code_hash       TEXT UNIQUE,                    -- authorization code, issued after approval
  code_used_at    TEXT,
  expires_at      TEXT NOT NULL,
  created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX oauth_requests_expires ON oauth_requests (expires_at);
