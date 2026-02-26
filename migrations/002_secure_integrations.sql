-- Migration 002: Secure integrations support with PKCE and encrypted tokens

-- 1. Add new columns for integration statuses, scopes, and timestamps
ALTER TABLE integrations ADD COLUMN status TEXT DEFAULT 'Not connected';
ALTER TABLE integrations ADD COLUMN scopes TEXT;
ALTER TABLE integrations ADD COLUMN expires_at INTEGER;
ALTER TABLE integrations ADD COLUMN connected_at TIMESTAMP;

-- 2. Purge any plaintext/dummy tokens from previous mock runs for security
UPDATE integrations SET access_token = '', refresh_token = '';
