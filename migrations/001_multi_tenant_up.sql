-- 001_multi_tenant_up.sql
-- Add users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add new columns to users (will fail gracefully if already existing via Python script)
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';
ALTER TABLE users ADD COLUMN is_demo BOOLEAN DEFAULT 0;

-- Implement 'cases' model for isolation (owned by a user)
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create a demo user to hold all existing data
INSERT INTO users (id, email, password_hash, role, is_demo)
VALUES (1, 'demo@forensiccpa.ai', 'unusable_hash', 'admin', 1)
ON CONFLICT(id) DO NOTHING;

-- Create a default case for the demo user
INSERT INTO cases (id, user_id, name, description)
VALUES (1, 1, 'Default Audit Case', 'System generated default case from legacy data')
ON CONFLICT(id) DO NOTHING;

-- Add user_id and case_id to domain tables (nullable to not break existing)
ALTER TABLE accounts ADD COLUMN user_id INTEGER;
ALTER TABLE accounts ADD COLUMN case_id INTEGER;

ALTER TABLE documents ADD COLUMN user_id INTEGER;
ALTER TABLE documents ADD COLUMN case_id INTEGER;

ALTER TABLE transactions ADD COLUMN user_id INTEGER;
ALTER TABLE transactions ADD COLUMN case_id INTEGER;

ALTER TABLE categories ADD COLUMN user_id INTEGER;
ALTER TABLE category_rules ADD COLUMN user_id INTEGER;

ALTER TABLE proof_links ADD COLUMN user_id INTEGER;

ALTER TABLE case_notes ADD COLUMN user_id INTEGER;
ALTER TABLE case_notes ADD COLUMN case_id INTEGER;

ALTER TABLE drilldown_logs ADD COLUMN user_id INTEGER;
ALTER TABLE document_extractions ADD COLUMN user_id INTEGER;
ALTER TABLE taxonomy_config ADD COLUMN user_id INTEGER;
ALTER TABLE document_categorizations ADD COLUMN user_id INTEGER;

-- Backfill ownership for existing records
UPDATE accounts SET user_id = 1, case_id = 1 WHERE user_id IS NULL;
UPDATE documents SET user_id = 1, case_id = 1 WHERE user_id IS NULL;
UPDATE transactions SET user_id = 1, case_id = 1 WHERE user_id IS NULL;
UPDATE categories SET user_id = 1 WHERE user_id IS NULL;
UPDATE category_rules SET user_id = 1 WHERE user_id IS NULL;
UPDATE proof_links SET user_id = 1 WHERE user_id IS NULL;
UPDATE case_notes SET user_id = 1, case_id = 1 WHERE user_id IS NULL;
UPDATE drilldown_logs SET user_id = 1 WHERE user_id IS NULL;
UPDATE document_extractions SET user_id = 1 WHERE user_id IS NULL;
UPDATE taxonomy_config SET user_id = 1 WHERE user_id IS NULL;
UPDATE document_categorizations SET user_id = 1 WHERE user_id IS NULL;

-- Create indexes for performance filtering
CREATE INDEX IF NOT EXISTS idx_accounts_userid ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_userid ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_userid ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_case_notes_userid ON case_notes(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_caseid ON transactions(case_id);
