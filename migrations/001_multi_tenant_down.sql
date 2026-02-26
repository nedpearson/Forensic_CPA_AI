-- 001_multi_tenant_down.sql
-- Revert the multi-tenant schema additions

-- Drop indexes
DROP INDEX IF EXISTS idx_accounts_userid;
DROP INDEX IF EXISTS idx_documents_userid;
DROP INDEX IF EXISTS idx_transactions_userid;
DROP INDEX IF EXISTS idx_case_notes_userid;
DROP INDEX IF EXISTS idx_transactions_caseid;

-- Drop columns (requires SQLite 3.35.0+)
ALTER TABLE accounts DROP COLUMN user_id;
ALTER TABLE accounts DROP COLUMN case_id;

ALTER TABLE documents DROP COLUMN user_id;
ALTER TABLE documents DROP COLUMN case_id;

ALTER TABLE transactions DROP COLUMN user_id;
ALTER TABLE transactions DROP COLUMN case_id;

ALTER TABLE categories DROP COLUMN user_id;
ALTER TABLE category_rules DROP COLUMN user_id;

ALTER TABLE proof_links DROP COLUMN user_id;

ALTER TABLE case_notes DROP COLUMN user_id;
ALTER TABLE case_notes DROP COLUMN case_id;

ALTER TABLE drilldown_logs DROP COLUMN user_id;
ALTER TABLE document_extractions DROP COLUMN user_id;
ALTER TABLE taxonomy_config DROP COLUMN user_id;
ALTER TABLE document_categorizations DROP COLUMN user_id;

-- Drop newly created tables
DROP TABLE IF EXISTS cases;
DROP TABLE IF EXISTS users;
