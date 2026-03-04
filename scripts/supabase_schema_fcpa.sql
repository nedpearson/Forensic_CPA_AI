-- Migration Schema for Supabase (PostgreSQL)
-- Prefix: fcpa_ (Forensic CPA AI)
-- Note: Includes Phase 3 Multi-Tenant isolated schema elements and dynamic SQLite columns.

CREATE TABLE fcpa_users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_demo INTEGER DEFAULT 0,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_companies (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    legal_name TEXT,
    created_by INTEGER REFERENCES fcpa_users(id),
    owner_user_id INTEGER REFERENCES fcpa_users(id),
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_company_memberships (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id) ON DELETE CASCADE,
    company_id INTEGER REFERENCES fcpa_companies(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'viewer',
    is_default INTEGER DEFAULT 0,
    invited_by INTEGER REFERENCES fcpa_users(id),
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, company_id)
);

CREATE TABLE fcpa_company_invitations (
    id SERIAL PRIMARY KEY,
    company_id INTEGER REFERENCES fcpa_companies(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    invited_by_user_id INTEGER REFERENCES fcpa_users(id) ON DELETE SET NULL,
    intended_role TEXT NOT NULL DEFAULT 'viewer',
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    accepted_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_advisor_company_state (
    company_id INTEGER PRIMARY KEY REFERENCES fcpa_companies(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'never_run', -- 'never_run', 'queued', 'running', 'completed', 'failed'
    needs_refresh INTEGER DEFAULT 1,
    last_run_at TIMESTAMP WITH TIME ZONE,
    last_success_at TIMESTAMP WITH TIME ZONE,
    last_failure_at TIMESTAMP WITH TIME ZONE,
    last_trigger_reason TEXT,
    last_result_json TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_accounts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    account_name TEXT NOT NULL,
    account_number TEXT,
    account_type TEXT NOT NULL,  -- 'bank', 'credit_card', 'venmo'
    institution TEXT,
    cardholder_name TEXT,
    card_last_four TEXT,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_documents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    filename TEXT NOT NULL,
    original_path TEXT,
    file_type TEXT NOT NULL,  -- 'pdf', 'xlsx', 'docx', 'csv'
    doc_category TEXT,  -- 'bank_statement', 'credit_card', 'venmo', 'proof', 'other'
    upload_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    statement_start_date TEXT,
    statement_end_date TEXT,
    account_id INTEGER,
    notes TEXT,
    status TEXT DEFAULT 'queued',
    parsed_transaction_count INTEGER DEFAULT 0,
    import_transaction_count INTEGER DEFAULT 0,
    failure_reason TEXT,
    content_sha256 TEXT,
    deduped_skipped_count INTEGER DEFAULT 0,
    parent_document_id INTEGER REFERENCES fcpa_documents(id),
    FOREIGN KEY (account_id) REFERENCES fcpa_accounts(id)
);

CREATE TABLE fcpa_merchants (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    canonical_name TEXT NOT NULL,
    default_category_id INTEGER, -- Added FK below
    parent_merchant_id INTEGER REFERENCES fcpa_merchants(id),
    is_transfer INTEGER DEFAULT 0,
    is_personal INTEGER DEFAULT 0,
    is_business INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    document_id INTEGER,
    account_id INTEGER,
    trans_date TEXT,
    post_date TEXT,
    description TEXT NOT NULL,
    amount NUMERIC NOT NULL,
    trans_type TEXT NOT NULL,  -- 'debit', 'credit', 'fee', 'transfer_out', 'transfer_in', 'deposit', 'payment'
    category TEXT DEFAULT 'uncategorized',
    subcategory TEXT,
    cardholder_name TEXT,
    card_last_four TEXT,
    payment_method TEXT,  -- 'debit', 'credit', 'check', 'venmo', 'transfer', 'cash', 'wire'
    check_number TEXT,
    is_transfer INTEGER DEFAULT 0,
    transfer_to_account TEXT,
    transfer_from_account TEXT,
    is_personal INTEGER DEFAULT 0,
    is_business INTEGER DEFAULT 0,
    is_flagged INTEGER DEFAULT 0,
    flag_reason TEXT,
    user_notes TEXT,
    auto_categorized INTEGER DEFAULT 1,
    manually_edited INTEGER DEFAULT 0,
    txn_fingerprint TEXT,
    is_approved INTEGER DEFAULT 1,
    merchant_id INTEGER REFERENCES fcpa_merchants(id),
    categorization_confidence REAL,
    categorization_source TEXT,
    categorization_status TEXT DEFAULT 'pending',
    categorization_explanation TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES fcpa_documents(id),
    FOREIGN KEY (account_id) REFERENCES fcpa_accounts(id)
);

CREATE TABLE fcpa_categories (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    name TEXT NOT NULL,
    parent_category TEXT,
    parent_category_id INTEGER REFERENCES fcpa_categories(id),
    category_type TEXT,
    scope TEXT,
    tax_deductible_default INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0,
    keywords TEXT,
    rules TEXT,
    requires_receipt INTEGER DEFAULT 0,
    reimbursable_default INTEGER DEFAULT 0,
    color TEXT DEFAULT '#6c757d',
    icon TEXT
);

-- Fix the foreign key referencing categories
ALTER TABLE fcpa_merchants ADD CONSTRAINT fk_merchant_default_category FOREIGN KEY (default_category_id) REFERENCES fcpa_categories(id);

CREATE TABLE fcpa_category_rules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    pattern TEXT NOT NULL,
    category TEXT NOT NULL,
    subcategory TEXT,
    is_personal INTEGER DEFAULT 0,
    is_business INTEGER DEFAULT 0,
    is_transfer INTEGER DEFAULT 0,
    priority INTEGER DEFAULT 0,
    hit_count INTEGER DEFAULT 1,
    last_applied TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    transaction_id INTEGER,
    action TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    field_changed TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (transaction_id) REFERENCES fcpa_transactions(id)
);

CREATE TABLE fcpa_proof_links (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    transaction_id INTEGER NOT NULL,
    document_id INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (transaction_id) REFERENCES fcpa_transactions(id) ON DELETE CASCADE,
    FOREIGN KEY (document_id) REFERENCES fcpa_documents(id) ON DELETE CASCADE,
    UNIQUE(transaction_id, document_id)
);

CREATE TABLE fcpa_transaction_sources (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    transaction_id INTEGER NOT NULL,
    document_id INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (transaction_id) REFERENCES fcpa_transactions(id) ON DELETE CASCADE,
    FOREIGN KEY (document_id) REFERENCES fcpa_documents(id) ON DELETE CASCADE,
    UNIQUE(transaction_id, document_id)
);

CREATE TABLE fcpa_case_notes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    note_type TEXT DEFAULT 'general',  -- 'general', 'finding', 'evidence', 'timeline'
    severity TEXT DEFAULT 'info',  -- 'info', 'warning', 'danger'
    linked_transaction_ids TEXT,  -- JSON array of transaction IDs
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_drilldown_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    source_tab TEXT NOT NULL,
    widget_id TEXT NOT NULL,
    target TEXT NOT NULL,
    filters_applied TEXT NOT NULL,
    metadata TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_saved_filters (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    name TEXT NOT NULL,
    filters TEXT NOT NULL,  -- JSON object of filter params
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_document_extractions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    document_id INTEGER NOT NULL,
    extraction_data TEXT,  -- JSON string of the extracted fields/layout
    status TEXT DEFAULT 'pending',  -- 'pending', 'completed', 'failed'
    error_message TEXT,
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES fcpa_documents(id) ON DELETE CASCADE
);

CREATE TABLE fcpa_taxonomy_config (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category_type TEXT NOT NULL, -- 'risk', 'entity', 'topic'
    severity TEXT DEFAULT 'low',  -- for risks
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_document_categorizations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    document_id INTEGER NOT NULL,
    extraction_id INTEGER,
    categorization_data TEXT, -- JSON containing RiskCategories, entities, topics, summary
    provider TEXT,
    model TEXT,
    version INTEGER DEFAULT 1,
    status TEXT DEFAULT 'completed',
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES fcpa_documents(id) ON DELETE CASCADE,
    FOREIGN KEY (extraction_id) REFERENCES fcpa_document_extractions(id) ON DELETE SET NULL
);

CREATE TABLE fcpa_integrations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    provider TEXT NOT NULL,
    account_id TEXT,
    status TEXT DEFAULT 'Not connected',
    scopes TEXT,
    access_token TEXT,
    refresh_token TEXT,
    expires_at BIGINT,
    metadata TEXT,
    connected_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(company_id, provider)
);

CREATE TABLE fcpa_advisor_findings (
    finding_id TEXT PRIMARY KEY,
    company_id INTEGER NOT NULL,
    analysis_run_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL, 
    confidence INTEGER NOT NULL,
    title TEXT NOT NULL,
    executive_summary TEXT,
    plain_english_explanation TEXT,
    forensic_rationale TEXT,
    financial_impact TEXT,
    recommended_actions TEXT,
    evidence_graph TEXT,
    drilldown_queries TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (company_id) REFERENCES fcpa_companies(id)
);

CREATE TABLE fcpa_advisor_remediation_tasks (
    id SERIAL PRIMARY KEY,
    company_id INTEGER NOT NULL,
    finding_id TEXT NOT NULL,
    analysis_run_id TEXT NOT NULL,
    task_description TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    owner TEXT DEFAULT 'unassigned',
    due_date TEXT,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (company_id) REFERENCES fcpa_companies(id),
    FOREIGN KEY (finding_id) REFERENCES fcpa_advisor_findings(finding_id) ON DELETE CASCADE,
    UNIQUE(finding_id, task_description)
);

CREATE TABLE fcpa_merchant_context_rules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    merchant_id INTEGER REFERENCES fcpa_merchants(id) ON DELETE CASCADE,
    context_type TEXT NOT NULL,  -- e.g., 'account_type'
    context_value TEXT NOT NULL, -- e.g., 'credit_card'
    mapped_category_id INTEGER REFERENCES fcpa_categories(id),
    priority INTEGER DEFAULT 60,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, merchant_id, context_type, context_value)
);

CREATE TABLE fcpa_merchant_aliases (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES fcpa_users(id),
    company_id INTEGER REFERENCES fcpa_companies(id),
    merchant_id INTEGER REFERENCES fcpa_merchants(id) ON DELETE CASCADE,
    raw_pattern TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcpa_lookup_cache (
    id SERIAL PRIMARY KEY,
    lookup_key TEXT NOT NULL UNIQUE,
    category_signal TEXT,
    confidence REAL,
    source TEXT,
    raw_response TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes

CREATE INDEX IF NOT EXISTS idx_fcpa_trans_date ON fcpa_transactions(trans_date);
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_category ON fcpa_transactions(category);
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_cardholder ON fcpa_transactions(cardholder_name);
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_type ON fcpa_transactions(trans_type);
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_flagged ON fcpa_transactions(is_flagged);
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_account ON fcpa_transactions(account_id);
CREATE INDEX IF NOT EXISTS idx_fcpa_proof_links_trans ON fcpa_proof_links(transaction_id);
CREATE INDEX IF NOT EXISTS idx_fcpa_proof_links_doc ON fcpa_proof_links(document_id);
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_personal_date ON fcpa_transactions(is_personal, trans_date);
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_business_date ON fcpa_transactions(is_business, trans_date);
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_flagged_date ON fcpa_transactions(is_flagged, trans_date);
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_amount ON fcpa_transactions(amount);

-- High performance indices for Analytics Drilldowns
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_composite_view ON fcpa_transactions(is_personal, is_business, trans_date);
CREATE INDEX IF NOT EXISTS idx_fcpa_trans_amount_date ON fcpa_transactions(amount, trans_date);
CREATE INDEX IF NOT EXISTS idx_fcpa_drilldown_logs_target ON fcpa_drilldown_logs(target, timestamp);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fcpa_documents_user_sha ON fcpa_documents(user_id, content_sha256) WHERE content_sha256 IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_fcpa_trans_fingerprint ON fcpa_transactions(user_id, txn_fingerprint) WHERE txn_fingerprint IS NOT NULL;

