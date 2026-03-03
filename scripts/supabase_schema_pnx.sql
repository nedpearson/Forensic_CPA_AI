-- Migration Schema for Supabase (PostgreSQL)
-- Prefix: pnx_

CREATE TABLE pnx_users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_demo INTEGER DEFAULT 0,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pnx_accounts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    account_name TEXT NOT NULL,
    account_number TEXT,
    account_type TEXT NOT NULL,  -- 'bank', 'credit_card', 'venmo'
    institution TEXT,
    cardholder_name TEXT,
    card_last_four TEXT,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pnx_documents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    filename TEXT NOT NULL,
    original_path TEXT,
    file_type TEXT NOT NULL,  -- 'pdf', 'xlsx', 'docx', 'csv'
    doc_category TEXT,  -- 'bank_statement', 'credit_card', 'venmo', 'proof', 'other'
    upload_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    statement_start_date TEXT,
    statement_end_date TEXT,
    account_id INTEGER,
    notes TEXT,
    FOREIGN KEY (account_id) REFERENCES pnx_accounts(id)
);

CREATE TABLE pnx_transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES pnx_documents(id),
    FOREIGN KEY (account_id) REFERENCES pnx_accounts(id)
);

CREATE TABLE pnx_categories (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    name TEXT NOT NULL,
    parent_category TEXT,
    category_type TEXT,  -- 'personal', 'business', 'transfer', 'deposit', 'fee', 'other'
    color TEXT DEFAULT '#6c757d',
    icon TEXT
);

CREATE TABLE pnx_category_rules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    pattern TEXT NOT NULL,
    category TEXT NOT NULL,
    subcategory TEXT,
    is_personal INTEGER DEFAULT 0,
    is_business INTEGER DEFAULT 0,
    is_transfer INTEGER DEFAULT 0,
    priority INTEGER DEFAULT 0
);

CREATE TABLE pnx_audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    transaction_id INTEGER,
    action TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    field_changed TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (transaction_id) REFERENCES pnx_transactions(id)
);

CREATE TABLE pnx_proof_links (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    transaction_id INTEGER NOT NULL,
    document_id INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (transaction_id) REFERENCES pnx_transactions(id) ON DELETE CASCADE,
    FOREIGN KEY (document_id) REFERENCES pnx_documents(id) ON DELETE CASCADE,
    UNIQUE(transaction_id, document_id)
);

CREATE TABLE pnx_case_notes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    note_type TEXT DEFAULT 'general',  -- 'general', 'finding', 'evidence', 'timeline'
    severity TEXT DEFAULT 'info',  -- 'info', 'warning', 'danger'
    linked_transaction_ids TEXT,  -- JSON array of transaction IDs
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pnx_drilldown_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    source_tab TEXT NOT NULL,
    widget_id TEXT NOT NULL,
    target TEXT NOT NULL,
    filters_applied TEXT NOT NULL,
    metadata TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pnx_saved_filters (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    name TEXT NOT NULL,
    filters TEXT NOT NULL,  -- JSON object of filter params
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pnx_document_extractions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    document_id INTEGER NOT NULL,
    extraction_data TEXT,  -- JSON string of the extracted fields/layout
    status TEXT DEFAULT 'pending',  -- 'pending', 'completed', 'failed'
    error_message TEXT,
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES pnx_documents(id) ON DELETE CASCADE
);

CREATE TABLE pnx_taxonomy_config (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category_type TEXT NOT NULL, -- 'risk', 'entity', 'topic'
    severity TEXT DEFAULT 'low',  -- for risks
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pnx_document_categorizations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
    document_id INTEGER NOT NULL,
    extraction_id INTEGER,
    categorization_data TEXT, -- JSON containing RiskCategories, entities, topics, summary
    provider TEXT,
    model TEXT,
    version INTEGER DEFAULT 1,
    status TEXT DEFAULT 'completed',
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES pnx_documents(id) ON DELETE CASCADE,
    FOREIGN KEY (extraction_id) REFERENCES pnx_document_extractions(id) ON DELETE SET NULL
);

CREATE TABLE pnx_integrations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES pnx_users(id),
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
    UNIQUE(user_id, provider)
);

-- Indexes

CREATE INDEX IF NOT EXISTS idx_pnx_trans_date ON pnx_transactions(trans_date);
CREATE INDEX IF NOT EXISTS idx_pnx_trans_category ON pnx_transactions(category);
CREATE INDEX IF NOT EXISTS idx_pnx_trans_cardholder ON pnx_transactions(cardholder_name);
CREATE INDEX IF NOT EXISTS idx_pnx_trans_type ON pnx_transactions(trans_type);
CREATE INDEX IF NOT EXISTS idx_pnx_trans_flagged ON pnx_transactions(is_flagged);
CREATE INDEX IF NOT EXISTS idx_pnx_trans_account ON pnx_transactions(account_id);
CREATE INDEX IF NOT EXISTS idx_pnx_proof_links_trans ON pnx_proof_links(transaction_id);
CREATE INDEX IF NOT EXISTS idx_pnx_proof_links_doc ON pnx_proof_links(document_id);
CREATE INDEX IF NOT EXISTS idx_pnx_trans_personal_date ON pnx_transactions(is_personal, trans_date);
CREATE INDEX IF NOT EXISTS idx_pnx_trans_business_date ON pnx_transactions(is_business, trans_date);
CREATE INDEX IF NOT EXISTS idx_pnx_trans_flagged_date ON pnx_transactions(is_flagged, trans_date);
CREATE INDEX IF NOT EXISTS idx_pnx_trans_amount ON pnx_transactions(amount);

-- High performance indices for Analytics Drilldowns
CREATE INDEX IF NOT EXISTS idx_pnx_trans_composite_view ON pnx_transactions(is_personal, is_business, trans_date);
CREATE INDEX IF NOT EXISTS idx_pnx_trans_amount_date ON pnx_transactions(amount, trans_date);
CREATE INDEX IF NOT EXISTS idx_pnx_drilldown_logs_target ON pnx_drilldown_logs(target, timestamp);

