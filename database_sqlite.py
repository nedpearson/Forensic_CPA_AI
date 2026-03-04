"""
Database layer for Forensic Auditor.
Uses SQLite for local, portable storage of all transaction data.
"""
import sqlite3
import os
import json
from datetime import datetime
import threading
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()

def _get_active_company_id_shim():
    try:
        from flask import session
        if session:
            return session.get('active_company_id')
    except Exception:
        pass
    return None


# --- Concurrency Locks ---
_doc_locks = {}
_doc_lock_mutex = threading.Lock()

@contextmanager
def document_lock(doc_id):
    """
    Grants thread-safe exclusive execution access to a specific document ID.
    Prevents race conditions when overlapping workflows (e.g. approve vs background parser) 
    target the exact same row simultaneously.
    """
    with _doc_lock_mutex:
        if doc_id not in _doc_locks:
            _doc_locks[doc_id] = threading.Lock()
        lock = _doc_locks[doc_id]
        
    lock.acquire()
    try:
        yield lock
    finally:
        lock.release()
        # Optional: cleanup could happen here if memory bounded, but int keys are small.

if os.environ.get('TESTING') == 'true':
    DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'test_audit.db')
else:
    DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'data', 'forensic_audit.db'))


def get_db():
    """Get a database connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def close_db(conn):
    if conn:
        conn.close()


def init_db():
    """Initialize all database tables."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_demo INTEGER DEFAULT 0,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            legal_name TEXT,
            created_by INTEGER REFERENCES users(id),
            owner_user_id INTEGER REFERENCES users(id),
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS company_memberships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
            role TEXT NOT NULL DEFAULT 'viewer',
            is_default INTEGER DEFAULT 0,
            invited_by INTEGER REFERENCES users(id),
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, company_id)
        );

        CREATE TABLE IF NOT EXISTS company_invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
            email TEXT NOT NULL,
            invited_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            intended_role TEXT NOT NULL DEFAULT 'viewer',
            token_hash TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'pending',
            expires_at TIMESTAMP NOT NULL,
            accepted_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS advisor_company_state (
            company_id INTEGER PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
            status TEXT DEFAULT 'never_run', -- 'never_run', 'queued', 'running', 'completed', 'failed'
            needs_refresh INTEGER DEFAULT 1,
            last_run_at TIMESTAMP,
            last_success_at TIMESTAMP,
            last_failure_at TIMESTAMP,
            last_trigger_reason TEXT,
            last_result_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        


        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            account_name TEXT NOT NULL,
            account_number TEXT,
            account_type TEXT NOT NULL,  -- 'bank', 'credit_card', 'venmo'
            institution TEXT,
            cardholder_name TEXT,
            card_last_four TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            filename TEXT NOT NULL,
            original_path TEXT,
            file_type TEXT NOT NULL,  -- 'pdf', 'xlsx', 'docx', 'csv'
            doc_category TEXT,  -- 'bank_statement', 'credit_card', 'venmo', 'proof', 'other'
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            statement_start_date TEXT,
            statement_end_date TEXT,
            account_id INTEGER,
            notes TEXT,
            status TEXT DEFAULT 'queued', -- 'queued', 'processing', 'parsed', 'pending_approval', 'approved', 'failed'
            parsed_transaction_count INTEGER DEFAULT 0,
            import_transaction_count INTEGER DEFAULT 0,
            failure_reason TEXT,
            content_sha256 TEXT,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            document_id INTEGER,
            account_id INTEGER,
            trans_date TEXT,
            post_date TEXT,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
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
            categorization_status TEXT DEFAULT 'pending',
            categorization_source TEXT,
            categorization_confidence REAL,
            categorization_explanation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES documents(id),
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            name TEXT NOT NULL,
            parent_category TEXT,
            parent_category_id INTEGER REFERENCES categories(id),
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

        CREATE TABLE IF NOT EXISTS category_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            pattern TEXT NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT,
            is_personal INTEGER DEFAULT 0,
            is_business INTEGER DEFAULT 0,
            is_transfer INTEGER DEFAULT 0,
            priority INTEGER DEFAULT 0,
            hit_count INTEGER DEFAULT 1,
            last_applied TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            transaction_id INTEGER,
            action TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            field_changed TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (transaction_id) REFERENCES transactions(id)
        );

        CREATE TABLE IF NOT EXISTS proof_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            transaction_id INTEGER NOT NULL,
            document_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
            FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
            UNIQUE(transaction_id, document_id)
        );

        CREATE TABLE IF NOT EXISTS transaction_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            transaction_id INTEGER NOT NULL,
            document_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
            FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
            UNIQUE(transaction_id, document_id)
        );

        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            note_type TEXT DEFAULT 'general',  -- 'general', 'finding', 'evidence', 'timeline'
            severity TEXT DEFAULT 'info',  -- 'info', 'warning', 'danger'
            linked_transaction_ids TEXT,  -- JSON array of transaction IDs
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS drilldown_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            source_tab TEXT NOT NULL,
            widget_id TEXT NOT NULL,
            target TEXT NOT NULL,
            filters_applied TEXT NOT NULL,
            metadata TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS saved_filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            name TEXT NOT NULL,
            filters TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS document_extractions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            document_id INTEGER NOT NULL,
            extraction_data TEXT,  -- JSON string of the extracted fields/layout
            status TEXT DEFAULT 'pending',  -- 'pending', 'completed', 'failed'
            error_message TEXT,
            version INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS taxonomy_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            category_type TEXT NOT NULL, -- 'risk', 'entity', 'topic'
            severity TEXT DEFAULT 'low',  -- for risks
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS document_categorizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            document_id INTEGER NOT NULL,
            extraction_id INTEGER,
            categorization_data TEXT, -- JSON containing RiskCategories, entities, topics, summary
            provider TEXT,
            model TEXT,
            version INTEGER DEFAULT 1,
            status TEXT DEFAULT 'completed',
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
            FOREIGN KEY (extraction_id) REFERENCES document_extractions(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS saved_filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            name TEXT NOT NULL,
            filters TEXT NOT NULL,  -- JSON object of filter params
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS integrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            provider TEXT NOT NULL,
            account_id TEXT,
            status TEXT DEFAULT 'Not connected',
            scopes TEXT,
            access_token TEXT,
            refresh_token TEXT,
            expires_at INTEGER,
            metadata TEXT,
            connected_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            company_id INTEGER REFERENCES companies(id),
            UNIQUE(company_id, provider)
        );

        CREATE TABLE IF NOT EXISTS merchants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            canonical_name TEXT NOT NULL,
            default_category_id INTEGER REFERENCES categories(id),
            parent_merchant_id INTEGER REFERENCES merchants(id),
            is_transfer INTEGER DEFAULT 0,
            is_personal INTEGER DEFAULT 0,
            is_business INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS advisor_findings (
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (company_id) REFERENCES companies(id)
        );

        CREATE TABLE IF NOT EXISTS advisor_remediation_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            finding_id TEXT NOT NULL,
            analysis_run_id TEXT NOT NULL,
            task_description TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            owner TEXT DEFAULT 'unassigned',
            due_date TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (company_id) REFERENCES companies(id),
            FOREIGN KEY (finding_id) REFERENCES advisor_findings(finding_id) ON DELETE CASCADE,
            UNIQUE(finding_id, task_description)
        );

        CREATE TABLE IF NOT EXISTS merchant_context_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            merchant_id INTEGER REFERENCES merchants(id) ON DELETE CASCADE,
            context_type TEXT NOT NULL,  -- e.g., 'account_type'
            context_value TEXT NOT NULL, -- e.g., 'credit_card'
            mapped_category_id INTEGER REFERENCES categories(id),
            priority INTEGER DEFAULT 60,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, merchant_id, context_type, context_value)
        );

        CREATE TABLE IF NOT EXISTS merchant_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            merchant_id INTEGER REFERENCES merchants(id) ON DELETE CASCADE,
            raw_pattern TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS lookup_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lookup_key TEXT NOT NULL UNIQUE,
            category_signal TEXT,
            confidence REAL,
            source TEXT,
            raw_response TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_trans_date ON transactions(trans_date);
        CREATE INDEX IF NOT EXISTS idx_trans_category ON transactions(category);
        CREATE INDEX IF NOT EXISTS idx_trans_cardholder ON transactions(cardholder_name);
        CREATE INDEX IF NOT EXISTS idx_trans_type ON transactions(trans_type);
        CREATE INDEX IF NOT EXISTS idx_trans_flagged ON transactions(is_flagged);
        CREATE INDEX IF NOT EXISTS idx_trans_account ON transactions(account_id);
        CREATE INDEX IF NOT EXISTS idx_proof_links_trans ON proof_links(transaction_id);
        CREATE INDEX IF NOT EXISTS idx_proof_links_doc ON proof_links(document_id);
        CREATE INDEX IF NOT EXISTS idx_trans_personal_date ON transactions(is_personal, trans_date);
        CREATE INDEX IF NOT EXISTS idx_trans_business_date ON transactions(is_business, trans_date);
        CREATE INDEX IF NOT EXISTS idx_trans_flagged_date ON transactions(is_flagged, trans_date);
        CREATE INDEX IF NOT EXISTS idx_trans_amount ON transactions(amount);
        
        -- High performance indices for Analytics Drilldowns
        CREATE INDEX IF NOT EXISTS idx_trans_composite_view ON transactions(is_personal, is_business, trans_date);
        CREATE INDEX IF NOT EXISTS idx_trans_amount_date ON transactions(amount, trans_date);
        CREATE INDEX IF NOT EXISTS idx_drilldown_logs_target ON drilldown_logs(target, timestamp);
    """)

    # Dynamic migrations for documents table tracking fields
    try:
        cursor.execute("ALTER TABLE documents ADD COLUMN status TEXT DEFAULT 'queued'")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE documents ADD COLUMN parsed_transaction_count INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE documents ADD COLUMN import_transaction_count INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE documents ADD COLUMN failure_reason TEXT")
    except sqlite3.OperationalError:
        pass
        
    try:
        cursor.execute("ALTER TABLE merchants ADD COLUMN parent_merchant_id INTEGER REFERENCES merchants(id)")
    except sqlite3.OperationalError:
        pass
    
    # Categories dynamic migrations
    for col, ctype in [
        ('parent_category_id', 'INTEGER REFERENCES categories(id)'),
        ('scope', 'TEXT'),
        ('tax_deductible_default', 'INTEGER DEFAULT 0'),
        ('is_active', 'INTEGER DEFAULT 1'),
        ('sort_order', 'INTEGER DEFAULT 0'),
        ('keywords', 'TEXT'),
        ('rules', 'TEXT'),
        ('requires_receipt', 'INTEGER DEFAULT 0'),
        ('reimbursable_default', 'INTEGER DEFAULT 0')
    ]:
        try: cursor.execute(f"ALTER TABLE categories ADD COLUMN {col} {ctype}")
        except sqlite3.OperationalError: pass
        
    try:
        cursor.execute("ALTER TABLE documents ADD COLUMN content_sha256 TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE transactions ADD COLUMN txn_fingerprint TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE documents ADD COLUMN deduped_skipped_count INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE documents ADD COLUMN parent_document_id INTEGER REFERENCES documents(id)")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE transactions ADD COLUMN is_approved INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass

    # Add advanced categorization foundation columns
    for col, ctype in [
        ('merchant_id', 'INTEGER REFERENCES merchants(id)'),
        ('categorization_confidence', 'REAL'),
        ('categorization_source', 'TEXT'),
        ('categorization_status', 'TEXT'),
        ('categorization_explanation', 'TEXT')
    ]:
        try: cursor.execute(f"ALTER TABLE transactions ADD COLUMN {col} {ctype}")
        except sqlite3.OperationalError: pass

    for col, ctype in [
        ('hit_count', 'INTEGER DEFAULT 1'),
        ('last_applied', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
    ]:
        try: cursor.execute(f"ALTER TABLE category_rules ADD COLUMN {col} {ctype}")
        except sqlite3.OperationalError: pass

    try:
        # Backfill transaction_sources for existing transactions
        cursor.execute("""
            INSERT OR IGNORE INTO transaction_sources (user_id, transaction_id, document_id)
            SELECT user_id, id, document_id FROM transactions WHERE document_id IS NOT NULL
        """)
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE transactions ADD COLUMN is_approved INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass

    try:
        # Backfill missing cardholder_name from account_name for legacy transactions
        cursor.executescript("""
            UPDATE transactions 
            SET cardholder_name = (SELECT account_name FROM accounts WHERE accounts.id = transactions.account_id)
            WHERE cardholder_name IS NULL OR cardholder_name IN ('', 'checking', 'credit', 'depository');
            
            UPDATE transactions
            SET card_last_four = (SELECT card_last_four FROM accounts WHERE accounts.id = transactions.account_id)
            WHERE card_last_four IS NULL OR card_last_four = '';
        """)
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Create uniqueness constraints after all columns are confirmed to exist
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_user_sha ON documents(user_id, content_sha256) WHERE content_sha256 IS NOT NULL")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_trans_fingerprint ON transactions(user_id, txn_fingerprint) WHERE txn_fingerprint IS NOT NULL")


    # Migration for user_id on existing databases
    cursor.execute("SELECT id FROM users WHERE email='root@system.local'")
    root_user = cursor.fetchone()
    if not root_user:
        import werkzeug.security
        hashed = werkzeug.security.generate_password_hash("root")
        cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", ("root@system.local", hashed))
        root_id = cursor.lastrowid
    else:
        root_id = root_user['id']

    tables_to_migrate = [
        'accounts', 'documents', 'transactions', 'categories', 
        'category_rules', 'saved_filters', 'document_extractions', 
        'document_categorizations', 'audit_log', 'case_notes', 
        'drilldown_logs', 'taxonomy_config', 'proof_links', 'integrations'
    ]
    for table in tables_to_migrate:
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [row['name'] for row in cursor.fetchall()]
        if 'user_id' not in columns:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER REFERENCES users(id)")
            cursor.execute(f"UPDATE {table} SET user_id = ?", (root_id,))

    # Phase 3: Tenant Isolation Schema Migration
    # 1. Add company_id to all domain tables
    domain_tables = tables_to_migrate + ['merchants', 'merchant_context_rules', 'merchant_aliases']
    for table in domain_tables:
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [row['name'] for row in cursor.fetchall()]
        if 'company_id' not in columns:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN company_id INTEGER REFERENCES companies(id)")
            
    # Add status backfill for companies
    cursor.execute("PRAGMA table_info(companies)")
    if 'status' not in [row['name'] for row in cursor.fetchall()]:
        cursor.execute("ALTER TABLE companies ADD COLUMN status TEXT DEFAULT 'active'")

    # Migration for unique integrations constraint
    try:
        # Check if the UNIQUE constraint uses company_id
        cursor.execute("PRAGMA index_list(integrations)")
        indexes = cursor.fetchall()
        needs_integration_rebuild = True
        for idx in indexes:
            if idx['unique']:
                cursor.execute(f"PRAGMA index_info({idx['name']})")
                cols = [r['name'] for r in cursor.fetchall()]
                if set(cols) == {'company_id', 'provider'}:
                    needs_integration_rebuild = False
                    break
        
        if needs_integration_rebuild:
            cursor.executescript('''
                CREATE TABLE IF NOT EXISTS integrations_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id),
                    company_id INTEGER REFERENCES companies(id),
                    provider TEXT NOT NULL,
                    account_id TEXT,
                    status TEXT DEFAULT 'Not connected',
                    scopes TEXT,
                    access_token TEXT,
                    refresh_token TEXT,
                    expires_at INTEGER,
                    metadata TEXT,
                    connected_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(company_id, provider)
                );
                INSERT INTO integrations_new (id, user_id, company_id, provider, account_id, status, scopes, access_token, refresh_token, expires_at, metadata, connected_at, created_at, updated_at)
                SELECT id, user_id, company_id, provider, account_id, status, scopes, access_token, refresh_token, expires_at, metadata, connected_at, created_at, updated_at FROM integrations;
                DROP TABLE integrations;
                ALTER TABLE integrations_new RENAME TO integrations;
            ''')
            conn.commit()
    except sqlite3.OperationalError:
        pass

    # Phase 1: Multi-Tenant Schema Compatibility Backfill
    # Ensure all existing users have a default workspace mapped to them
    cursor.execute("SELECT id, email FROM users")
    existing_users = cursor.fetchall()
    
    for user_row in existing_users:
        u_id = user_row['id']
        u_email = user_row['email']
        
        cursor.execute("SELECT id FROM company_memberships WHERE user_id = ?", (u_id,))
        if not cursor.fetchone():
            default_name = f"{u_email.split('@')[0].capitalize()}'s Workspace"
            cursor.execute(
                "INSERT INTO companies (name, created_by, owner_user_id) VALUES (?, ?, ?)",
                (default_name, u_id, u_id)
            )
            new_comp_id = cursor.lastrowid
            
            cursor.execute(
                "INSERT INTO company_memberships (user_id, company_id, role, is_default) VALUES (?, ?, 'owner', 1)",
                (u_id, new_comp_id)
            )

    # Phase 3: Tenant Isolation Backfill
    # Ensure all existing rows obtain the active company_id from the user's default company
    for table in domain_tables:
        try:
            cursor.execute(f"""
                UPDATE {table}
                SET company_id = (
                    SELECT company_id 
                    FROM company_memberships 
                    WHERE company_memberships.user_id = {table}.user_id 
                    ORDER BY is_default DESC 
                    LIMIT 1
                )
                WHERE company_id IS NULL AND user_id IS NOT NULL
            """)
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()

    # Bootstrap Super Admin from environment
    if os.environ.get('ENABLE_SUPER_ADMIN_BOOTSTRAP', os.environ.get('SUPER_ADMIN_BOOTSTRAP', 'false')).lower() in ('true', '1'):
        admin_email = os.environ.get('SUPER_ADMIN_EMAIL', 'nedpearson@gmail.com').strip().lower()
        admin_pass = os.environ.get('SUPER_ADMIN_PASSWORD')
        if admin_email and admin_pass:
            import werkzeug.security
            user_record = get_user_by_email(admin_email)
            if not user_record:
                _id = create_user(admin_email, admin_pass, role='SUPER_ADMIN')
                if _id:
                    print(f"Super admin verified: {admin_email} created.")
            else:
                needs_repair = False
                if user_record.get('role') != 'SUPER_ADMIN':
                    needs_repair = True
                elif not werkzeug.security.check_password_hash(user_record['password_hash'], admin_pass):
                    needs_repair = True
                
                if needs_repair:
                    conn_admin = get_db()
                    conn_admin.execute("UPDATE users SET role = 'SUPER_ADMIN', password_hash = ? WHERE email = ?", 
                                       (werkzeug.security.generate_password_hash(admin_pass), admin_email))
                    conn_admin.commit()
                    conn_admin.close()
                    print(f"Super admin verified: {admin_email} repaired to SUPER_ADMIN with correct password.")
                else:
                    print(f"Super admin verified: {admin_email} already active and correct.")
# --- Company Admin & Access Management ---

def get_company_members(company_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cm.id as membership_id, cm.user_id, cm.company_id, cm.role,
               u.email, cm.created_at
        FROM company_memberships cm
        JOIN users u ON cm.user_id = u.id
        WHERE cm.company_id = ?
        ORDER BY cm.role='owner' DESC, u.email ASC
    """, (company_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_company_member_role(company_id, user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM company_memberships WHERE company_id = ? AND user_id = ?", (company_id, user_id))
    row = cursor.fetchone()
    conn.close()
    return row['role'] if row else None

def add_company_member(company_id, user_id, role='viewer', invited_by=None):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO company_memberships (user_id, company_id, role, invited_by)
            VALUES (?, ?, ?, ?)
        """, (user_id, company_id, role, invited_by))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def update_company_member_role(company_id, user_id, role):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE company_memberships SET role = ? WHERE company_id = ? AND user_id = ?", (role, company_id, user_id))
    conn.commit()
    conn.close()
    return True

def remove_company_member(company_id, user_id):
    conn = get_db()
    cursor = conn.cursor()
    # Safely prevent removing last owner
    cursor.execute("SELECT role FROM company_memberships WHERE company_id = ? AND user_id = ?", (company_id, user_id))
    row = cursor.fetchone()
    if row and row['role'] == 'owner':
        cursor.execute("SELECT count(*) as owner_count FROM company_memberships WHERE company_id = ? AND role = 'owner'", (company_id,))
        owner_count = cursor.fetchone()['owner_count']
        if owner_count <= 1:
            conn.close()
            return False, "Cannot remove the last owner of the company."
            
    cursor.execute("DELETE FROM company_memberships WHERE company_id = ? AND user_id = ?", (company_id, user_id))
    conn.commit()
    conn.close()
    return True, "Member removed."

def transfer_company_ownership(company_id, current_owner_id, new_owner_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if target user is in the company
    cursor.execute("SELECT id FROM company_memberships WHERE company_id = ? AND user_id = ?", (company_id, new_owner_id))
    if not cursor.fetchone():
        conn.close()
        return False, "Target user must be a member of the company before transferring ownership."
        
    try:
        # Transfer owner_user_id in companies table
        cursor.execute("UPDATE companies SET owner_user_id = ? WHERE id = ? AND owner_user_id = ?", (new_owner_id, company_id, current_owner_id))
        if cursor.rowcount == 0:
            conn.close()
            return False, "Not authorized or company not found."
            
        # Update roles
        cursor.execute("UPDATE company_memberships SET role = 'owner' WHERE company_id = ? AND user_id = ?", (company_id, new_owner_id))
        cursor.execute("UPDATE company_memberships SET role = 'admin' WHERE company_id = ? AND user_id = ?", (company_id, current_owner_id))
        conn.commit()
        return True, "Ownership transferred successfully."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()

def soft_delete_company(company_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE companies SET status = 'deleted' WHERE id = ?", (company_id,))
    conn.commit()
    conn.close()
    return True

def create_company_invitation(company_id, email, intended_role, invited_by_user_id, expires_hours=72):
    import secrets
    import hashlib
    from datetime import datetime, timedelta
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check for existing pending invites for this company/email
    cursor.execute("SELECT id FROM company_invitations WHERE company_id = ? AND email = ? AND status = 'pending'", (company_id, email))
    if cursor.fetchone():
        conn.close()
        return None, "A pending invitation already exists for this email in this company."
        
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = (datetime.utcnow() + timedelta(hours=expires_hours)).strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        cursor.execute("""
            INSERT INTO company_invitations 
            (company_id, email, intended_role, invited_by_user_id, token_hash, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (company_id, email, intended_role, invited_by_user_id, token_hash, expires_at))
        invite_id = cursor.lastrowid
        conn.commit()
        return {'id': invite_id, 'raw_token': raw_token, 'expires_at': expires_at}, None
    except Exception as e:
        return None, str(e)
    finally:
        conn.close()

def get_invitation_by_token(raw_token):
    import hashlib
    from datetime import datetime
    
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ci.*, c.name as company_name 
        FROM company_invitations ci
        JOIN companies c ON ci.company_id = c.id
        WHERE ci.token_hash = ?
    """, (token_hash,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None, "Invalid invitation token."
        
    invitation = dict(row)
    if invitation['status'] != 'pending':
        return invitation, f"Invitation is {invitation['status']}."
        
    if invitation['expires_at'] < datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'):
        # Auto-revoke if fetched and expired
        revoke_invitation(invitation['id'], system_auto=True)
        return invitation, "Invitation has expired."
        
    return invitation, None

def get_pending_invitations_for_company(company_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ci.id, ci.email, ci.intended_role, ci.status, ci.expires_at, ci.created_at,
               u.email as invited_by_email
        FROM company_invitations ci
        LEFT JOIN users u ON ci.invited_by_user_id = u.id
        WHERE ci.company_id = ? AND ci.status = 'pending'
        ORDER BY ci.created_at DESC
    """, (company_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def revoke_invitation(invite_id, system_auto=False):
    conn = get_db()
    cursor = conn.cursor()
    new_status = 'expired' if system_auto else 'revoked'
    cursor.execute("UPDATE company_invitations SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'", (new_status, invite_id))
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return success

def mark_invitation_accepted(invite_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE company_invitations SET status = 'accepted', accepted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'", (invite_id,))
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return success

# --- Identity / Auth Operations ---

def get_user_by_email(email):
    email = email.strip().lower()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_id(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def create_user(email, password, role='USER'):
    email = email.strip().lower()
    import werkzeug.security
    import sqlite3
    hashed = werkzeug.security.generate_password_hash(password)
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", (email, hashed, role))
        user_id = cursor.lastrowid
        conn.commit()
        seed_taxonomy(user_id)
        return user_id
    except sqlite3.IntegrityError as e:
        print(f"IntegrityError in create_user: {e}")
        return None
    except Exception as e:
        print(f"Error creating user: {e}")
        return None
    finally:
        conn.close()


def create_demo_user(wipe_data=False):
    """Guarantee a clean demo user exists, optionally wiping existing data to keep seeding idempotent."""
    import werkzeug.security
    conn = get_db()
    cursor = conn.cursor()
    
    email = "demo@forensiccpa.ai"
    password = "demo_password_not_used"
    hashed = werkzeug.security.generate_password_hash(password)
    
    try:
        # Check if exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user_row = cursor.fetchone()
        
        if user_row:
            user_id = user_row['id']
            # Wipe existing tenant data for idempotent seeded demo runs
            if wipe_data:
                tables = [
                    'audit_log', 'proof_links', 'document_categorizations', 
                    'document_extractions', 'drilldown_logs', 'case_notes', 
                    'saved_filters', 'category_rules', 'categories', 'taxonomy_config',
                    'transactions', 'documents', 'accounts'
                ]
                for t in tables:
                    cursor.execute(f"DELETE FROM {t} WHERE user_id = ?", (user_id,))
                
            # Ensure is_demo is flipped just in case
            cursor.execute("UPDATE users SET is_demo = 1, password_hash = ? WHERE id = ?", (hashed, user_id))
        else:
            # Create new
            cursor.execute(
                "INSERT INTO users (email, password_hash, is_demo) VALUES (?, ?, 1)", 
                (email, hashed)
            )
            user_id = cursor.lastrowid
            
        conn.commit()
        return user_id
    except Exception as e:
        print(f"Error initializing demo user: {e}")
        return None


# --- Data Management ---

def clear_all_data(user_id):
    """Delete all financial data while keeping categories and rules."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.executescript(f"""
        DELETE FROM proof_links WHERE user_id = {user_id};
        DELETE FROM audit_log WHERE user_id = {user_id};
        DELETE FROM case_notes WHERE user_id = {user_id};
        DELETE FROM transaction_sources WHERE user_id = {user_id};
        UPDATE transactions SET document_id = NULL WHERE user_id = {user_id};
        DELETE FROM transactions WHERE user_id = {user_id};
        DELETE FROM document_categorizations WHERE user_id = {user_id};
        DELETE FROM document_extractions WHERE user_id = {user_id};
        UPDATE documents SET parent_document_id = NULL WHERE user_id = {user_id};
        DELETE FROM documents WHERE user_id = {user_id};
        DELETE FROM accounts WHERE user_id = {user_id};
        DELETE FROM saved_filters WHERE user_id = {user_id};
    """)
    conn.commit()
    conn.close()


# --- CRUD Operations ---

def add_account(user_id, account_name, account_number, account_type, institution, cardholder_name=None, card_last_four=None, notes=None, conn=None, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()

    is_external_conn = conn is not None
    db_conn = conn or get_db()
    cursor = db_conn.cursor()
    cursor.execute(
        "INSERT INTO accounts (user_id, company_id, account_name, account_number, account_type, institution, cardholder_name, card_last_four, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, company_id, account_name, account_number, account_type, institution, cardholder_name, card_last_four, notes)
    )
    account_id = cursor.lastrowid
    if not is_external_conn:
        db_conn.commit()
        db_conn.close()
    return account_id


def get_or_create_account(user_id, account_name, account_number, account_type, institution, cardholder_name=None, card_last_four=None, conn=None, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()

    is_external_conn = conn is not None
    db_conn = conn or get_db()
    cursor = db_conn.cursor()
    cursor.execute(
        "SELECT id FROM accounts WHERE user_id = ? AND company_id = ? AND account_number = ? AND account_type = ? AND (cardholder_name = ? OR cardholder_name IS NULL)",
        (user_id, company_id, account_number, account_type, cardholder_name)
    )
    row = cursor.fetchone()
    if row:
        if not is_external_conn:
            db_conn.close()
        return row['id']
    if not is_external_conn:
        db_conn.close()
    return add_account(user_id, account_name, account_number, account_type, institution, cardholder_name, card_last_four, conn=conn, company_id=company_id)

def get_duplicate_document(user_id, content_sha256):
    if not content_sha256:
        return None
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM documents WHERE user_id = ? AND content_sha256 = ?", (user_id, content_sha256))
    row = cursor.fetchone()
    conn.close()
    return row['id'] if row else None


def add_document(user_id, filename, original_path, file_type, doc_category, account_id=None, statement_start=None, statement_end=None, notes=None, content_sha256=None, parent_document_id=None, status='queued', conn=None, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    is_external_conn = conn is not None
    db_conn = conn or get_db()
    cursor = db_conn.cursor()
    
    if content_sha256:
        cursor.execute("SELECT id FROM documents WHERE user_id = ? AND company_id = ? AND content_sha256 = ?", (user_id, company_id, content_sha256))
        row = cursor.fetchone()
        if row:
            if not is_external_conn:
                db_conn.close()
            return row['id']

    cursor.execute(
        "INSERT INTO documents (user_id, company_id, filename, original_path, file_type, doc_category, account_id, statement_start_date, statement_end_date, notes, content_sha256, parent_document_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, company_id, filename, original_path, file_type, doc_category, account_id, statement_start, statement_end, notes, content_sha256, parent_document_id, status)
    )
    doc_id = cursor.lastrowid
    
    if not is_external_conn:
        db_conn.commit()
        db_conn.close()
        
    return doc_id


def delete_document(user_id, doc_id, conn=None, company_id=None):
    """
    Deletes a document, its children (if zip), and safely removes orphan transactions.
    """
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    with document_lock(doc_id):
        is_external_conn = conn is not None
        db_conn = conn or get_db()
        cursor = db_conn.cursor()
        
        # 1. Get document details
        cursor.execute("SELECT id, filename, file_type, status FROM documents WHERE id = ? AND user_id = ? AND company_id = ?", (doc_id, user_id, company_id))
        doc = cursor.fetchone()
        if not doc:
            if not is_external_conn:
                db_conn.close()
            return False
            
        # Block deleting documents currently locked by background threads
        if doc['status'] == 'processing':
            print(f"Cannot delete document {doc_id} while it is actively processing.")
            if not is_external_conn:
                db_conn.close()
            return False
            
        doc_ids_to_delete = [doc_id]
        
        # 2. Find any children documents (if zip container)
        if doc['file_type'] == 'zip':
            cursor.execute("SELECT id FROM documents WHERE parent_document_id = ? AND user_id = ? AND company_id = ?", (doc_id, user_id, company_id))
            children = cursor.fetchall()
            doc_ids_to_delete.extend([child['id'] for child in children])
            
        # Create placeholders
        placeholders = ','.join('?' for _ in doc_ids_to_delete)
        
        try:
            # 3. Delete from transaction_sources
            cursor.execute(f"DELETE FROM transaction_sources WHERE document_id IN ({placeholders}) AND user_id = ?", (*doc_ids_to_delete, user_id))
            
            # 4. Remove orphan transactions
            cursor.execute("""
                DELETE FROM transactions 
                WHERE user_id = ? AND company_id = ?
                AND id NOT IN (SELECT transaction_id FROM transaction_sources WHERE user_id = ?)
            """, (user_id, company_id, user_id))
            
            # 4.5. Reassign or clear document_id for surviving transactions that referenced this document
            cursor.execute(f"""
                UPDATE transactions 
                SET document_id = NULL
                WHERE document_id IN ({placeholders}) AND user_id = ? AND company_id = ?
            """, (*doc_ids_to_delete, user_id, company_id))
            
            # 5. Delete document_extractions and categorizations explicitly if foreign key cascade lacks
            cursor.execute(f"DELETE FROM document_categorizations WHERE document_id IN ({placeholders}) AND user_id = ?", (*doc_ids_to_delete, user_id))
            cursor.execute(f"DELETE FROM document_extractions WHERE document_id IN ({placeholders}) AND user_id = ?", (*doc_ids_to_delete, user_id))
    
            # 6. Nullify parent_document_id on any document referencing these before they are deleted
            cursor.execute(f"UPDATE documents SET parent_document_id = NULL WHERE parent_document_id IN ({placeholders}) AND user_id = ? AND company_id = ?", (*doc_ids_to_delete, user_id, company_id))
    
            # 7. Delete documents
            cursor.execute(f"DELETE FROM documents WHERE id IN ({placeholders}) AND user_id = ? AND company_id = ?", (*doc_ids_to_delete, user_id, company_id))
            
            if not is_external_conn:
                db_conn.commit()
        except Exception as e:
            if not is_external_conn:
                db_conn.rollback()
            print(f"Error during document deletion: {e}")
            if not is_external_conn:
                db_conn.close()
            return False
            
        if not is_external_conn:
            db_conn.close()
        return True


VALID_TRANSITIONS = {
    'uploaded': ['extracting', 'failed'],
    'extracting': ['extracted', 'failed'],
    'extracted': ['generating_previews', 'parsing', 'pending_approval', 'completed', 'failed'],
    'generating_previews': ['parsing', 'pending_approval', 'completed', 'failed'],
    'queued': ['processing', 'completed', 'failed', 'pending_approval'], 
    'processing': ['parsed', 'completed', 'failed'],
    'parsing': ['completed', 'pending_approval', 'failed'],
    'parsed': ['completed', 'pending_approval', 'approved', 'failed'],
    'completed': ['pending_approval', 'approved', 'failed'],
    'pending_approval': ['approved', 'failed'],
    'approved': [], # Terminal
    'failed': ['queued', 'uploaded', 'extracting'] # Retry
}

def update_document_status(user_id, doc_id, status=None, parsed_count=None, import_count=None, skipped_count=None, failure_reason=None, conn=None, company_id=None):
    """Update the status and tracking metrics of a document with strict state-machine enforcement."""
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    with document_lock(doc_id):
        is_external_conn = conn is not None
        db_conn = conn or get_db()
        cursor = db_conn.cursor()
        
        try:
            # Enforce State Machine and Terminal States
            cursor.execute("SELECT status FROM documents WHERE id = ? AND user_id = ? AND company_id = ?", (doc_id, user_id, company_id))
            row = cursor.fetchone()
            if row:
                current_status = row['status']
                
                # Block all modifications to documents in a terminal state
                if current_status == 'approved':
                    print(f"Workflow State Error: Document {doc_id} is already in terminal state ('approved') and cannot be modified.")
                    if not is_external_conn:
                        db_conn.close()
                    return False
                    
                if status is not None and current_status != status: # If it's a real transition attempt
                    if current_status in VALID_TRANSITIONS and status not in VALID_TRANSITIONS[current_status]:
                        print(f"Workflow State Error: Invalid transition from '{current_status}' to '{status}' for document {doc_id}")
                        if not is_external_conn:
                            db_conn.rollback()
                            db_conn.close()
                        else:
                            raise ValueError(f"Invalid transition from '{current_status}' to '{status}'")
                        return False
    
            updates = []
            params = []
            
            if status is not None:
                updates.append("status = ?")
                params.append(status)
            if parsed_count is not None:
                updates.append("parsed_transaction_count = ?")
                params.append(parsed_count)
            if import_count is not None:
                updates.append("import_transaction_count = ?")
                params.append(import_count)
            if skipped_count is not None:
                updates.append("deduped_skipped_count = ?")
                params.append(skipped_count)
            if failure_reason is not None:
                updates.append("failure_reason = ?")
                params.append(failure_reason)
                
            if not updates:
                if not is_external_conn:
                    db_conn.close()
                return True
                
            params.extend([doc_id, user_id, company_id])
            query = f"UPDATE documents SET {', '.join(updates)} WHERE id = ? AND user_id = ? AND company_id = ?"
            
            cursor.execute(query, tuple(params))
            
            if not is_external_conn:
                db_conn.commit()
        except Exception as e:
            print(f"Error updating document status: {e}")
            if not is_external_conn:
                db_conn.rollback()
            raise e
        finally:
            if not is_external_conn:
                db_conn.close()
            
        return True

def find_duplicate_transactions(user_id, transactions, company_id=None):
    """Check a list of parsed transactions against existing DB transactions.
    Returns list of (index, existing_transaction) tuples for duplicates."""
    if company_id is None:
        company_id = _get_active_company_id_shim()

    conn = get_db()
    cursor = conn.cursor()
    duplicates = []
    dates = set()
    for i, t in enumerate(transactions):
        t_date = t.get('trans_date')
        if t_date:
            dates.add(t_date)

    if not dates:
        conn.close()
        return duplicates

    # Batch fetch all transactions on these dates
    date_list = list(dates)
    existing_map = {}
    batch_size = 900

    for idx in range(0, len(date_list), batch_size):
        batch = date_list[idx:idx+batch_size]
        placeholders = ','.join('?' for _ in batch)
        cursor.execute(f"""
            SELECT id, trans_date, description, amount FROM transactions
            WHERE user_id = ? AND company_id = ? AND trans_date IN ({placeholders})
        """, (user_id, company_id, *batch))
        
        for row in cursor.fetchall():
            key = (row['trans_date'], row['description'].upper() if row['description'] else '', round(float(row['amount']), 2))
            existing_map[key] = dict(row)

    for i, t in enumerate(transactions):
        t_date = t.get('trans_date', '')
        t_desc = t.get('description', '').upper()
        t_amt = round(float(t.get('amount', 0)), 2)
        key = (t_date, t_desc, t_amt)
        
        if key in existing_map:
            duplicates.append({'index': i, 'existing': existing_map[key]})
            
    conn.close()
    return duplicates


def add_transaction(user_id, doc_id, account_id, trans_date, post_date, description, amount, trans_type, category='uncategorized', company_id=None, **kwargs):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    
    txn_fingerprint = kwargs.get('txn_fingerprint')
    if txn_fingerprint:
        cursor.execute("SELECT id FROM transactions WHERE user_id = ? AND company_id = ? AND txn_fingerprint = ?", (user_id, company_id, txn_fingerprint))
        existing = cursor.fetchone()
        if existing:
            trans_id = existing['id']
            if doc_id:
                try:
                    cursor.execute("""
                        INSERT OR IGNORE INTO transaction_sources (user_id, transaction_id, document_id)
                        VALUES (?, ?, ?)
                    """, (user_id, trans_id, doc_id))
                    conn.commit()
                except sqlite3.OperationalError:
                    pass
            conn.close()
            return trans_id, False

    cursor.execute("""
        INSERT INTO transactions (user_id, company_id, document_id, account_id, trans_date, post_date, description, amount, trans_type, category,
            subcategory, cardholder_name, card_last_four, payment_method, check_number,
            is_transfer, transfer_to_account, transfer_from_account,
            is_personal, is_business, is_flagged, flag_reason, auto_categorized, manually_edited, txn_fingerprint, is_approved,
            merchant_id, categorization_confidence, categorization_source, categorization_status, categorization_explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, company_id, doc_id, account_id, trans_date, post_date, description, amount, trans_type, category,
        kwargs.get('subcategory'), kwargs.get('cardholder_name'), kwargs.get('card_last_four'),
        kwargs.get('payment_method'), kwargs.get('check_number'),
        kwargs.get('is_transfer', 0), kwargs.get('transfer_to_account'), kwargs.get('transfer_from_account'),
        kwargs.get('is_personal', 0), kwargs.get('is_business', 0),
        kwargs.get('is_flagged', 0), kwargs.get('flag_reason'),
        kwargs.get('auto_categorized', 1), kwargs.get('manually_edited', 0), txn_fingerprint, kwargs.get('is_approved', 1),
        kwargs.get('merchant_id'), kwargs.get('categorization_confidence'), kwargs.get('categorization_source'),
        kwargs.get('categorization_status'), kwargs.get('categorization_explanation')
    ))
    trans_id = cursor.lastrowid
    
    if doc_id:
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO transaction_sources (user_id, transaction_id, document_id)
                VALUES (?, ?, ?)
            """, (user_id, trans_id, doc_id))
        except sqlite3.OperationalError:
            pass
            
    conn.commit()
    conn.close()
    return trans_id, True


def add_transactions_bulk(user_id, account_id, transactions_with_hashes, target_doc_ids, conn=None, company_id=None):
    """
    Bulk insert transactions within a single transaction boundary for performance and reliability.
    transactions_with_hashes: list of dicts with 'trans' (the transaction dictionary) and 'txn_fingerprint' (the deduplication hash)
    target_doc_ids: list of document_ids corresponding to each transaction.
    Returns (added_count, skipped_count, doc_stats)
    Where doc_stats is {doc_id: {'added': count, 'skipped': count, 'total': count}}
    """
    if company_id is None:
        company_id = _get_active_company_id_shim()

    is_external_conn = conn is not None
    db_conn = conn or get_db()
    cursor = db_conn.cursor()
    
    try:
        # 1. First, check which ones already exist
        fingerprints = [t['txn_fingerprint'] for t in transactions_with_hashes]
        # We can fetch existing in batches to avoid large IN clauses, but SQLite handles up to 32766 parameters.
        # We'll just do one query if it's < 30000, else we batch it.
        existing_map = {}
        batch_size = 999
        
        for i in range(0, len(fingerprints), batch_size):
            batch = fingerprints[i:i+batch_size]
            placeholders = ','.join('?' for _ in batch)
            cursor.execute(f"SELECT txn_fingerprint, id FROM transactions WHERE user_id = ? AND company_id = ? AND txn_fingerprint IN ({placeholders})", (user_id, company_id, *batch))
            for row in cursor.fetchall():
                existing_map[row['txn_fingerprint']] = row['id']

                
        insertions = []
        source_insertions = []
        
        added_count = 0
        skipped_count = 0
        doc_stats = {}
        new_fps_set = set()
        
        for i, item in enumerate(transactions_with_hashes):
            t = item['trans']
            fp = item['txn_fingerprint']
            target_doc_id = target_doc_ids[i]
            
            if target_doc_id not in doc_stats:
                doc_stats[target_doc_id] = {'added': 0, 'skipped': 0, 'total': 0}
                
            doc_stats[target_doc_id]['total'] += 1
            
            if fp in existing_map:
                # Transaction already exists
                trans_id = existing_map[fp]
                if target_doc_id:
                    # Still need to record the source mapping
                    if trans_id != 'PENDING_INSERT':
                        source_insertions.append((user_id, trans_id, target_doc_id))
                skipped_count += 1
                doc_stats[target_doc_id]['skipped'] += 1
            else:
                # Prepare for insertion
                insertions.append((
                    user_id, company_id, target_doc_id, account_id, t['trans_date'], t.get('post_date', t['trans_date']), 
                    t['description'], t['amount'], t.get('trans_type', 'debit'), t.get('category', 'Uncategorized'),
                    t.get('subcategory'), t.get('cardholder_name', ''), t.get('card_last_four', ''),
                    t.get('payment_method', ''), t.get('check_number'),
                    t.get('is_transfer', 0), t.get('transfer_to_account'), t.get('transfer_from_account'),
                    t.get('is_personal', 0), t.get('is_business', 0),
                    t.get('is_flagged', 0), t.get('flag_reason'),
                    t.get('auto_categorized', 1), t.get('manually_edited', 0), fp, t.get('is_approved', 1),
                    t.get('merchant_id'), t.get('categorization_confidence'), t.get('categorization_source'),
                    t.get('categorization_status'), t.get('categorization_explanation')
                ))
                existing_map[fp] = 'PENDING_INSERT'
                new_fps_set.add(fp)
                added_count += 1
                doc_stats[target_doc_id]['added'] += 1
                
        # Execute insertions
        if insertions:
            cursor.executemany("""
                INSERT INTO transactions (user_id, company_id, document_id, account_id, trans_date, post_date, description, amount, trans_type, category,
                    subcategory, cardholder_name, card_last_four, payment_method, check_number,
                    is_transfer, transfer_to_account, transfer_from_account,
                    is_personal, is_business, is_flagged, flag_reason, auto_categorized, manually_edited, txn_fingerprint, is_approved,
                    merchant_id, categorization_confidence, categorization_source, categorization_status, categorization_explanation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, insertions)
            
            new_fps = list(new_fps_set)
            for i in range(0, len(new_fps), batch_size):
                batch = new_fps[i:i+batch_size]
                placeholders = ','.join('?' for _ in batch)
                cursor.execute(f"SELECT txn_fingerprint, id FROM transactions WHERE user_id = ? AND company_id = ? AND txn_fingerprint IN ({placeholders})", (user_id, company_id, *batch))
                for row in cursor.fetchall():
                    existing_map[row['txn_fingerprint']] = row['id']
                    
            # Now construct source insertions for new IDs
            for i, item in enumerate(transactions_with_hashes):
                fp = item['txn_fingerprint']
                target_doc_id = target_doc_ids[i]
                if fp in new_fps_set and fp in existing_map:
                    source_insertions.append((user_id, existing_map[fp], target_doc_id))
                    
        if source_insertions:
            cursor.executemany("""
                INSERT OR IGNORE INTO transaction_sources (user_id, transaction_id, document_id)
                VALUES (?, ?, ?)
            """, source_insertions)
            
        if not is_external_conn:
            db_conn.commit()
    except Exception as e:
        if not is_external_conn:
            db_conn.rollback()
        raise e
    finally:
        if not is_external_conn:
            db_conn.close()
        
    return added_count, skipped_count, doc_stats

def update_transaction(user_id, trans_id, company_id=None, **fields):
    """Update a transaction and log the changes."""
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()

    # Get current values for audit log
    cursor.execute("SELECT * FROM transactions WHERE id = ? AND user_id = ? AND company_id = ?", (trans_id, user_id, company_id))
    old = dict(cursor.fetchone() or {})
    if not old:
        conn.close()
        return

    set_clauses = []
    values = []
    for field, value in fields.items():
        set_clauses.append(f"{field} = ?")
        values.append(value)
        # Log the change
        if str(old.get(field)) != str(value):
            cursor.execute(
                "INSERT INTO audit_log (user_id, transaction_id, action, old_value, new_value, field_changed) VALUES (?, ?, 'update', ?, ?, ?)",
                (user_id, trans_id, str(old.get(field)), str(value), field)
            )

    set_clauses.append("updated_at = ?")
    values.append(datetime.now().isoformat())
    
    # Only flag as manually edited if explicitly told to, or by default for legacy
    if fields.get('manually_edited', 1) == 1:
        set_clauses.append("manually_edited = 1")
    
    values.append(trans_id)
    values.append(user_id)
    values.append(company_id)

    cursor.execute(f"UPDATE transactions SET {', '.join(set_clauses)} WHERE id = ? AND user_id = ? AND company_id = ?", values)
    conn.commit()
    conn.close()


def delete_transaction(user_id, trans_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions WHERE id = ? AND user_id = ? AND company_id = ?", (trans_id, user_id, company_id))
    old = cursor.fetchone()
    if old:
        cursor.execute(
            "INSERT INTO audit_log (user_id, transaction_id, action, old_value, field_changed) VALUES (?, ?, 'delete', ?, 'all')",
            (user_id, trans_id, str(dict(old)))
        )
    cursor.execute("DELETE FROM transactions WHERE id = ? AND user_id = ? AND company_id = ?", (trans_id, user_id, company_id))
    conn.commit()
    conn.close()


def get_transactions(user_id, filters=None, company_id=None):
    """Get transactions with optional filters."""
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()

    query = """
        SELECT t.*, d.filename as doc_filename, a.account_name, a.institution
        FROM transactions t
        LEFT JOIN documents d ON t.document_id = d.id AND d.company_id = t.company_id
        LEFT JOIN accounts a ON t.account_id = a.id AND a.company_id = t.company_id
        WHERE t.user_id = ? AND t.company_id = ?
    """
    params = [user_id, company_id]

    if filters:
        if filters.get('category'):
            query += " AND t.category = ?"
            params.append(filters['category'])
        if filters.get('cardholder'):
            query += " AND t.cardholder_name LIKE ?"
            params.append(f"%{filters['cardholder']}%")
        if filters.get('trans_type'):
            query += " AND t.trans_type = ?"
            params.append(filters['trans_type'])
        if filters.get('date_from'):
            query += " AND t.trans_date >= ?"
            params.append(filters['date_from'])
        if filters.get('date_to'):
            query += " AND t.trans_date <= ?"
            params.append(filters['date_to'])
        if filters.get('is_flagged'):
            query += " AND t.is_flagged = 1"
        if filters.get('is_personal'):
            query += " AND t.is_personal = 1"
        if filters.get('is_business'):
            query += " AND t.is_business = 1"
        if filters.get('is_transfer'):
            query += " AND t.is_transfer = 1"
        if filters.get('search'):
            query += " AND t.description LIKE ?"
            params.append(f"%{filters['search']}%")
        if filters.get('account_id'):
            query += " AND t.account_id = ?"
            params.append(filters['account_id'])
        if filters.get('min_amount'):
            query += " AND ABS(t.amount) >= ?"
            params.append(float(filters['min_amount']))
        if filters.get('max_amount'):
            query += " AND ABS(t.amount) <= ?"
            params.append(float(filters['max_amount']))
        if filters.get('view_mode') == 'personal':
            query += " AND t.is_personal = 1"
        elif filters.get('view_mode') == 'business':
            query += " AND t.is_business = 1"

    query += " ORDER BY t.trans_date DESC, t.id DESC"

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def _is_super_admin():
    from flask_login import current_user
    try:
        return current_user.is_authenticated and getattr(current_user, 'role', '') == 'SUPER_ADMIN'
    except Exception:
        return False

def add_category(user_id, name, parent_category=None, category_type='other', color='#6c757d', icon='tag', company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO categories (user_id, company_id, name, parent_category, category_type, color, icon)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, company_id, name, parent_category, category_type, color, icon))
        cat_id = cursor.lastrowid
        conn.commit()
        return cat_id
    except Exception as e:
        print(f"Error adding category: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()

def get_categories(user_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM categories WHERE user_id = ? AND company_id = ? ORDER BY name", (user_id, company_id))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_accounts(user_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE user_id = ? AND company_id = ? ORDER BY account_name", (user_id, company_id))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_documents(user_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            d.id, d.user_id, d.filename, d.original_path, d.file_type, 
            d.upload_date, d.status, 
            COALESCE(d.parsed_transaction_count, 0) + COALESCE(SUM(c.parsed_transaction_count), 0) as parsed_transaction_count,
            COALESCE(d.import_transaction_count, 0) + COALESCE(SUM(c.import_transaction_count), 0) as import_transaction_count,
            COALESCE(d.deduped_skipped_count, 0) + COALESCE(SUM(c.deduped_skipped_count), 0) as deduped_skipped_count,
            d.failure_reason, d.doc_category, d.account_id, d.content_sha256, d.parent_document_id,
            a.account_name 
        FROM documents d 
        LEFT JOIN accounts a ON d.account_id = a.id 
        LEFT JOIN documents c ON c.parent_document_id = d.id AND c.user_id = d.user_id AND c.company_id = d.company_id
        WHERE d.user_id = ? AND d.company_id = ? 
        GROUP BY d.id
        ORDER BY d.upload_date DESC
    """, (user_id, company_id))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def build_filter_clause(user_id, filters=None, table_alias='', company_id=None):
    """Build a SQL WHERE clause and parameter list from a filters dictionary."""
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    prefix = f"{table_alias}." if table_alias else ""
    
    where = f"WHERE {prefix}user_id = ? AND {prefix}company_id = ?"
    params = [user_id, company_id]
    
    if not filters:
        return where, params

    if filters.get('date_from'):
        where += f" AND {prefix}trans_date >= ?"
        params.append(filters['date_from'])
    if filters.get('date_to'):
        where += f" AND {prefix}trans_date <= ?"
        params.append(filters['date_to'])
    if filters.get('cardholder'):
        where += f" AND {prefix}cardholder_name LIKE ?"
        params.append(f"%{filters['cardholder']}%")
    if filters.get('card_last_four'):
        where += f" AND {prefix}card_last_four = ?"
        params.append(filters['card_last_four'])
    if filters.get('account_id'):
        where += f" AND {prefix}account_id = ?"
        params.append(filters['account_id'])
    if filters.get('category'):
        where += f" AND {prefix}category = ?"
        params.append(filters['category'])
    if filters.get('trans_type'):
        where += f" AND {prefix}trans_type = ?"
        params.append(filters['trans_type'])
    if filters.get('payment_method'):
        where += f" AND {prefix}payment_method = ?"
        params.append(filters['payment_method'])
    if filters.get('document_id'):
        where += f" AND {prefix}id IN (SELECT transaction_id FROM transaction_sources WHERE document_id = ?)"
        params.append(filters['document_id'])
    if str(filters.get('is_flagged')) == '1':
        where += f" AND {prefix}is_flagged = 1"
    if str(filters.get('is_transfer')) == '1':
        where += f" AND {prefix}is_transfer = 1"
    if filters.get('search'):
        where += f" AND {prefix}description LIKE ?"
        params.append(f"%{filters['search']}%")
    if filters.get('min_amount'):
        where += f" AND ABS({prefix}amount) >= ?"
        params.append(float(filters['min_amount']))
    if filters.get('max_amount'):
        where += f" AND ABS({prefix}amount) <= ?"
        params.append(float(filters['max_amount']))

    # By default, only show approved transactions UNLESS we are viewing a specific document
    if not filters.get('document_id') and not filters.get('include_pending'):
        where += f" AND {prefix}is_approved = 1"

    is_personal_str = str(filters.get('is_personal', ''))
    is_business_str = str(filters.get('is_business', ''))
    view_mode = filters.get('view_mode')
    
    if view_mode == 'personal' or is_personal_str == '1' or is_personal_str.lower() == 'true':
        where += f" AND {prefix}is_personal = 1"
    elif view_mode == 'business' or is_business_str == '1' or is_business_str.lower() == 'true':
        where += f" AND {prefix}is_business = 1"

    return where, params

def get_summary_stats(user_id, filters=None, company_id=None):
    """Get summary statistics for dashboard."""
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()

    where, params = build_filter_clause(user_id, filters, company_id=company_id)

    stats = {}

    # Total deposits
    cursor.execute(f"SELECT COALESCE(SUM(amount), 0) as total, COUNT(*) as cnt FROM transactions {where} AND amount > 0", params)
    row = cursor.fetchone()
    stats['total_deposits'] = row['total']
    stats['deposit_count'] = row['cnt']

    # Total withdrawals
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt FROM transactions {where} AND amount < 0", params)
    row = cursor.fetchone()
    stats['total_withdrawals'] = row['total']
    stats['withdrawal_count'] = row['cnt']

    # Transfers out
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt FROM transactions {where} AND is_transfer = 1 AND amount < 0", params)
    row = cursor.fetchone()
    stats['transfers_out'] = row['total']
    stats['transfer_out_count'] = row['cnt']

    # Personal spending
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt FROM transactions {where} AND is_personal = 1", params)
    row = cursor.fetchone()
    stats['personal_total'] = row['total']
    stats['personal_count'] = row['cnt']

    # Business spending
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt FROM transactions {where} AND is_business = 1", params)
    row = cursor.fetchone()
    stats['business_total'] = row['total']
    stats['business_count'] = row['cnt']

    # Fees
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt FROM transactions {where} AND category LIKE 'Fees%'", params)
    row = cursor.fetchone()
    stats['fees_total'] = row['total']
    stats['fees_count'] = row['cnt']

    # Flagged
    cursor.execute(f"SELECT COUNT(*) as cnt FROM transactions {where} AND is_flagged = 1", params)
    stats['flagged_count'] = cursor.fetchone()['cnt']

    # By cardholder
    cursor.execute(f"""
        SELECT cardholder_name,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total_spent,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as total_received,
            COUNT(*) as cnt
        FROM transactions {where} AND cardholder_name IS NOT NULL AND cardholder_name != ''
        GROUP BY cardholder_name ORDER BY total_spent DESC
    """, params)
    stats['by_cardholder'] = [dict(r) for r in cursor.fetchall()]

    # By category
    cursor.execute(f"""
        SELECT category,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as spent,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as received,
            COUNT(*) as cnt
        FROM transactions {where}
        GROUP BY category ORDER BY spent DESC
    """, params)
    stats['by_category'] = [dict(r) for r in cursor.fetchall()]

    # Monthly trend
    cursor.execute(f"""
        SELECT substr(trans_date, 1, 7) as month,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as deposits,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as withdrawals,
            COALESCE(SUM(CASE WHEN is_transfer = 1 AND amount < 0 THEN ABS(amount) ELSE 0 END), 0) as transfers_out
        FROM transactions {where}
        GROUP BY month ORDER BY month
    """, params)
    stats['monthly_trend'] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return stats


def add_category_rule(user_id, pattern, category, subcategory=None, is_personal=0, is_business=0, is_transfer=0, priority=50, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    
    # Enforce case-insensitive uniqueness globally to stop duplicate fragment rules
    pattern = pattern.upper()
    
    # Check if a rule for this pattern already exists for the user
    cursor.execute("SELECT id, category, priority, hit_count FROM category_rules WHERE user_id = ? AND company_id = ? AND pattern = ?", (user_id, company_id, pattern))
    existing_rule = cursor.fetchone()
    
    if existing_rule:
        rule_id = existing_rule['id']
        existing_category = existing_rule['category']
        existing_priority = existing_rule['priority']
        
        hit_count = 1
        if 'hit_count' in existing_rule.keys() and existing_rule['hit_count'] is not None:
            hit_count = existing_rule['hit_count']
        
        if existing_category == category:
            # Strengthening: Same category
            new_hit_count = hit_count + 1
            
            if priority == 100:
                new_priority = 100
            elif priority <= 40:
                # Weak AI suggestion doesn't actively push up high priority rules
                new_priority = max(existing_priority, priority)
            else:
                # Accelerate Priority scaling for loyal rules (User confirmed again)
                if new_hit_count >= 5: new_priority = 95
                elif new_hit_count >= 4: new_priority = 85
                elif new_hit_count >= 3: new_priority = 80
                elif new_hit_count >= 2: new_priority = 65
                else: new_priority = max(existing_priority, priority + 5)
            
            new_priority = min(100, max(existing_priority, new_priority))
            
            cursor.execute(
                "UPDATE category_rules SET subcategory = ?, is_personal = ?, is_business = ?, is_transfer = ?, priority = ?, hit_count = ?, last_applied = CURRENT_TIMESTAMP WHERE id = ?",
                (subcategory, is_personal, is_business, is_transfer, new_priority, new_hit_count, rule_id)
            )
        else:
            # Correction: Different category
            if priority == 100:
                # Explicit override bypasses safeguards
                cursor.execute(
                    "UPDATE category_rules SET category = ?, subcategory = ?, is_personal = ?, is_business = ?, is_transfer = ?, priority = ?, hit_count = 1, last_applied = CURRENT_TIMESTAMP WHERE id = ?",
                    (category, subcategory, is_personal, is_business, is_transfer, 100, rule_id)
                )
            elif priority <= 40:
                # AI weak suggestion bouncing off an existing rule. Ignore.
                pass
            else:
                # Passive User Edit correcting a past rule
                if existing_priority >= 80:
                    # Stability Safeguard & Active Decay Penalty
                    # Demote the old rule heavily but do not flip the category yet
                    demoted_priority = existing_priority - 20
                    cursor.execute(
                        "UPDATE category_rules SET priority = ? WHERE id = ?",
                        (demoted_priority, rule_id)
                    )
                else:
                    # Faster Correction Recovery: Overwrite and rapidly jump priority
                    cursor.execute(
                        "UPDATE category_rules SET category = ?, subcategory = ?, is_personal = ?, is_business = ?, is_transfer = ?, priority = ?, hit_count = 1, last_applied = CURRENT_TIMESTAMP WHERE id = ?",
                        (category, subcategory, is_personal, is_business, is_transfer, max(priority, 60), rule_id)
                    )
    else:
        # Insert a fresh rule
        cursor.execute(
            "INSERT INTO category_rules (user_id, company_id, pattern, category, subcategory, is_personal, is_business, is_transfer, priority, hit_count, last_applied) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)",
            (user_id, company_id, pattern, category, subcategory, is_personal, is_business, is_transfer, priority)
        )
        
    conn.commit()
    conn.close()


def get_category_rules(user_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM category_rules WHERE user_id = ? AND company_id = ? ORDER BY priority DESC, pattern", (user_id, company_id))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# --- Proof Document Links ---

def link_proof(user_id, transaction_id, document_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO proof_links (user_id, transaction_id, document_id) VALUES (?, ?, ?)",
        (user_id, transaction_id, document_id)
    )
    conn.commit()
    conn.close()


def unlink_proof(user_id, transaction_id, document_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM proof_links WHERE transaction_id = ? AND document_id = ? AND user_id = ?",
        (transaction_id, document_id, user_id)
    )
    conn.commit()
    conn.close()


def get_proofs_for_transaction(user_id, transaction_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.* FROM documents d
        JOIN proof_links pl ON pl.document_id = d.id
        WHERE pl.transaction_id = ? AND pl.user_id = ?
        ORDER BY d.upload_date DESC
    """, (transaction_id, user_id))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_transactions_for_proof(user_id, document_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.id, t.trans_date, t.description, t.amount
        FROM transactions t
        JOIN proof_links pl ON pl.transaction_id = t.id
        WHERE pl.document_id = ? AND pl.user_id = ?
        ORDER BY t.trans_date DESC
    """, (document_id, user_id))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# --- Case Notes ---

def get_case_notes(user_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM case_notes WHERE user_id = ? AND company_id = ? ORDER BY updated_at DESC", (user_id, company_id))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def add_case_note(user_id, title, content, note_type='general', severity='info', linked_transaction_ids=None, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO case_notes (user_id, company_id, title, content, note_type, severity, linked_transaction_ids) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, company_id, title, content, note_type, severity, json.dumps(linked_transaction_ids or []))
    )
    note_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return note_id


def update_case_note(user_id, note_id, **fields):
    conn = get_db()
    cursor = conn.cursor()
    set_clauses = []
    values = []
    for field, value in fields.items():
        if field in ('title', 'content', 'note_type', 'severity', 'linked_transaction_ids'):
            set_clauses.append(f"{field} = ?")
            values.append(value if field != 'linked_transaction_ids' else json.dumps(value or []))
    set_clauses.append("updated_at = CURRENT_TIMESTAMP")
    values.append(note_id)
    values.append(user_id)
    
    company_id = _get_active_company_id_shim()
    values.append(company_id)
    
    cursor.execute(f"UPDATE case_notes SET {', '.join(set_clauses)} WHERE id = ? AND user_id = ? AND company_id = ?", values)
    conn.commit()
    conn.close()


def delete_case_note(user_id, note_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM case_notes WHERE id = ? AND user_id = ? AND company_id = ?", (note_id, user_id, company_id))
    conn.commit()
    conn.close()


# --- Saved Filters ---

def get_saved_filters(user_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM saved_filters WHERE user_id = ? AND company_id = ? ORDER BY name", (user_id, company_id))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def add_saved_filter(user_id, name, filters):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO saved_filters (user_id, name, filters) VALUES (?, ?, ?)", (user_id, name, json.dumps(filters)))
    fid = cursor.lastrowid
    conn.commit()
    conn.close()
    return fid


def delete_saved_filter(user_id, filter_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM saved_filters WHERE id = ? AND user_id = ?", (filter_id, user_id))
    conn.commit()
    conn.close()


# --- Running Balance Per Account ---

def get_account_running_balance(user_id, account_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, trans_date, description, amount, category,
            SUM(amount) OVER (ORDER BY trans_date, id) as running_balance
        FROM transactions
        WHERE account_id = ? AND user_id = ?
        ORDER BY trans_date, id
    """, (account_id, user_id))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# --- Alerts ---

def get_alerts(user_id):
    conn = get_db()
    cursor = conn.cursor()
    alerts = []

    user_cnd = " AND user_id = ?"
    params = (user_id,)

    # Uncategorized transactions
    cursor.execute(f"SELECT COUNT(*) as cnt, COALESCE(SUM(ABS(amount)),0) as total FROM transactions WHERE category = 'Uncategorized'{user_cnd}", params)
    r = dict(cursor.fetchone())
    if r['cnt'] > 0:
        alerts.append({'type': 'uncategorized', 'severity': 'warning', 'count': r['cnt'],
            'title': f"{r['cnt']} uncategorized transactions", 'detail': f"${r['total']:,.2f} needs review",
            'action': 'transactions', 'filters': {'category': 'Uncategorized'}})

    # Flagged needing review
    cursor.execute(f"SELECT COUNT(*) as cnt FROM transactions WHERE is_flagged = 1 AND (user_notes IS NULL OR user_notes = ''){user_cnd}", params)
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'flagged_unreviewed', 'severity': 'danger', 'count': r['cnt'],
            'title': f"{r['cnt']} flagged transactions without notes",
            'detail': 'Flagged items should be reviewed and noted',
            'action': 'transactions', 'filters': {'is_flagged': '1'}})

    # Transactions with no cardholder
    cursor.execute(f"SELECT COUNT(*) as cnt FROM transactions WHERE (cardholder_name IS NULL OR cardholder_name = '') AND amount < 0{user_cnd}", params)
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'no_cardholder', 'severity': 'info', 'count': r['cnt'],
            'title': f"{r['cnt']} transactions without cardholder",
            'detail': 'Assign cardholders for better analysis',
            'action': 'transactions', 'filters': {}})

    # Not classified as personal or business
    cursor.execute(f"SELECT COUNT(*) as cnt FROM transactions WHERE is_personal = 0 AND is_business = 0 AND amount < 0{user_cnd}", params)
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'unclassified', 'severity': 'warning', 'count': r['cnt'],
            'title': f"{r['cnt']} not marked personal or business",
            'detail': 'Mark spending as personal or business for separation',
            'action': 'transactions', 'filters': {}})

    # Large single transactions
    cursor.execute(f"SELECT COUNT(*) as cnt FROM transactions WHERE ABS(amount) > 5000 AND (user_notes IS NULL OR user_notes = ''){user_cnd}", params)
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'large_unnoted', 'severity': 'info', 'count': r['cnt'],
            'title': f"{r['cnt']} large transactions without notes",
            'detail': 'Transactions over $5,000 should be documented',
            'action': 'transactions', 'filters': {'min_amount': '5000'}})

    conn.close()
    return alerts

# --- Saved Filters ---

def get_saved_filters(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, filters FROM saved_filters WHERE user_id = ? ORDER BY name ASC", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{'id': r['id'], 'name': r['name'], 'filters': json.loads(r['filters'])} for r in rows]

def add_saved_filter(user_id, name, filters_dict):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO saved_filters (user_id, name, filters) VALUES (?, ?, ?)",
        (user_id, name, json.dumps(filters_dict))
    )
    conn.commit()
    fid = cursor.lastrowid
    conn.close()
    return fid

def delete_saved_filter(user_id, filter_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM saved_filters WHERE user_id = ? AND id = ?", (user_id, filter_id))
    conn.commit()
    conn.close()

# --- Telemetry Logs ---

def log_drilldown(user_id, data):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO drilldown_logs (user_id, source_tab, widget_id, target, filters_applied, metadata)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        data.get('source_tab'),
        data.get('widget_id'),
        data.get('target'),
        data.get('filters_applied'),
        data.get('metadata')
    ))
    conn.commit()
    log_id = cursor.lastrowid
    conn.close()
    return log_id

def add_document_extraction(user_id, document_id, status='pending'):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO document_extractions (user_id, document_id, status)
        VALUES (?, ?, ?)
    """, (user_id, document_id, status))
    conn.commit()
    ext_id = cursor.lastrowid
    conn.close()
    return ext_id

def update_document_extraction(user_id, ext_id, extraction_data=None, status=None, error_message=None):
    conn = get_db()
    cursor = conn.cursor()
    
    updates = []
    params = []
    
    if extraction_data is not None:
        updates.append("extraction_data = ?")
        params.append(extraction_data if isinstance(extraction_data, str) else json.dumps(extraction_data))
        
    if status is not None:
        updates.append("status = ?")
        params.append(status)
        
    if error_message is not None:
        updates.append("error_message = ?")
        params.append(error_message)
        
    if not updates:
        return
        
    updates.append("updated_at = CURRENT_TIMESTAMP")
    params.append(ext_id)
    params.append(user_id)
    
    query = f"UPDATE document_extractions SET {', '.join(updates)} WHERE id = ? AND user_id = ?"
    cursor.execute(query, tuple(params))
    conn.commit()
    conn.close()

def get_document_extraction(user_id, document_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM document_extractions 
        WHERE document_id = ? AND user_id = ?
        ORDER BY created_at DESC LIMIT 1
    """, (document_id, user_id))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_taxonomy_config(user_id, company_id=None):
    """Fetches the taxonomy configuration as a list of dicts."""
    if company_id is None:
        company_id = _get_active_company_id_shim()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM taxonomy_config WHERE user_id = ? AND company_id = ? ORDER BY category_type, severity DESC", (user_id, company_id))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def add_taxonomy_config(user_id, name, description, category_type, severity, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO taxonomy_config (user_id, company_id, name, description, category_type, severity) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, company_id, name, description, category_type, severity)
        )
        _id = cursor.lastrowid
        conn.commit()
        return _id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def delete_taxonomy_config(user_id, tax_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM taxonomy_config WHERE id = ? AND user_id = ? AND company_id = ?", (tax_id, user_id, company_id))
    conn.commit()
    conn.close()

def add_document_categorization(user_id, document_id, extraction_id, categorization_data, provider, model, status="completed", error_message=None):
    """Persists an LLM-generated document categorization payload."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Auto-increment version dynamically per document
    cursor.execute("SELECT MAX(version) FROM document_categorizations WHERE document_id = ? AND user_id = ?", (document_id, user_id))
    result = cursor.fetchone()[0]
    next_version = 1 if result is None else result + 1

    cursor.execute("""
        INSERT INTO document_categorizations (
            user_id, document_id, extraction_id, categorization_data, 
            provider, model, version, status, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, document_id, extraction_id, 
        categorization_data if isinstance(categorization_data, str) else json.dumps(categorization_data),
        provider, model, next_version, status, error_message
    ))
    conn.commit()
    cat_id = cursor.lastrowid
    conn.close()
    return cat_id

def get_document_categorization(user_id, document_id):
    """Fetches the latest categorization for a given document."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM document_categorizations 
        WHERE document_id = ? AND user_id = ?
        ORDER BY created_at DESC, version DESC LIMIT 1
    """, (document_id, user_id))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


# --- Integrations ---

def get_integration(user_id, provider, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM integrations WHERE user_id = ? AND company_id = ? AND provider = ?", (user_id, company_id, provider))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_integrations(user_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM integrations WHERE user_id = ? AND company_id = ?", (user_id, company_id))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def upsert_integration(user_id, provider, status='Connected', scopes=None, access_token=None, refresh_token=None, expires_at=None, metadata=None, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
    conn = get_db()
    cursor = conn.cursor()
    
    # Store JSON if metadata or scopes are dicts/lists
    if isinstance(scopes, (dict, list)):
        scopes = json.dumps(scopes)
    if isinstance(metadata, (dict, list)):
        metadata = json.dumps(metadata)
        
    cursor.execute("""
        INSERT INTO integrations (
            user_id, company_id, provider, status, scopes, access_token, refresh_token,
            expires_at, metadata, connected_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT(company_id, provider) DO UPDATE SET
            status = excluded.status,
            scopes = excluded.scopes,
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            expires_at = excluded.expires_at,
            metadata = excluded.metadata,
            updated_at = CURRENT_TIMESTAMP
    """, (user_id, company_id, provider, status, scopes, access_token, refresh_token, expires_at, metadata))
    conn.commit()
    conn.close()

def delete_integration(user_id, provider, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM integrations WHERE user_id = ? AND company_id = ? AND provider = ?", (user_id, company_id, provider))
    conn.commit()
    conn.close()

def seed_taxonomy(user_id, passed_cursor=None, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
        
    if passed_cursor:
        cursor = passed_cursor
        conn = None
    else:
        conn = get_db()
        cursor = conn.cursor()
        
    cursor.execute("SELECT id FROM categories WHERE user_id = ? AND company_id = ? LIMIT 1", (user_id, company_id))
    if cursor.fetchone():
        if conn: conn.close()
        return

    default_categories = [
        ('Deposits', None, 'deposit', '#28a745', 'arrow-down'),
        ('Transfers Out', None, 'transfer', '#dc3545', 'arrow-right'),
        ('Transfers In', None, 'transfer', '#17a2b8', 'arrow-left'),
        ('Personal - Dining', 'Personal', 'personal', '#fd7e14', 'utensils'),
        ('Personal - Entertainment', 'Personal', 'personal', '#e83e8c', 'film'),
        ('Personal - Shopping', 'Personal', 'personal', '#6f42c1', 'shopping-cart'),
        ('Personal - Groceries', 'Personal', 'personal', '#20c997', 'shopping-basket'),
        ('Personal - Utilities', 'Personal', 'personal', '#6c757d', 'bolt'),
        ('Personal - Other', 'Personal', 'personal', '#fd7e14', 'tag'),
        ('Business - Supplies', 'Business', 'business', '#007bff', 'box'),
        ('Business - Services', 'Business', 'business', '#0056b3', 'briefcase'),
        ('Business - Inventory', 'Business', 'business', '#004085', 'warehouse'),
        ('Business - Equipment', 'Business', 'business', '#003366', 'tools'),
        ('Business - Payroll', 'Business', 'business', '#17a2b8', 'users'),
        ('Business - Other', 'Business', 'business', '#007bff', 'tag'),
        ('Venmo - Payment', None, 'transfer', '#3d95ce', 'mobile'),
        ('Venmo - Cashout', None, 'transfer', '#3d95ce', 'dollar-sign'),
        ('Fees - NSF/Overdraft', 'Fees', 'fee', '#dc3545', 'exclamation-triangle'),
        ('Fees - Late Payment', 'Fees', 'fee', '#dc3545', 'clock'),
        ('Fees - Service Charge', 'Fees', 'fee', '#ffc107', 'file-invoice'),
        ('Check Payment', None, 'other', '#795548', 'money-check'),
        ('Capital One Payment', None, 'transfer', '#dc3545', 'credit-card'),
        ('Wire Transfer', None, 'transfer', '#dc3545', 'exchange-alt'),
        ('Cash Advance', None, 'other', '#dc3545', 'hand-holding-usd'),
        ('Uncategorized', None, 'other', '#6c757d', 'question'),
    ]

    for cat in default_categories:
        cursor.execute(
            "INSERT INTO categories (user_id, company_id, name, parent_category, category_type, color, icon) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, company_id) + cat
        )

    default_rules = [
        # Transfers
        ('INTERNET TRANSFER TO%', 'Transfers Out', None, 0, 0, 1, 100),
        ('INTERNET TRANSFER FROM%', 'Transfers In', None, 0, 0, 1, 100),
        ('WIRE TRANSFER%', 'Wire Transfer', None, 0, 0, 1, 100),
        ('CAPITAL ONE%PMT%', 'Capital One Payment', None, 0, 0, 1, 90),
        ('CAPITAL ONE/MOBILE%', 'Capital One Payment', None, 0, 0, 1, 90),
        # Venmo
        ('VENMO%PAYMENT%', 'Venmo - Payment', None, 0, 0, 1, 80),
        ('VENMO%CASHOUT%', 'Venmo - Cashout', None, 0, 0, 1, 80),
        ('VENMO%RECOVERY%', 'Venmo - Payment', None, 0, 0, 1, 80),
        ('%VENMO *%', 'Venmo - Payment', None, 0, 0, 1, 75),
        # Fees
        ('NSF%FEE%', 'Fees - NSF/Overdraft', None, 0, 0, 0, 90),
        ('OVERDRAFT%', 'Fees - NSF/Overdraft', None, 0, 0, 0, 90),
        ('OD CHARGE%', 'Fees - NSF/Overdraft', None, 0, 0, 0, 90),
        ('PAST DUE FEE%', 'Fees - Late Payment', None, 0, 0, 0, 90),
        ('SERVICE CHARGE%', 'Fees - Service Charge', None, 0, 0, 0, 85),
        ('LATE%FEE%', 'Fees - Late Payment', None, 0, 0, 0, 85),
        # Checks
        ('CHECK #%', 'Check Payment', None, 0, 1, 0, 70),
        # Deposits
        ('DEPOSIT%', 'Deposits', None, 0, 0, 0, 95),
        # Personal - Dining
        ('%SUPERIOR GRILL%', 'Personal - Dining', None, 1, 0, 0, 60),
        ('%PAPPADEAUX%', 'Personal - Dining', None, 1, 0, 0, 60),
        ('%MOXIES GRILL%', 'Personal - Dining', None, 1, 0, 0, 60),
        ('%BULLDOG%', 'Personal - Dining', None, 1, 0, 0, 60),
        ('%GINOS%RESTAURANT%', 'Personal - Dining', None, 1, 0, 0, 60),
        ('%FOOD SERVICE%', 'Personal - Dining', None, 1, 0, 0, 50),
        ('%JEFF%S FOOD%', 'Personal - Dining', None, 1, 0, 0, 50),
        # Personal - Utilities
        ('%COX BATON ROUGE%', 'Personal - Utilities', None, 1, 0, 0, 60),
        # Business
        ('%TST* 601%CC%', 'Business - Inventory', None, 0, 1, 0, 60),
        ('%TST* 604%CC%', 'Business - Inventory', None, 0, 1, 0, 60),
        ('%TRI-CARE%', 'Business - Services', None, 0, 1, 0, 60),
        ('%HEBERTS BOUDIN%', 'Business - Inventory', None, 0, 1, 0, 60),
        ('%AMAZON%', 'Business - Supplies', None, 0, 1, 0, 40),
        ('%FTD%HEROMANS%', 'Business - Inventory', None, 0, 1, 0, 60),
        ('%CIRCLE K%', 'Business - Supplies', None, 0, 1, 0, 40),
    ]

    for rule in default_rules:
        cursor.execute(
            "INSERT INTO category_rules (user_id, company_id, pattern, category, subcategory, is_personal, is_business, is_transfer, priority) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, company_id) + rule
        )
            
    if conn:
        conn.commit()
        conn.close()

def delete_category(user_id, category_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM categories WHERE id = ? AND user_id = ? AND company_id = ?", (category_id, user_id, company_id))
    conn.commit()
    conn.close()

def delete_category_rule(user_id, rule_id, company_id=None):
    if company_id is None:
        company_id = _get_active_company_id_shim()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM category_rules WHERE id = ? AND user_id = ? AND company_id = ?", (rule_id, user_id, company_id))
    conn.commit()
    conn.close()

def reset_user_taxonomy(user_id, company_id=None):
    """Wipes the user's categories and rules, then reseeds the standard 25 names."""
    if company_id is None:
        company_id = _get_active_company_id_shim()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM categories WHERE user_id = ? AND company_id = ?", (user_id, company_id))
    cursor.execute("DELETE FROM category_rules WHERE user_id = ? AND company_id = ?", (user_id, company_id))
    conn.commit()
    conn.close()
    
    # Now call seed_taxonomy logic to inject the default setup
    seed_taxonomy(user_id, company_id=company_id)

# --- Internet Lookup Cache ---

def get_lookup_cache(lookup_key):
    """Retrieves an internet lookup cached result for a given merchant/key."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT raw_response FROM lookup_cache WHERE lookup_key = ?", (lookup_key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row['raw_response']
    return None

def set_lookup_cache(lookup_key, raw_response, source='wikipedia'):
    """Caches an internet lookup result."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO lookup_cache (lookup_key, raw_response, source, updated_at) 
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(lookup_key) DO UPDATE SET 
            raw_response = excluded.raw_response,
            source = excluded.source,
            updated_at = excluded.updated_at
    """, (lookup_key, raw_response, source))
    conn.commit()
    conn.close()

def add_merchant_context_rule(user_id: int, merchant_id: int, context_type: str, context_value: str, mapped_category_id: int, priority: int = 60) -> int:
    """
    Phase 11: Adds a context-specific rule for a merchant (e.g., categorizing by 'account_type').
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO merchant_context_rules 
        (user_id, merchant_id, context_type, context_value, mapped_category_id, priority) 
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, merchant_id, context_type, context_value) DO UPDATE SET
        mapped_category_id=excluded.mapped_category_id, priority=excluded.priority
    """, (user_id, merchant_id, context_type, str(context_value), mapped_category_id, priority))
    conn.commit()
    rule_id = cursor.lastrowid
    conn.close()
    return rule_id

def get_merchant_context_rules(user_id: int, merchant_id: int) -> list:
    """
    Retrieves all contextual classification rules for a specific merchant.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT mcr.*, c.name as category_name
        FROM merchant_context_rules mcr
        JOIN categories c ON mcr.mapped_category_id = c.id
        WHERE mcr.user_id = ? AND mcr.merchant_id = ?
        ORDER BY mcr.priority DESC
    """, (user_id, merchant_id))
    rules = [dict(r) for r in cursor.fetchall()]
    return rules

def get_advisor_company_state(company_id: int) -> dict:
    """Retrieve the current Advisor execution state for a company."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM advisor_company_state WHERE company_id = ?", (company_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return {
            "company_id": company_id,
            "status": "never_run",
            "needs_refresh": 1,
            "last_run_at": None,
            "last_success_at": None,
            "last_failure_at": None,
            "last_trigger_reason": None
        }
    return dict(row)

def update_advisor_company_state(company_id: int, status: str = None, needs_refresh: int = None, trigger_reason: str = None):
    """
    Creates or updates the Advisor execution state for a company.
    If needs_refresh is passed, it flags the company's advisor tab as stale.
    """
    conn = get_db()
    cursor = conn.cursor()
    
    # Ensure a row exists first
    cursor.execute("SELECT 1 FROM advisor_company_state WHERE company_id = ?", (company_id,))
    if not cursor.fetchone():
        cursor.execute("INSERT INTO advisor_company_state (company_id) VALUES (?)", (company_id,))
        
    updates = ["updated_at = CURRENT_TIMESTAMP"]
    params = []
    
    if status is not None:
        if status == 'queued':
            updates.append("status = CASE WHEN status = 'running' THEN 'running' ELSE 'queued' END")
        else:
            updates.append("status = ?")
            params.append(status)
            
        if status == 'running':
            updates.append("last_run_at = CURRENT_TIMESTAMP")
        elif status == 'completed':
            updates.append("last_success_at = CURRENT_TIMESTAMP")
        elif status == 'failed':
            updates.append("last_failure_at = CURRENT_TIMESTAMP")
            
    if needs_refresh is not None:
        updates.append("needs_refresh = ?")
        params.append(needs_refresh)
        
    if trigger_reason is not None:
        updates.append("last_trigger_reason = ?")
        params.append(trigger_reason)
        
    params.append(company_id)
    
    query = f"UPDATE advisor_company_state SET {', '.join(updates)} WHERE company_id = ?"
    cursor.execute(query, params)
    conn.commit()
    conn.close()

def insert_advisor_findings(company_id: int, run_id: str, findings: list):
    """
    Deterministically bulk-upserts canonical Findings into the database.
    findings should be a list of dicts matching the advisor_findings schema.
    """
    if not findings:
        return
        
    conn = get_db()
    cursor = conn.cursor()
    
    query = """
    INSERT INTO advisor_findings (
        finding_id, company_id, analysis_run_id, category, severity, confidence,
        title, executive_summary, plain_english_explanation, forensic_rationale,
        financial_impact, recommended_actions, evidence_graph, drilldown_queries
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(finding_id) DO UPDATE SET
        analysis_run_id = excluded.analysis_run_id,
        severity = excluded.severity,
        confidence = excluded.confidence,
        executive_summary = excluded.executive_summary,
        plain_english_explanation = excluded.plain_english_explanation,
        forensic_rationale = excluded.forensic_rationale,
        financial_impact = excluded.financial_impact,
        recommended_actions = excluded.recommended_actions,
        evidence_graph = excluded.evidence_graph,
        drilldown_queries = excluded.drilldown_queries,
        created_at = CURRENT_TIMESTAMP
    """
    
    rows = []
    import json
    for f in findings:
        rows.append((
            f['finding_id'],
            company_id,
            run_id,
            f['category'],
            f.get('severity', 'info'),
            f.get('confidence', 0),
            f['title'],
            f.get('executive_summary', ''),
            f.get('plain_english_explanation', ''),
            f.get('forensic_rationale', ''),
            json.dumps(f.get('financial_impact', {})),
            json.dumps(f.get('recommended_actions', [])),
            json.dumps(f.get('evidence_graph', [])),
            json.dumps(f.get('drilldown_queries', {}))
        ))
        
    cursor.executemany(query, rows)
    conn.commit()
    conn.close()

def get_advisor_findings(company_id: int, category: str = None) -> list:
    """
    Fetches persisted AI Advisor findings for a specific company, ensuring strict isolation.
    """
    conn = get_db()
    cursor = conn.cursor()
    
    if category:
        cursor.execute("SELECT * FROM advisor_findings WHERE company_id = ? AND category = ? ORDER BY confidence DESC, created_at DESC", (company_id, category))
    else:
        cursor.execute("SELECT * FROM advisor_findings WHERE company_id = ? ORDER BY category, confidence DESC", (company_id,))
        
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    import json
    for row in rows:
        d = dict(row)
        for key in ['financial_impact', 'recommended_actions', 'evidence_graph', 'drilldown_queries']:
            if d.get(key) and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except Exception:
                    pass
        results.append(d)
        
    return results

def get_advisor_finding_by_id(company_id: int, finding_id: str) -> dict:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM advisor_findings WHERE company_id = ? AND finding_id = ?", (company_id, finding_id))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
        
    import json
    d = dict(row)
    for key in ['financial_impact', 'recommended_actions', 'evidence_graph', 'drilldown_queries']:
        if d.get(key) and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except Exception:
                pass
    return d

def sync_remediation_tasks(company_id: int, findings: list):
    """
    Creates unassigned, open remediation tasks for new findings' recommended actions.
    Existing tasks (by finding_id and description) are ignored via INSERT OR IGNORE.
    """
    conn = get_db()
    cursor = conn.cursor()
    
    tasks_to_insert = []
    for f in findings:
        actions = f.get('recommended_actions', [])
        for act in actions:
            tasks_to_insert.append((
                company_id,
                f['finding_id'],
                f.get('analysis_run_id', 'unknown'),
                act
            ))
            
    if tasks_to_insert:
        cursor.executemany('''
            INSERT OR IGNORE INTO advisor_remediation_tasks 
            (company_id, finding_id, analysis_run_id, task_description) 
            VALUES (?, ?, ?, ?)
        ''', tasks_to_insert)
        conn.commit()
    conn.close()

def get_remediation_tasks(company_id: int) -> list:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT t.*, f.title as finding_title, f.category as finding_category, f.severity as finding_severity
        FROM advisor_remediation_tasks t
        LEFT JOIN advisor_findings f ON t.finding_id = f.finding_id
        WHERE t.company_id = ?
        ORDER BY t.created_at DESC
    ''', (company_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def update_remediation_task(company_id: int, task_id: int, updates: dict):
    conn = get_db()
    cursor = conn.cursor()
    
    allowed_fields = ['status', 'owner', 'due_date', 'notes']
    set_clauses = []
    params = []
    
    for k, v in updates.items():
        if k in allowed_fields:
            set_clauses.append(f"{k} = ?")
            params.append(v)
            
    if set_clauses:
        set_clauses.append("updated_at = CURRENT_TIMESTAMP")
        params.extend([company_id, task_id])
        cursor.execute(f"UPDATE advisor_remediation_tasks SET {', '.join(set_clauses)} WHERE company_id = ? AND id = ?", params)
        conn.commit()
    conn.close()
    
def get_advisor_re_audit_status(company_id: int) -> dict:
    """
    Compares the current findings vs historical findings to determine remediation progress.
    """
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT analysis_run_id, created_at FROM advisor_findings WHERE company_id = ? ORDER BY created_at DESC LIMIT 1", (company_id,))
    latest = cursor.fetchone()
    if not latest:
        conn.close()
        return {"status": "no_runs", "message": "No audits have been run for this company."}
        
    latest_run_id = latest['analysis_run_id']
    
    cursor.execute("SELECT DISTINCT analysis_run_id, MAX(created_at) as run_time FROM advisor_findings WHERE company_id = ? GROUP BY analysis_run_id ORDER BY run_time DESC", (company_id,))
    runs = cursor.fetchall()
    
    if len(runs) <= 1:
        conn.close()
        return {"status": "single_run", "message": "Only one audit has been run. Re-run after applying fixes to see changes.", "current_run_id": latest_run_id}
        
    previous_run_id = runs[1]['analysis_run_id']
    
    cursor.execute("SELECT count(*) as cnt FROM advisor_findings WHERE company_id = ? AND analysis_run_id = ?", (company_id, latest_run_id))
    current_count = cursor.fetchone()['cnt']
    
    cursor.execute("SELECT count(*) as cnt FROM advisor_findings WHERE company_id = ? AND analysis_run_id = ?", (company_id, previous_run_id))
    previous_count = cursor.fetchone()['cnt']
    
    cursor.execute('''
        SELECT finding_id FROM advisor_findings 
        WHERE company_id = ? AND analysis_run_id = ? 
        AND finding_id NOT IN (
            SELECT finding_id FROM advisor_findings WHERE company_id = ? AND analysis_run_id = ?
        )
    ''', (company_id, previous_run_id, company_id, latest_run_id))
    
    resolved_ids = [r['finding_id'] for r in cursor.fetchall()]
    
    if resolved_ids:
        placeholders = ','.join(['?']*len(resolved_ids))
        cursor.execute(f"UPDATE advisor_remediation_tasks SET status = 'done', notes = 'Resolved by Re-Audit' WHERE company_id = ? AND finding_id IN ({placeholders}) AND status != 'done'", [company_id] + resolved_ids)
        conn.commit()
    
    conn.close()
    
    return {
        "status": "compared",
        "current_run_id": latest_run_id,
        "previous_run_id": previous_run_id,
        "current_issues": current_count,
        "previous_issues": previous_count,
        "net_improvement": previous_count - current_count,
        "resolved_finding_ids": resolved_ids
    }
