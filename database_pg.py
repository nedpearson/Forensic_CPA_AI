"""
Database layer for Forensic Auditor.
Uses SQLite for local, portable storage of all transaction data.
"""
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import os
import json
from datetime import datetime

if os.environ.get('TESTING') == 'true':
    DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'test_audit.db')
else:
    DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'data', 'forensic_audit.db'))



# PostgreSQL connection pool
_pg_pool = None

def get_db():
    global _pg_pool
    if _pg_pool is None:
        db_url = os.environ.get('DATABASE_URL')
        if not db_url:
            raise ValueError("DATABASE_URL is not set for PostgreSQL.")
        _pg_pool = psycopg2.pool.SimpleConnectionPool(1, 10, db_url)
    
    conn = _pg_pool.getconn()
    conn.autocommit = False # keep transaction behavior similar to sqlite
    return conn

def close_db(conn):
    global _pg_pool
    if _pg_pool and conn:
        _pg_pool.putconn(conn)


def init_db():
    """Initialize all database tables."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS fcpa_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_demo INTEGER DEFAULT 0,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS fcpa_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            account_name TEXT NOT NULL,
            account_number TEXT,
            account_type TEXT NOT NULL,  -- 'bank', 'credit_card', 'venmo'
            institution TEXT,
            cardholder_name TEXT,
            card_last_four TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS fcpa_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            filename TEXT NOT NULL,
            original_path TEXT,
            file_type TEXT NOT NULL,  -- 'pdf', 'xlsx', 'docx', 'csv'
            doc_category TEXT,  -- 'bank_statement', 'credit_card', 'venmo', 'proof', 'other'
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            statement_start_date TEXT,
            statement_end_date TEXT,
            account_id INTEGER,
            notes TEXT,
            FOREIGN KEY (account_id) REFERENCES fcpa_accounts(id)
        );

        CREATE TABLE IF NOT EXISTS fcpa_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES fcpa_documents(id),
            FOREIGN KEY (account_id) REFERENCES fcpa_accounts(id)
        );

        CREATE TABLE IF NOT EXISTS fcpa_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            name TEXT NOT NULL,
            parent_category TEXT,
            category_type TEXT,  -- 'personal', 'business', 'transfer', 'deposit', 'fee', 'other'
            color TEXT DEFAULT '#6c757d',
            icon TEXT
        );

        CREATE TABLE IF NOT EXISTS fcpa_category_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            pattern TEXT NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT,
            is_personal INTEGER DEFAULT 0,
            is_business INTEGER DEFAULT 0,
            is_transfer INTEGER DEFAULT 0,
            priority INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS fcpa_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            transaction_id INTEGER,
            action TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            field_changed TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (transaction_id) REFERENCES fcpa_transactions(id)
        );

        CREATE TABLE IF NOT EXISTS fcpa_proof_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            transaction_id INTEGER NOT NULL,
            document_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (transaction_id) REFERENCES fcpa_transactions(id) ON DELETE CASCADE,
            FOREIGN KEY (document_id) REFERENCES fcpa_documents(id) ON DELETE CASCADE,
            UNIQUE(transaction_id, document_id)
        );

        CREATE TABLE IF NOT EXISTS fcpa_case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            note_type TEXT DEFAULT 'general',  -- 'general', 'finding', 'evidence', 'timeline'
            severity TEXT DEFAULT 'info',  -- 'info', 'warning', 'danger'
            linked_transaction_ids TEXT,  -- JSON array of transaction IDs
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS fcpa_drilldown_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            source_tab TEXT NOT NULL,
            widget_id TEXT NOT NULL,
            target TEXT NOT NULL,
            filters_applied TEXT NOT NULL,
            metadata TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS fcpa_saved_filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            name TEXT NOT NULL,
            filters TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS fcpa_document_extractions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            document_id INTEGER NOT NULL,
            extraction_data TEXT,  -- JSON string of the extracted fields/layout
            status TEXT DEFAULT 'pending',  -- 'pending', 'completed', 'failed'
            error_message TEXT,
            version INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES fcpa_documents(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS fcpa_taxonomy_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            category_type TEXT NOT NULL, -- 'risk', 'entity', 'topic'
            severity TEXT DEFAULT 'low',  -- for risks
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS fcpa_document_categorizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            document_id INTEGER NOT NULL,
            extraction_id INTEGER,
            categorization_data TEXT, -- JSON containing RiskCategories, entities, topics, summary
            provider TEXT,
            model TEXT,
            version INTEGER DEFAULT 1,
            status TEXT DEFAULT 'completed',
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES fcpa_documents(id) ON DELETE CASCADE,
            FOREIGN KEY (extraction_id) REFERENCES fcpa_document_extractions(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS fcpa_saved_filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
            name TEXT NOT NULL,
            filters TEXT NOT NULL,  -- JSON object of filter params
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS fcpa_integrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES fcpa_users(id),
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
            UNIQUE(user_id, provider)
        );

        CREATE INDEX IF NOT EXISTS idx_trans_date ON fcpa_transactions(trans_date);
        CREATE INDEX IF NOT EXISTS idx_trans_category ON fcpa_transactions(category);
        CREATE INDEX IF NOT EXISTS idx_trans_cardholder ON fcpa_transactions(cardholder_name);
        CREATE INDEX IF NOT EXISTS idx_trans_type ON fcpa_transactions(trans_type);
        CREATE INDEX IF NOT EXISTS idx_trans_flagged ON fcpa_transactions(is_flagged);
        CREATE INDEX IF NOT EXISTS idx_trans_account ON fcpa_transactions(account_id);
        CREATE INDEX IF NOT EXISTS idx_proof_links_trans ON fcpa_proof_links(transaction_id);
        CREATE INDEX IF NOT EXISTS idx_proof_links_doc ON fcpa_proof_links(document_id);
        CREATE INDEX IF NOT EXISTS idx_trans_personal_date ON fcpa_transactions(is_personal, trans_date);
        CREATE INDEX IF NOT EXISTS idx_trans_business_date ON fcpa_transactions(is_business, trans_date);
        CREATE INDEX IF NOT EXISTS idx_trans_flagged_date ON fcpa_transactions(is_flagged, trans_date);
        CREATE INDEX IF NOT EXISTS idx_trans_amount ON fcpa_transactions(amount);
        
        -- High performance indices for Analytics Drilldowns
        CREATE INDEX IF NOT EXISTS idx_trans_composite_view ON fcpa_transactions(is_personal, is_business, trans_date);
        CREATE INDEX IF NOT EXISTS idx_trans_amount_date ON fcpa_transactions(amount, trans_date);
        CREATE INDEX IF NOT EXISTS idx_drilldown_logs_target ON fcpa_drilldown_logs(target, timestamp);
    """)

    # Migration for user_id on existing databases
    cursor.execute("SELECT id FROM fcpa_users WHERE email='root@system.local'")
    root_user = cursor.fetchone()
    if not root_user:
        import werkzeug.security
        hashed = werkzeug.security.generate_password_hash("root")
        cursor.execute("INSERT INTO fcpa_users (email, password_hash) VALUES (%s, %s) RETURNING id", ("root@system.local", hashed))
        root_id = cursor.fetchone()['id']
    else:
        root_id = root_user['id']

    tables_to_migrate = [
        'fcpa_accounts', 'fcpa_documents', 'fcpa_transactions', 'fcpa_categories', 
        'fcpa_category_rules', 'fcpa_saved_filters', 'fcpa_document_extractions', 
        'fcpa_document_categorizations', 'fcpa_audit_log', 'fcpa_case_notes', 
        'fcpa_drilldown_logs', 'fcpa_taxonomy_config', 'fcpa_proof_links', 'fcpa_integrations'
    ]
    for table in tables_to_migrate:
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [row['name'] for row in cursor.fetchall()]
        if 'user_id' not in columns:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER REFERENCES fcpa_users(id)")
            cursor.execute(f"UPDATE {table} SET user_id = %s", (root_id,))

    # Migrate fcpa_users table to add role
    cursor.execute("PRAGMA table_info(fcpa_users)")
    user_columns = [row['name'] for row in cursor.fetchall()]
    if 'role' not in user_columns:
        cursor.execute("ALTER TABLE fcpa_users ADD COLUMN role TEXT DEFAULT 'user'")

    # Insert default fcpa_categories only for root_id to bootstrap
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
        ('Business - Payroll', 'Business', 'business', '#17a2b8', 'fcpa_users'),
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
            "SELECT id FROM fcpa_categories WHERE name = %s AND user_id = %s", (cat[0], root_id)
        )
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO fcpa_categories (user_id, name, parent_category, category_type, color, icon) VALUES (%s, %s, %s, %s, %s, %s)",
                (root_id,) + cat
            )

    # Insert default categorization rules
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
            "SELECT id FROM fcpa_category_rules WHERE pattern = %s AND user_id = %s", (rule[0], root_id)
        )
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO fcpa_category_rules (user_id, pattern, category, subcategory, is_personal, is_business, is_transfer, priority) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (root_id,) + rule
            )

    conn.commit()
    close_db(conn)

    # Bootstrap Super Admin from environment
    if os.environ.get('SUPER_ADMIN_BOOTSTRAP', 'false').lower() == 'true':
        admin_email = os.environ.get('SUPER_ADMIN_EMAIL')
        admin_pass = os.environ.get('SUPER_ADMIN_PASSWORD')
        if admin_email and admin_pass:
            import werkzeug.security
            user_record = get_user_by_email(admin_email)
            if not user_record:
                _id = create_user(admin_email, admin_pass, role='SUPER_ADMIN')
                if _id:
                    print(f"Super admin verified: {admin_email} created.")
            elif user_record.get('role') != 'SUPER_ADMIN':
                conn_admin = get_db()
                conn_admin.execute("UPDATE fcpa_users SET role = 'SUPER_ADMIN', password_hash = %s WHERE email = %s", 
                                   (werkzeug.security.generate_password_hash(admin_pass), admin_email))
                conn_admin.commit()
                conn_admin.close()
                print(f"Super admin verified: {admin_email} updated to SUPER_ADMIN.")
            else:
                print(f"Super admin verified: {admin_email} already active.")

# --- Identity / Auth Operations ---

def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_users WHERE email = %s", (email,))
    user = cursor.fetchone()
    close_db(conn)
    return dict(user) if user else None

def get_user_by_id(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    close_db(conn)
    return dict(user) if user else None

def create_user(email, password, role='USER'):
    import werkzeug.security
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extras import RealDictCursor
    hashed = werkzeug.security.generate_password_hash(password)
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute("INSERT INTO fcpa_users (email, password_hash, role) VALUES (%s, %s, %s) RETURNING id", (email, hashed, role))
        user_id = cursor.fetchone()['id']
        conn.commit()
        return user_id
    except psycopg2.IntegrityError as e:
        print(f"IntegrityError in create_user: {e}")
        return None
    except Exception as e:
        print(f"Error creating user: {e}")
        return None
    finally:
        close_db(conn)


def create_demo_user(wipe_data=False):
    """Guarantee a clean demo user exists, optionally wiping existing data to keep seeding idempotent."""
    import werkzeug.security
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    email = "demo@forensiccpa.ai"
    password = "demo_password_not_used"
    hashed = werkzeug.security.generate_password_hash(password)
    
    try:
        # Check if exists
        cursor.execute("SELECT id FROM fcpa_users WHERE email = %s", (email,))
        user_row = cursor.fetchone()
        
        if user_row:
            user_id = user_row['id']
            # Wipe existing tenant data for idempotent seeded demo runs
            if wipe_data:
                tables = [
                    'fcpa_audit_log', 'fcpa_proof_links', 'fcpa_document_categorizations', 
                    'fcpa_document_extractions', 'fcpa_drilldown_logs', 'fcpa_case_notes', 
                    'fcpa_saved_filters', 'fcpa_category_rules', 'fcpa_categories', 'fcpa_taxonomy_config',
                    'fcpa_transactions', 'fcpa_documents', 'fcpa_accounts'
                ]
                for t in tables:
                    cursor.execute(f"DELETE FROM {t} WHERE user_id = %s", (user_id,))
                
            # Ensure is_demo is flipped just in case
            cursor.execute("UPDATE fcpa_users SET is_demo = 1, password_hash = %s WHERE id = %s", (hashed, user_id))
        else:
            # Create new
            cursor.execute(
                "INSERT INTO fcpa_users (email, password_hash, is_demo) VALUES (%s, %s, 1) RETURNING id", 
                (email, hashed)
            )
            user_id = cursor.fetchone()['id']
            
        conn.commit()
        return user_id
    except Exception as e:
        print(f"Error initializing demo user: {e}")
        return None


# --- Data Management ---

def clear_all_data(user_id):
    """Delete all financial data while keeping fcpa_categories and rules."""
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.executescript(f"""
        DELETE FROM fcpa_proof_links WHERE user_id = {user_id};
        DELETE FROM fcpa_audit_log WHERE user_id = {user_id};
        DELETE FROM fcpa_transactions WHERE user_id = {user_id};
        DELETE FROM fcpa_documents WHERE user_id = {user_id};
        DELETE FROM fcpa_accounts WHERE user_id = {user_id};
        DELETE FROM fcpa_case_notes WHERE user_id = {user_id};
        DELETE FROM fcpa_saved_filters WHERE user_id = {user_id};
    """)
    conn.commit()
    close_db(conn)


# --- CRUD Operations ---

def add_account(user_id, account_name, account_number, account_type, institution, cardholder_name=None, card_last_four=None, notes=None):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "INSERT INTO fcpa_accounts (user_id, account_name, account_number, account_type, institution, cardholder_name, card_last_four, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (user_id, account_name, account_number, account_type, institution, cardholder_name, card_last_four, notes)
    )
    account_id = cursor.fetchone()['id']
    conn.commit()
    close_db(conn)
    return account_id


def get_or_create_account(user_id, account_name, account_number, account_type, institution, cardholder_name=None, card_last_four=None):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "SELECT id FROM fcpa_accounts WHERE user_id = %s AND account_number = %s AND account_type = %s AND (cardholder_name = %s OR cardholder_name IS NULL)",
        (user_id, account_number, account_type, cardholder_name)
    )
    row = cursor.fetchone()
    if row:
        close_db(conn)
        return row['id']
    close_db(conn)
    return add_account(user_id, account_name, account_number, account_type, institution, cardholder_name, card_last_four)


def add_document(user_id, filename, original_path, file_type, doc_category, account_id=None, statement_start=None, statement_end=None, notes=None):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "INSERT INTO fcpa_documents (user_id, filename, original_path, file_type, doc_category, account_id, statement_start_date, statement_end_date, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (user_id, filename, original_path, file_type, doc_category, account_id, statement_start, statement_end, notes)
    )
    doc_id = cursor.fetchone()['id']
    conn.commit()
    close_db(conn)
    return doc_id


def find_duplicate_transactions(user_id, fcpa_transactions):
    """Check a list of parsed fcpa_transactions against existing DB fcpa_transactions.
    Returns list of (index, existing_transaction) tuples for duplicates."""
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    duplicates = []
    for i, t in enumerate(fcpa_transactions):
        cursor.execute("""
            SELECT id, trans_date, description, amount FROM fcpa_transactions
            WHERE user_id = %s AND trans_date = %s AND ABS(amount - %s) < 0.01
            AND UPPER(description) = UPPER(%s)
        """, (user_id, t.get('trans_date', ''), t.get('amount', 0), t.get('description', '')))
        existing = cursor.fetchone()
        if existing:
            duplicates.append({'index': i, 'existing': dict(existing)})
    close_db(conn)
    return duplicates


def add_transaction(user_id, doc_id, account_id, trans_date, post_date, description, amount, trans_type, category='uncategorized', **kwargs):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        INSERT INTO fcpa_transactions (user_id, document_id, account_id, trans_date, post_date, description, amount, trans_type, category,
            subcategory, cardholder_name, card_last_four, payment_method, check_number,
            is_transfer, transfer_to_account, transfer_from_account,
            is_personal, is_business, is_flagged, flag_reason, auto_categorized, manually_edited)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
    """, (
        user_id, doc_id, account_id, trans_date, post_date, description, amount, trans_type, category,
        kwargs.get('subcategory'), kwargs.get('cardholder_name'), kwargs.get('card_last_four'),
        kwargs.get('payment_method'), kwargs.get('check_number'),
        kwargs.get('is_transfer', 0), kwargs.get('transfer_to_account'), kwargs.get('transfer_from_account'),
        kwargs.get('is_personal', 0), kwargs.get('is_business', 0),
        kwargs.get('is_flagged', 0), kwargs.get('flag_reason'),
        kwargs.get('auto_categorized', 1), kwargs.get('manually_edited', 0)
    ))
    trans_id = cursor.fetchone()['id']
    conn.commit()
    close_db(conn)
    return trans_id


def update_transaction(user_id, trans_id, **fields):
    """Update a transaction and log the changes."""
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    # Get current values for audit log
    cursor.execute("SELECT * FROM fcpa_transactions WHERE id = %s AND user_id = %s", (trans_id, user_id))
    old = dict(cursor.fetchone() or {})
    if not old:
        close_db(conn)
        return

    set_clauses = []
    values = []
    for field, value in fields.items():
        set_clauses.append(f"{field} = %s")
        values.append(value)
        # Log the change
        if str(old.get(field)) != str(value):
            cursor.execute(
                "INSERT INTO fcpa_audit_log (user_id, transaction_id, action, old_value, new_value, field_changed) VALUES (%s, %s, 'update', %s, %s, %s)",
                (user_id, trans_id, str(old.get(field)), str(value), field)
            )

    set_clauses.append("updated_at = %s")
    values.append(datetime.now().isoformat())
    set_clauses.append("manually_edited = 1")
    
    values.append(trans_id)
    values.append(user_id)

    cursor.execute(f"UPDATE fcpa_transactions SET {', '.join(set_clauses)} WHERE id = %s AND user_id = %s", values)
    conn.commit()
    close_db(conn)


def delete_transaction(user_id, trans_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_transactions WHERE id = %s AND user_id = %s", (trans_id, user_id))
    old = cursor.fetchone()
    if old:
        cursor.execute(
            "INSERT INTO fcpa_audit_log (user_id, transaction_id, action, old_value, field_changed) VALUES (%s, %s, 'delete', %s, 'all')",
            (user_id, trans_id, str(dict(old)))
        )
    cursor.execute("DELETE FROM fcpa_transactions WHERE id = %s AND user_id = %s", (trans_id, user_id))
    conn.commit()
    close_db(conn)


def get_transactions(user_id, filters=None):
    """Get fcpa_transactions with optional filters."""
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    query = """
        SELECT t.*, d.filename as doc_filename, a.account_name, a.institution
        FROM fcpa_transactions t
        LEFT JOIN fcpa_documents d ON t.document_id = d.id
        LEFT JOIN fcpa_accounts a ON t.account_id = a.id
        WHERE t.user_id = %s
    """
    params = [user_id]


    if filters:
        if filters.get('category'):
            query += " AND t.category = %s"
            params.append(filters['category'])
        if filters.get('cardholder'):
            query += " AND t.cardholder_name LIKE %s"
            params.append(f"%{filters['cardholder']}%")
        if filters.get('trans_type'):
            query += " AND t.trans_type = %s"
            params.append(filters['trans_type'])
        if filters.get('date_from'):
            query += " AND t.trans_date >= %s"
            params.append(filters['date_from'])
        if filters.get('date_to'):
            query += " AND t.trans_date <= %s"
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
            query += " AND t.description LIKE %s"
            params.append(f"%{filters['search']}%")
        if filters.get('account_id'):
            query += " AND t.account_id = %s"
            params.append(filters['account_id'])
        if filters.get('min_amount'):
            query += " AND ABS(t.amount) >= %s"
            params.append(float(filters['min_amount']))
        if filters.get('max_amount'):
            query += " AND ABS(t.amount) <= %s"
            params.append(float(filters['max_amount']))
        if filters.get('view_mode') == 'personal':
            query += " AND t.is_personal = 1"
        elif filters.get('view_mode') == 'business':
            query += " AND t.is_business = 1"

    query += " ORDER BY t.trans_date DESC, t.id DESC"

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    close_db(conn)
    return rows


def get_categories(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_categories WHERE user_id = %s ORDER BY name", (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    close_db(conn)
    return rows


def get_accounts(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_accounts WHERE user_id = %s ORDER BY account_name", (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    close_db(conn)
    return rows


def get_documents(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT d.*, a.account_name FROM fcpa_documents d LEFT JOIN fcpa_accounts a ON d.account_id = a.id WHERE d.user_id = %s ORDER BY d.upload_date DESC", (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    close_db(conn)
    return rows


def build_filter_clause(user_id, filters=None, table_alias=''):
    """Build a SQL WHERE clause and parameter list from a filters dictionary."""
    prefix = f"{table_alias}." if table_alias else ""
    where = f"WHERE {prefix}user_id = %s"
    params = [user_id]
    
    if not filters:
        return where, params

    if filters.get('date_from'):
        where += f" AND {prefix}trans_date >= %s"
        params.append(filters['date_from'])
    if filters.get('date_to'):
        where += f" AND {prefix}trans_date <= %s"
        params.append(filters['date_to'])
    if filters.get('cardholder'):
        where += f" AND {prefix}cardholder_name LIKE %s"
        params.append(f"%{filters['cardholder']}%")
    if filters.get('account_id'):
        where += f" AND {prefix}account_id = %s"
        params.append(filters['account_id'])
    if filters.get('category'):
        where += f" AND {prefix}category = %s"
        params.append(filters['category'])
    if filters.get('trans_type'):
        where += f" AND {prefix}trans_type = %s"
        params.append(filters['trans_type'])
    if filters.get('payment_method'):
        where += f" AND {prefix}payment_method = %s"
        params.append(filters['payment_method'])
    if str(filters.get('is_flagged')) == '1':
        where += f" AND {prefix}is_flagged = 1"
    if str(filters.get('is_transfer')) == '1':
        where += f" AND {prefix}is_transfer = 1"
    if filters.get('search'):
        where += f" AND {prefix}description LIKE %s"
        params.append(f"%{filters['search']}%")
    if filters.get('min_amount'):
        where += f" AND ABS({prefix}amount) >= %s"
        params.append(float(filters['min_amount']))
    if filters.get('max_amount'):
        where += f" AND ABS({prefix}amount) <= %s"
        params.append(float(filters['max_amount']))

    is_personal_str = str(filters.get('is_personal', ''))
    is_business_str = str(filters.get('is_business', ''))
    view_mode = filters.get('view_mode')
    
    if view_mode == 'personal' or is_personal_str == '1' or is_personal_str.lower() == 'true':
        where += f" AND {prefix}is_personal = 1"
    elif view_mode == 'business' or is_business_str == '1' or is_business_str.lower() == 'true':
        where += f" AND {prefix}is_business = 1"

    return where, params

def get_summary_stats(user_id, filters=None):
    """Get summary statistics for dashboard."""
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    where, params = build_filter_clause(user_id, filters)

    stats = {}

    # Total deposits
    cursor.execute(f"SELECT COALESCE(SUM(amount), 0) as total, COUNT(*) as cnt FROM fcpa_transactions {where} AND amount > 0", params)
    row = cursor.fetchone()
    stats['total_deposits'] = row['total']
    stats['deposit_count'] = row['cnt']

    # Total withdrawals
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt FROM fcpa_transactions {where} AND amount < 0", params)
    row = cursor.fetchone()
    stats['total_withdrawals'] = row['total']
    stats['withdrawal_count'] = row['cnt']

    # Transfers out
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt FROM fcpa_transactions {where} AND is_transfer = 1 AND amount < 0", params)
    row = cursor.fetchone()
    stats['transfers_out'] = row['total']
    stats['transfer_out_count'] = row['cnt']

    # Personal spending
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt FROM fcpa_transactions {where} AND is_personal = 1", params)
    row = cursor.fetchone()
    stats['personal_total'] = row['total']
    stats['personal_count'] = row['cnt']

    # Business spending
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt FROM fcpa_transactions {where} AND is_business = 1", params)
    row = cursor.fetchone()
    stats['business_total'] = row['total']
    stats['business_count'] = row['cnt']

    # Fees
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt FROM fcpa_transactions {where} AND category LIKE 'Fees%'", params)
    row = cursor.fetchone()
    stats['fees_total'] = row['total']
    stats['fees_count'] = row['cnt']

    # Flagged
    cursor.execute(f"SELECT COUNT(*) as cnt FROM fcpa_transactions {where} AND is_flagged = 1", params)
    stats['flagged_count'] = cursor.fetchone()['cnt']

    # By cardholder
    cursor.execute(f"""
        SELECT cardholder_name,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total_spent,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as total_received,
            COUNT(*) as cnt
        FROM fcpa_transactions {where} AND cardholder_name IS NOT NULL AND cardholder_name != ''
        GROUP BY cardholder_name ORDER BY total_spent DESC
    """, params)
    stats['by_cardholder'] = [dict(r) for r in cursor.fetchall()]

    # By category
    cursor.execute(f"""
        SELECT category,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as spent,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as received,
            COUNT(*) as cnt
        FROM fcpa_transactions {where}
        GROUP BY category ORDER BY spent DESC
    """, params)
    stats['by_category'] = [dict(r) for r in cursor.fetchall()]

    # Monthly trend
    cursor.execute(f"""
        SELECT substr(trans_date, 1, 7) as month,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as deposits,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as withdrawals,
            COALESCE(SUM(CASE WHEN is_transfer = 1 AND amount < 0 THEN ABS(amount) ELSE 0 END), 0) as transfers_out
        FROM fcpa_transactions {where}
        GROUP BY month ORDER BY month
    """, params)
    stats['monthly_trend'] = [dict(r) for r in cursor.fetchall()]

    close_db(conn)
    return stats


def add_category_rule(user_id, pattern, category, subcategory=None, is_personal=0, is_business=0, is_transfer=0, priority=50):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "INSERT INTO fcpa_category_rules (user_id, pattern, category, subcategory, is_personal, is_business, is_transfer, priority) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (user_id, pattern, category, subcategory, is_personal, is_business, is_transfer, priority)
    )
    conn.commit()
    close_db(conn)


def get_category_rules(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_category_rules WHERE user_id = %s ORDER BY priority DESC, pattern", (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    close_db(conn)
    return rows


# --- Proof Document Links ---

def link_proof(user_id, transaction_id, document_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "INSERT OR IGNORE INTO fcpa_proof_links (user_id, transaction_id, document_id) VALUES (%s, %s, %s)",
        (user_id, transaction_id, document_id)
    )
    conn.commit()
    close_db(conn)


def unlink_proof(user_id, transaction_id, document_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "DELETE FROM fcpa_proof_links WHERE transaction_id = %s AND document_id = %s AND user_id = %s",
        (transaction_id, document_id, user_id)
    )
    conn.commit()
    close_db(conn)


def get_proofs_for_transaction(user_id, transaction_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT d.* FROM fcpa_documents d
        JOIN fcpa_proof_links pl ON pl.document_id = d.id
        WHERE pl.transaction_id = %s AND pl.user_id = %s
        ORDER BY d.upload_date DESC
    """, (transaction_id, user_id))
    rows = [dict(r) for r in cursor.fetchall()]
    close_db(conn)
    return rows


def get_transactions_for_proof(user_id, document_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT t.id, t.trans_date, t.description, t.amount
        FROM fcpa_transactions t
        JOIN fcpa_proof_links pl ON pl.transaction_id = t.id
        WHERE pl.document_id = %s AND pl.user_id = %s
        ORDER BY t.trans_date DESC
    """, (document_id, user_id))
    rows = [dict(r) for r in cursor.fetchall()]
    close_db(conn)
    return rows


# --- Case Notes ---

def get_case_notes(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_case_notes WHERE user_id = %s ORDER BY updated_at DESC", (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    close_db(conn)
    return rows


def add_case_note(user_id, title, content, note_type='general', severity='info', linked_transaction_ids=None):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("INSERT INTO fcpa_case_notes (user_id, title, content, note_type, severity, linked_transaction_ids) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id", (user_id, title, content, note_type, severity, json.dumps(linked_transaction_ids or [])))
    note_id = cursor.fetchone()['id']
    conn.commit()
    close_db(conn)
    return note_id


def update_case_note(user_id, note_id, **fields):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    set_clauses = []
    values = []
    for field, value in fields.items():
        if field in ('title', 'content', 'note_type', 'severity', 'linked_transaction_ids'):
            set_clauses.append(f"{field} = %s")
            values.append(value if field != 'linked_transaction_ids' else json.dumps(value or []))
    set_clauses.append("updated_at = CURRENT_TIMESTAMP")
    values.append(note_id)
    values.append(user_id)
    cursor.execute(f"UPDATE fcpa_case_notes SET {', '.join(set_clauses)} WHERE id = %s AND user_id = %s", values)
    conn.commit()
    close_db(conn)


def delete_case_note(user_id, note_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("DELETE FROM fcpa_case_notes WHERE id = %s AND user_id = %s", (note_id, user_id))
    conn.commit()
    close_db(conn)


# --- Saved Filters ---

def get_saved_filters(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_saved_filters WHERE user_id = %s ORDER BY name", (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    close_db(conn)
    return rows


def add_saved_filter(user_id, name, filters):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("INSERT INTO fcpa_saved_filters (user_id, name, filters) VALUES (%s, %s, %s) RETURNING id", (user_id, name, json.dumps(filters)))
    fid = cursor.fetchone()['id']
    conn.commit()
    close_db(conn)
    return fid


def delete_saved_filter(user_id, filter_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("DELETE FROM fcpa_saved_filters WHERE id = %s AND user_id = %s", (filter_id, user_id))
    conn.commit()
    close_db(conn)


# --- Running Balance Per Account ---

def get_account_running_balance(user_id, account_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT id, trans_date, description, amount, category,
            SUM(amount) OVER (ORDER BY trans_date, id) as running_balance
        FROM fcpa_transactions
        WHERE account_id = %s AND user_id = %s
        ORDER BY trans_date, id
    """, (account_id, user_id))
    rows = [dict(r) for r in cursor.fetchall()]
    close_db(conn)
    return rows


# --- Alerts ---

def get_alerts(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    alerts = []

    # Uncategorized fcpa_transactions
    cursor.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(ABS(amount)),0) as total FROM fcpa_transactions WHERE category = 'Uncategorized' AND user_id = %s", (user_id,))
    r = dict(cursor.fetchone())
    if r['cnt'] > 0:
        alerts.append({'type': 'uncategorized', 'severity': 'warning', 'count': r['cnt'],
            'title': f"{r['cnt']} uncategorized fcpa_transactions", 'detail': f"${r['total']:,.2f} needs review",
            'action': 'fcpa_transactions', 'filters': {'category': 'Uncategorized'}})

    # Flagged needing review
    cursor.execute("SELECT COUNT(*) as cnt FROM fcpa_transactions WHERE is_flagged = 1 AND (user_notes IS NULL OR user_notes = '') AND user_id = %s", (user_id,))
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'flagged_unreviewed', 'severity': 'danger', 'count': r['cnt'],
            'title': f"{r['cnt']} flagged fcpa_transactions without notes",
            'detail': 'Flagged items should be reviewed and noted',
            'action': 'fcpa_transactions', 'filters': {'is_flagged': '1'}})

    # Transactions with no cardholder
    cursor.execute("SELECT COUNT(*) as cnt FROM fcpa_transactions WHERE (cardholder_name IS NULL OR cardholder_name = '') AND amount < 0 AND user_id = %s", (user_id,))
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'no_cardholder', 'severity': 'info', 'count': r['cnt'],
            'title': f"{r['cnt']} fcpa_transactions without cardholder",
            'detail': 'Assign cardholders for better analysis',
            'action': 'fcpa_transactions', 'filters': {}})

    # Not classified as personal or business
    cursor.execute("SELECT COUNT(*) as cnt FROM fcpa_transactions WHERE is_personal = 0 AND is_business = 0 AND amount < 0 AND user_id = %s", (user_id,))
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'unclassified', 'severity': 'warning', 'count': r['cnt'],
            'title': f"{r['cnt']} not marked personal or business",
            'detail': 'Mark spending as personal or business for separation',
            'action': 'fcpa_transactions', 'filters': {}})

    # Large single fcpa_transactions
    cursor.execute("SELECT COUNT(*) as cnt FROM fcpa_transactions WHERE ABS(amount) > 5000 AND (user_notes IS NULL OR user_notes = '') AND user_id = %s", (user_id,))
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'large_unnoted', 'severity': 'info', 'count': r['cnt'],
            'title': f"{r['cnt']} large fcpa_transactions without notes",
            'detail': 'Transactions over $5,000 should be documented',
            'action': 'fcpa_transactions', 'filters': {'min_amount': '5000'}})

    close_db(conn)
    return alerts

# --- Saved Filters ---

def get_saved_filters(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT id, name, filters FROM fcpa_saved_filters WHERE user_id = %s ORDER BY name ASC", (user_id,))
    rows = cursor.fetchall()
    close_db(conn)
    return [{'id': r['id'], 'name': r['name'], 'filters': json.loads(r['filters'])} for r in rows]

def add_saved_filter(user_id, name, filters_dict):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "INSERT INTO fcpa_saved_filters (user_id, name, filters) VALUES (%s, %s, %s)",
        (user_id, name, json.dumps(filters_dict))
    )
    conn.commit()
    fid = cursor.lastrowid
    close_db(conn)
    return fid

def delete_saved_filter(user_id, filter_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("DELETE FROM fcpa_saved_filters WHERE user_id = %s AND id = %s", (user_id, filter_id))
    conn.commit()
    close_db(conn)

# --- Telemetry Logs ---

def log_drilldown(user_id, data):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        INSERT INTO fcpa_drilldown_logs (user_id, source_tab, widget_id, target, filters_applied, metadata)
        VALUES (%s, %s, %s, %s, %s, %s)
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
    close_db(conn)
    return log_id

def add_document_extraction(user_id, document_id, status='pending'):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        INSERT INTO fcpa_document_extractions (user_id, document_id, status)
        VALUES (%s, %s, %s)
    """, (user_id, document_id, status))
    conn.commit()
    ext_id = cursor.lastrowid
    close_db(conn)
    return ext_id

def update_document_extraction(user_id, ext_id, extraction_data=None, status=None, error_message=None):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    updates = []
    params = []
    
    if extraction_data is not None:
        updates.append("extraction_data = %s")
        params.append(extraction_data if isinstance(extraction_data, str) else json.dumps(extraction_data))
        
    if status is not None:
        updates.append("status = %s")
        params.append(status)
        
    if error_message is not None:
        updates.append("error_message = %s")
        params.append(error_message)
        
    if not updates:
        return
        
    updates.append("updated_at = CURRENT_TIMESTAMP")
    params.append(ext_id)
    params.append(user_id)
    
    query = f"UPDATE fcpa_document_extractions SET {', '.join(updates)} WHERE id = %s AND user_id = %s"
    cursor.execute(query, tuple(params))
    conn.commit()
    close_db(conn)

def get_document_extraction(user_id, document_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT * FROM fcpa_document_extractions 
        WHERE document_id = %s AND user_id = %s
        ORDER BY created_at DESC LIMIT 1
    """, (document_id, user_id))
    row = cursor.fetchone()
    close_db(conn)
    return dict(row) if row else None

def get_taxonomy_config(user_id):
    """Fetches the taxonomy configuration as a list of dicts."""
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_taxonomy_config WHERE user_id = %s ORDER BY category_type, severity DESC", (user_id,))
    rows = cursor.fetchall()
    close_db(conn)
    return [dict(r) for r in rows]

def add_taxonomy_config(user_id, name, description, category_type, severity):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute("INSERT INTO fcpa_taxonomy_config (user_id, name, description, category_type, severity) VALUES (%s, %s, %s, %s, %s) RETURNING id", (user_id, name, description, category_type, severity))
        _id = cursor.fetchone()['id']
        conn.commit()
        return _id
    except psycopg2.IntegrityError:
        return None
    finally:
        close_db(conn)

def delete_taxonomy_config(user_id, tax_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("DELETE FROM fcpa_taxonomy_config WHERE id = %s AND user_id = %s", (tax_id, user_id))
    conn.commit()
    close_db(conn)

def add_document_categorization(user_id, document_id, extraction_id, categorization_data, provider, model, status="completed", error_message=None):
    """Persists an LLM-generated document categorization payload."""
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Auto-increment version dynamically per document
    cursor.execute("SELECT MAX(version) FROM fcpa_document_categorizations WHERE document_id = %s AND user_id = %s", (document_id, user_id))
    result = cursor.fetchone()[0]
    next_version = 1 if result is None else result + 1

    cursor.execute("""
        INSERT INTO fcpa_document_categorizations (
            user_id, document_id, extraction_id, categorization_data, 
            provider, model, version, status, error_message
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        user_id, document_id, extraction_id, 
        categorization_data if isinstance(categorization_data, str) else json.dumps(categorization_data),
        provider, model, next_version, status, error_message
    ))
    conn.commit()
    cat_id = cursor.lastrowid
    close_db(conn)
    return cat_id

def get_document_categorization(user_id, document_id):
    """Fetches the latest categorization for a given document."""
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT * FROM fcpa_document_categorizations 
        WHERE document_id = %s AND user_id = %s
        ORDER BY created_at DESC, version DESC LIMIT 1
    """, (document_id, user_id))
    row = cursor.fetchone()
    close_db(conn)
    return dict(row) if row else None


# --- Integrations ---

def get_integration(user_id, provider):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_integrations WHERE user_id = %s AND provider = %s", (user_id, provider))
    row = cursor.fetchone()
    close_db(conn)
    return dict(row) if row else None

def get_integrations(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM fcpa_integrations WHERE user_id = %s", (user_id,))
    rows = cursor.fetchall()
    close_db(conn)
    return [dict(row) for row in rows]

def upsert_integration(user_id, provider, status='Connected', scopes=None, access_token=None, refresh_token=None, expires_at=None, metadata=None):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Store JSON if metadata or scopes are dicts/lists
    if isinstance(scopes, (dict, list)):
        scopes = json.dumps(scopes)
    if isinstance(metadata, (dict, list)):
        metadata = json.dumps(metadata)
        
    cursor.execute("""
        INSERT INTO fcpa_integrations (
            user_id, provider, status, scopes, access_token, refresh_token,
            expires_at, metadata, connected_at, updated_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, provider) DO UPDATE SET
            status = excluded.status,
            scopes = excluded.scopes,
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            expires_at = excluded.expires_at,
            metadata = excluded.metadata,
            updated_at = CURRENT_TIMESTAMP
    """, (user_id, provider, status, scopes, access_token, refresh_token, expires_at, metadata))
    conn.commit()
    close_db(conn)

def delete_integration(user_id, provider):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("DELETE FROM fcpa_integrations WHERE user_id = %s AND provider = %s", (user_id, provider))
    conn.commit()
    close_db(conn)
