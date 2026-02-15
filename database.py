"""
Database layer for Forensic Auditor.
Uses SQLite for local, portable storage of all transaction data.
"""
import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'forensic_audit.db')


def get_db():
    """Get a database connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialize all database tables."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            filename TEXT NOT NULL,
            original_path TEXT,
            file_type TEXT NOT NULL,  -- 'pdf', 'xlsx', 'docx', 'csv'
            doc_category TEXT,  -- 'bank_statement', 'credit_card', 'venmo', 'proof', 'other'
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            statement_start_date TEXT,
            statement_end_date TEXT,
            account_id INTEGER,
            notes TEXT,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            FOREIGN KEY (document_id) REFERENCES documents(id),
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            parent_category TEXT,
            category_type TEXT,  -- 'personal', 'business', 'transfer', 'deposit', 'fee', 'other'
            color TEXT DEFAULT '#6c757d',
            icon TEXT
        );

        CREATE TABLE IF NOT EXISTS category_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT,
            is_personal INTEGER DEFAULT 0,
            is_business INTEGER DEFAULT 0,
            is_transfer INTEGER DEFAULT 0,
            priority INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            transaction_id INTEGER NOT NULL,
            document_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
            FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
            UNIQUE(transaction_id, document_id)
        );

        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            note_type TEXT DEFAULT 'general',  -- 'general', 'finding', 'evidence', 'timeline'
            severity TEXT DEFAULT 'info',  -- 'info', 'warning', 'danger'
            linked_transaction_ids TEXT,  -- JSON array of transaction IDs
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS saved_filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            filters TEXT NOT NULL,  -- JSON object of filter params
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    """)

    # Insert default categories
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
            "INSERT OR IGNORE INTO categories (name, parent_category, category_type, color, icon) VALUES (?, ?, ?, ?, ?)",
            cat
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
            "INSERT OR IGNORE INTO category_rules (pattern, category, subcategory, is_personal, is_business, is_transfer, priority) VALUES (?, ?, ?, ?, ?, ?, ?)",
            rule
        )

    conn.commit()
    conn.close()


# --- Data Management ---

def clear_all_data():
    """Delete all financial data while keeping categories and rules."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.executescript("""
        DELETE FROM proof_links;
        DELETE FROM audit_log;
        DELETE FROM transactions;
        DELETE FROM documents;
        DELETE FROM accounts;
        DELETE FROM case_notes;
        DELETE FROM saved_filters;
    """)
    conn.commit()
    conn.close()


# --- CRUD Operations ---

def add_account(account_name, account_number, account_type, institution, cardholder_name=None, card_last_four=None, notes=None):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO accounts (account_name, account_number, account_type, institution, cardholder_name, card_last_four, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (account_name, account_number, account_type, institution, cardholder_name, card_last_four, notes)
    )
    account_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return account_id


def get_or_create_account(account_name, account_number, account_type, institution, cardholder_name=None, card_last_four=None):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM accounts WHERE account_number = ? AND account_type = ? AND (cardholder_name = ? OR cardholder_name IS NULL)",
        (account_number, account_type, cardholder_name)
    )
    row = cursor.fetchone()
    if row:
        conn.close()
        return row['id']
    conn.close()
    return add_account(account_name, account_number, account_type, institution, cardholder_name, card_last_four)


def add_document(filename, original_path, file_type, doc_category, account_id=None, statement_start=None, statement_end=None, notes=None):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO documents (filename, original_path, file_type, doc_category, account_id, statement_start_date, statement_end_date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (filename, original_path, file_type, doc_category, account_id, statement_start, statement_end, notes)
    )
    doc_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return doc_id


def find_duplicate_transactions(transactions):
    """Check a list of parsed transactions against existing DB transactions.
    Returns list of (index, existing_transaction) tuples for duplicates."""
    conn = get_db()
    cursor = conn.cursor()
    duplicates = []
    for i, t in enumerate(transactions):
        cursor.execute("""
            SELECT id, trans_date, description, amount FROM transactions
            WHERE trans_date = ? AND ABS(amount - ?) < 0.01
            AND UPPER(description) = UPPER(?)
        """, (t.get('trans_date', ''), t.get('amount', 0), t.get('description', '')))
        existing = cursor.fetchone()
        if existing:
            duplicates.append({'index': i, 'existing': dict(existing)})
    conn.close()
    return duplicates


def add_transaction(doc_id, account_id, trans_date, post_date, description, amount, trans_type, category='uncategorized', **kwargs):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO transactions (document_id, account_id, trans_date, post_date, description, amount, trans_type, category,
            subcategory, cardholder_name, card_last_four, payment_method, check_number,
            is_transfer, transfer_to_account, transfer_from_account,
            is_personal, is_business, is_flagged, flag_reason, auto_categorized, manually_edited)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        doc_id, account_id, trans_date, post_date, description, amount, trans_type, category,
        kwargs.get('subcategory'), kwargs.get('cardholder_name'), kwargs.get('card_last_four'),
        kwargs.get('payment_method'), kwargs.get('check_number'),
        kwargs.get('is_transfer', 0), kwargs.get('transfer_to_account'), kwargs.get('transfer_from_account'),
        kwargs.get('is_personal', 0), kwargs.get('is_business', 0),
        kwargs.get('is_flagged', 0), kwargs.get('flag_reason'),
        kwargs.get('auto_categorized', 1), kwargs.get('manually_edited', 0)
    ))
    trans_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return trans_id


def update_transaction(trans_id, **fields):
    """Update a transaction and log the changes."""
    conn = get_db()
    cursor = conn.cursor()

    # Get current values for audit log
    cursor.execute("SELECT * FROM transactions WHERE id = ?", (trans_id,))
    old = dict(cursor.fetchone())

    set_clauses = []
    values = []
    for field, value in fields.items():
        set_clauses.append(f"{field} = ?")
        values.append(value)
        # Log the change
        if str(old.get(field)) != str(value):
            cursor.execute(
                "INSERT INTO audit_log (transaction_id, action, old_value, new_value, field_changed) VALUES (?, 'update', ?, ?, ?)",
                (trans_id, str(old.get(field)), str(value), field)
            )

    set_clauses.append("updated_at = ?")
    values.append(datetime.now().isoformat())
    set_clauses.append("manually_edited = 1")
    values.append(trans_id)

    cursor.execute(f"UPDATE transactions SET {', '.join(set_clauses)} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_transaction(trans_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions WHERE id = ?", (trans_id,))
    old = cursor.fetchone()
    if old:
        cursor.execute(
            "INSERT INTO audit_log (transaction_id, action, old_value, field_changed) VALUES (?, 'delete', ?, 'all')",
            (trans_id, str(dict(old)))
        )
    cursor.execute("DELETE FROM transactions WHERE id = ?", (trans_id,))
    conn.commit()
    conn.close()


def get_transactions(filters=None):
    """Get transactions with optional filters."""
    conn = get_db()
    cursor = conn.cursor()

    query = """
        SELECT t.*, d.filename as doc_filename, a.account_name, a.institution
        FROM transactions t
        LEFT JOIN documents d ON t.document_id = d.id
        LEFT JOIN accounts a ON t.account_id = a.id
        WHERE 1=1
    """
    params = []

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


def get_categories():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM categories ORDER BY name")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_accounts():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts ORDER BY account_name")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_documents():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT d.*, a.account_name FROM documents d LEFT JOIN accounts a ON d.account_id = a.id ORDER BY d.upload_date DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_summary_stats(filters=None):
    """Get summary statistics for dashboard."""
    conn = get_db()
    cursor = conn.cursor()

    where = "WHERE 1=1"
    params = []
    if filters:
        if filters.get('date_from'):
            where += " AND trans_date >= ?"
            params.append(filters['date_from'])
        if filters.get('date_to'):
            where += " AND trans_date <= ?"
            params.append(filters['date_to'])
        if filters.get('cardholder'):
            where += " AND cardholder_name LIKE ?"
            params.append(f"%{filters['cardholder']}%")
        if filters.get('view_mode') == 'personal':
            where += " AND is_personal = 1"
        elif filters.get('view_mode') == 'business':
            where += " AND is_business = 1"

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


def add_category_rule(pattern, category, subcategory=None, is_personal=0, is_business=0, is_transfer=0, priority=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO category_rules (pattern, category, subcategory, is_personal, is_business, is_transfer, priority) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (pattern, category, subcategory, is_personal, is_business, is_transfer, priority)
    )
    conn.commit()
    conn.close()


def get_category_rules():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM category_rules ORDER BY priority DESC, pattern")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# --- Proof Document Links ---

def link_proof(transaction_id, document_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO proof_links (transaction_id, document_id) VALUES (?, ?)",
        (transaction_id, document_id)
    )
    conn.commit()
    conn.close()


def unlink_proof(transaction_id, document_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM proof_links WHERE transaction_id = ? AND document_id = ?",
        (transaction_id, document_id)
    )
    conn.commit()
    conn.close()


def get_proofs_for_transaction(transaction_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.* FROM documents d
        JOIN proof_links pl ON pl.document_id = d.id
        WHERE pl.transaction_id = ?
        ORDER BY d.upload_date DESC
    """, (transaction_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_transactions_for_proof(document_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.id, t.trans_date, t.description, t.amount
        FROM transactions t
        JOIN proof_links pl ON pl.transaction_id = t.id
        WHERE pl.document_id = ?
        ORDER BY t.trans_date DESC
    """, (document_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# --- Case Notes ---

def get_case_notes():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM case_notes ORDER BY updated_at DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def add_case_note(title, content, note_type='general', severity='info', linked_transaction_ids=None):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO case_notes (title, content, note_type, severity, linked_transaction_ids) VALUES (?, ?, ?, ?, ?)",
        (title, content, note_type, severity, json.dumps(linked_transaction_ids or []))
    )
    note_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return note_id


def update_case_note(note_id, **fields):
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
    cursor.execute(f"UPDATE case_notes SET {', '.join(set_clauses)} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_case_note(note_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM case_notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()


# --- Saved Filters ---

def get_saved_filters():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM saved_filters ORDER BY name")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def add_saved_filter(name, filters):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO saved_filters (name, filters) VALUES (?, ?)", (name, json.dumps(filters)))
    fid = cursor.lastrowid
    conn.commit()
    conn.close()
    return fid


def delete_saved_filter(filter_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM saved_filters WHERE id = ?", (filter_id,))
    conn.commit()
    conn.close()


# --- Running Balance Per Account ---

def get_account_running_balance(account_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, trans_date, description, amount, category,
            SUM(amount) OVER (ORDER BY trans_date, id) as running_balance
        FROM transactions
        WHERE account_id = ?
        ORDER BY trans_date, id
    """, (account_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# --- Alerts ---

def get_alerts():
    conn = get_db()
    cursor = conn.cursor()
    alerts = []

    # Uncategorized transactions
    cursor.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(ABS(amount)),0) as total FROM transactions WHERE category = 'Uncategorized'")
    r = dict(cursor.fetchone())
    if r['cnt'] > 0:
        alerts.append({'type': 'uncategorized', 'severity': 'warning', 'count': r['cnt'],
            'title': f"{r['cnt']} uncategorized transactions", 'detail': f"${r['total']:,.2f} needs review",
            'action': 'transactions', 'filters': {'category': 'Uncategorized'}})

    # Flagged needing review
    cursor.execute("SELECT COUNT(*) as cnt FROM transactions WHERE is_flagged = 1 AND (user_notes IS NULL OR user_notes = '')")
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'flagged_unreviewed', 'severity': 'danger', 'count': r['cnt'],
            'title': f"{r['cnt']} flagged transactions without notes",
            'detail': 'Flagged items should be reviewed and noted',
            'action': 'transactions', 'filters': {'is_flagged': '1'}})

    # Transactions with no cardholder
    cursor.execute("SELECT COUNT(*) as cnt FROM transactions WHERE (cardholder_name IS NULL OR cardholder_name = '') AND amount < 0")
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'no_cardholder', 'severity': 'info', 'count': r['cnt'],
            'title': f"{r['cnt']} transactions without cardholder",
            'detail': 'Assign cardholders for better analysis',
            'action': 'transactions', 'filters': {}})

    # Not classified as personal or business
    cursor.execute("SELECT COUNT(*) as cnt FROM transactions WHERE is_personal = 0 AND is_business = 0 AND amount < 0")
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'unclassified', 'severity': 'warning', 'count': r['cnt'],
            'title': f"{r['cnt']} not marked personal or business",
            'detail': 'Mark spending as personal or business for separation',
            'action': 'transactions', 'filters': {}})

    # Large single transactions
    cursor.execute("SELECT COUNT(*) as cnt FROM transactions WHERE ABS(amount) > 5000 AND (user_notes IS NULL OR user_notes = '')")
    r = cursor.fetchone()
    if r['cnt'] > 0:
        alerts.append({'type': 'large_unnoted', 'severity': 'info', 'count': r['cnt'],
            'title': f"{r['cnt']} large transactions without notes",
            'detail': 'Transactions over $5,000 should be documented',
            'action': 'transactions', 'filters': {'min_amount': '5000'}})

    conn.close()
    return alerts
