import re

def convert():
    with open('database_sqlite.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Imports
    content = 'import psycopg2\nfrom psycopg2 import pool\nfrom psycopg2.extras import RealDictCursor\n' + content
    content = content.replace('import sqlite3', '')

    # 2. Connection Logic
    db_logic = """
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
"""

    # replace get_db
    content = re.sub(r'def get_db\(\):.*?(?=\n\n\w)', db_logic, content, flags=re.DOTALL)
    
    # replace conn.close() with close_db(conn) everywhere
    content = content.replace('conn.close()', 'close_db(conn)')
    
    # replace cursor creation
    content = content.replace('conn.cursor()', 'conn.cursor(cursor_factory=RealDictCursor)')
    
    # 3. Parameters
    content = content.replace('?', '%s')
    
    # 4. Table prefixes
    tables = [
        'users', 'accounts', 'documents', 'transactions', 'categories', 
        'category_rules', 'saved_filters', 'document_extractions', 
        'document_categorizations', 'audit_log', 'case_notes', 
        'drilldown_logs', 'taxonomy_config', 'proof_links', 'integrations',
        'companies', 'company_memberships', 'company_invitations', 'advisor_company_state',
        'transaction_sources', 'integrations_new', 'merchants', 'advisor_findings',
        'advisor_remediation_tasks', 'merchant_context_rules', 'merchant_aliases', 'lookup_cache'
    ]
    
    for t in tables:
        # Avoid replacing things like 'documents_dir' or 'users_id'
        content = re.sub(rf'\b{t}\b', f'fcpa_{t}', content)

    # Undo the accidental replacements of fcpa_users in function params or comments if any, but since these are generic nouns, let's refine:
    # We mainly need to replace them in FROM, INTO, UPDATE, JOIN, TABLE...
    
    # 5. Replace SQLite-specific errors with psycopg2 equivalents
    content = content.replace('except sqlite3.IntegrityError', 'except psycopg2.IntegrityError')
    
    # 5. lastrowid to RETURNING id
    # Since sqlite lastrowid is used after execute, we can modify the execute statement
    # Example: cursor.execute("INSERT ...") \n _id = cursor.lastrowid
    # We will just write a regex that catches cursor.execute(INSERT ...) followed by cursor.lastrowid
    # Actually, let's just do a manual pass for the specific `lastrowid` lines since there are few.
    print("Writing to database_pg.py")
    with open('database_pg.py', 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == '__main__':
    convert()
