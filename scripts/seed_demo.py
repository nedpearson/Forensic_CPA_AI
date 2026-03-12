import os
import sys
import random
import json
from datetime import datetime, timedelta

# Ensure python path allows importing database
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import database

def load_scenario():
    path = os.path.join(os.path.dirname(__file__), '..', 'shared', 'demo_scenario.json')
    with open(path, 'r') as f:
        return json.load(f)

def seed_demo_environment():
    print("Initializing demo environment...")
    
    scenario = load_scenario()
    
    # 1. Guarantee idempotent workspace
    user_id = database.create_demo_user(wipe_data=True)
    if not user_id:
        print("Failed to initialize demo user. Aborting seed.")
        return
        
    print(f"Isolated demo tenant initialized (User ID: {user_id})")
    
    # 2. Add sample accounts
    accounts = scenario.get("accounts", [])
    
    # Check if we are using Postgres or SQLite to properly format queries
    is_pg = os.environ.get('DB_DIALECT', 'sqlite').lower() == 'postgres'
    placeholder = '%s' if is_pg else '?'
    table_prefix = 'fcpa_' if is_pg else ''
    
    conn = database.get_db()
    if is_pg:
        from psycopg2.extras import RealDictCursor
        cursor = conn.cursor(cursor_factory=RealDictCursor)
    else:
        cursor = conn.cursor()

    # Guarantee Company Context
    cursor.execute(f"SELECT cm.company_id FROM {table_prefix}company_memberships cm WHERE cm.user_id = {placeholder} ORDER BY cm.is_default DESC LIMIT 1", (user_id,))
    comp_row = cursor.fetchone()
    if comp_row:
        company_id = comp_row['company_id'] if isinstance(comp_row, dict) else comp_row[0]
    else:
        cursor.execute(f"INSERT INTO {table_prefix}companies (name, created_by, owner_user_id) VALUES ({placeholder}, {placeholder}, {placeholder})", ("Mock Company LLC (Demo)", user_id, user_id))
        company_id = cursor.fetchone()['id'] if is_pg else cursor.lastrowid
        cursor.execute(f"INSERT INTO {table_prefix}company_memberships (user_id, company_id, role, is_default) VALUES ({placeholder}, {placeholder}, 'ADMIN', 1)", (user_id, company_id))
    # Always ensure demo user has ADMIN role (required for QuickBooks Connect button)
    cursor.execute(f"UPDATE {table_prefix}company_memberships SET role = 'ADMIN' WHERE user_id = {placeholder}", (user_id,))
    conn.commit()

    account_ids = {}
    for acc in accounts:
        # Pass company_id explicitly to bypass session Shim requirement
        acc_id = database.add_account(
            user_id, acc["name"], acc["number"], acc["type"], acc["institution"], company_id=company_id
        )
        account_ids[acc["type"]] = acc_id
    
    # 3. Add sample taxonomy configs
    topics = scenario.get("taxonomy", [])
    for topic in topics:
        cursor.execute(
            f"INSERT INTO {table_prefix}taxonomy_config (user_id, name, description, category_type, severity) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})",
            (user_id, topic['name'], topic['description'], topic['category_type'], topic['severity'])
        )
        
    # 4. Generate some realistic transactions over the last 6 months
    transactions = scenario.get("base_transactions", [])
    
    today = datetime.now()
    records_inserted = 0
    
    # Duplicate base transactions across random dates to build volume
    for _ in range(5):
        for tx in transactions:
            random_days = random.randint(1, 180)
            tx_date = (today - timedelta(days=random_days)).strftime('%Y-%m-%d')
            
            # Use query builder directly
            cursor.execute(f"""
                INSERT INTO {table_prefix}transactions (
                    user_id, account_id, trans_date, description, amount, trans_type
                ) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
            """, (user_id, account_ids[tx["acc"]], tx_date, tx["desc"], tx["amount"], tx["type"]))
            records_inserted += 1
            
    # Add a specifically flagged anomaly
    flagged = scenario.get("flagged_transaction", {})
    if flagged:
        cursor.execute(f"""
            INSERT INTO {table_prefix}transactions (
                user_id, account_id, trans_date, description, amount, trans_type, is_flagged, flag_reason
            ) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
        """, (user_id, account_ids.get(flagged["acc"], account_ids['bank']), today.strftime('%Y-%m-%d'), 
              flagged["desc"], flagged["amount"], flagged["type"], 1, flagged["flag_reason"]))

        # For the flagged anomaly, we need its ID for the proof link
        if is_pg:
            cursor.execute(f"SELECT id FROM {table_prefix}transactions WHERE user_id = %s ORDER BY id DESC LIMIT 1", (user_id,))
            tx_id_flagged = cursor.fetchone()['id']
        else:
            tx_id_flagged = cursor.lastrowid

    # Free the write lock so add_document can use its own connection
    conn.commit()

    # Add a mock document
    doc_meta = scenario.get("document", {})
    doc_id = None
    if doc_meta:
        doc_id = database.add_document(
            user_id, 
            doc_meta["filename"], 
            doc_meta["original_path"], 
            doc_meta["file_type"], 
            doc_meta["doc_category"], 
            account_ids.get(doc_meta["account"], account_ids['bank']), 
            doc_meta["statement_start_date"], 
            doc_meta["statement_end_date"],
            company_id=company_id
        )

    # Adding mock proof link just to populate the drill down
    if doc_id and flagged:
        cursor.execute(f"INSERT INTO {table_prefix}proof_links (user_id, transaction_id, document_id) VALUES ({placeholder}, {placeholder}, {placeholder})", (user_id, tx_id_flagged, doc_id))

    conn.commit()
    
    # Verification
    cursor.execute(f"SELECT COUNT(*) as cnt FROM {table_prefix}transactions WHERE user_id = {placeholder}", (user_id,))
    
    if is_pg:
        count = cursor.fetchone()['cnt']
    else:
        count = cursor.fetchone()[0]
        
    print(f"Transactions committed to DB for user {user_id}: {count}")
    
    database.close_db(conn)
    
    print(f"Demo seeding complete. Inserted {records_inserted + 1} realistic mock transactions.")
    return user_id

if __name__ == "__main__":
    seed_demo_environment()
