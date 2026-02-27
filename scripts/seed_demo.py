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
    
    account_ids = {}
    for acc in accounts:
        acc_id = database.add_account(
            user_id, acc["name"], acc["number"], acc["type"], acc["institution"]
        )
        account_ids[acc["type"]] = acc_id
    
    # 3. Add sample taxonomy configs
    topics = scenario.get("taxonomy", [])
    conn = database.get_db()
    cursor = conn.cursor()
    for topic in topics:
        cursor.execute(
            "INSERT INTO taxonomy_config (user_id, name, description, category_type, severity) VALUES (?, ?, ?, ?, ?)",
            (user_id, topic['name'], topic['description'], topic['category_type'], topic['severity'])
        )
        
    # 4. Generate rules
    rules = scenario.get("category_rules", [])
    for rule in rules:
        cursor.execute(
            "INSERT INTO category_rules (user_id, pattern, category, subcategory, is_personal, is_business, is_transfer, priority) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, rule['pattern'], rule['category'], rule.get('subcategory', ''), rule.get('is_personal', 0), rule.get('is_business', 0), rule.get('is_transfer', 0), rule.get('priority', 0))
        )

    # 5. Generate some realistic transactions over the last 6 months
    transactions = scenario.get("base_transactions", [])
    
    today = datetime.now()
    records_inserted = 0
    
    # Duplicate base transactions across random dates to build volume
    for _ in range(5):
        for tx in transactions:
            random_days = random.randint(1, 180)
            tx_date = (today - timedelta(days=random_days)).strftime('%Y-%m-%d')
            
            # Use query builder directly
            cursor.execute("""
                INSERT INTO transactions (
                    user_id, account_id, trans_date, description, amount, trans_type, 
                    category, subcategory, payment_method, is_business, is_personal, 
                    is_transfer, cardholder_name, user_notes, is_flagged, flag_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, account_ids[tx["acc"]], tx_date, tx["desc"], tx["amount"], tx["type"],
                tx.get('category', 'Uncategorized'), tx.get('subcategory', ''), tx.get('payment_method', ''),
                tx.get('is_business', 0), tx.get('is_personal', 0), tx.get('is_transfer', 0),
                tx.get('cardholder_name', ''), tx.get('user_notes', ''),
                tx.get('is_flagged', 0), tx.get('flag_reason')
            ))
            records_inserted += 1
            
    # Add a specifically flagged anomaly
    flagged = scenario.get("flagged_transaction", {})
    if flagged:
        cursor.execute("""
            INSERT INTO transactions (
                user_id, account_id, trans_date, description, amount, trans_type, 
                category, subcategory, payment_method, is_business, is_personal, 
                is_transfer, cardholder_name, user_notes, is_flagged, flag_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id, account_ids.get(flagged["acc"], account_ids.get('bank')), today.strftime('%Y-%m-%d'), 
            flagged["desc"], flagged["amount"], flagged["type"],
            flagged.get('category', 'Uncategorized'), flagged.get('subcategory', ''), flagged.get('payment_method', ''),
            flagged.get('is_business', 0), flagged.get('is_personal', 0), flagged.get('is_transfer', 0),
            flagged.get('cardholder_name', ''), flagged.get('user_notes', ''),
            1, flagged.get("flag_reason", "")
        ))

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
            doc_meta["statement_end_date"]
        )

    # Adding mock proof link just to populate the drill down
    if doc_id:
        tx_id_flagged = cursor.lastrowid
        cursor.execute("INSERT INTO proof_links (user_id, transaction_id, document_id) VALUES (?, ?, ?)", (user_id, tx_id_flagged, doc_id))

    conn.commit()
    
    # Verification
    cursor.execute("SELECT COUNT(*) FROM transactions WHERE user_id = ?", (user_id,))
    count = cursor.fetchone()[0]
    print(f"DB PATH IS: {database.DB_PATH}")
    print(f"Transactions committed to DB for user {user_id}: {count}")
    
    conn.close()
    
    print(f"Demo seeding complete. Inserted {records_inserted + 1} realistic mock transactions.")
    return user_id

if __name__ == "__main__":
    seed_demo_environment()
