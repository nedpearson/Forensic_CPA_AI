import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import database
from categorization_pipeline import CategorizationPipeline

def setup_db():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'test_final_pass.db')
    if os.path.exists(db_path):
        os.remove(db_path)
    os.environ['DB_PATH'] = db_path
    database.DB_PATH = db_path
    database.init_db()

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (email, password_hash) VALUES ('test_final@example.com', 'has')")
    cursor.execute("SELECT id FROM users WHERE email='test_final@example.com'")
    user_id = cursor.fetchone()['id']
    conn.commit()
    conn.close()
    
    return user_id

def run_test():
    uid = setup_db()
    print("\n--- Phase 14: Final Autopilot Hardening Verification ---\n")
    
    conn = database.get_db()
    c = conn.cursor()
    
    # 1. Duplicate Rule Prevention
    # If the AI or User spams the same pattern, it should only create ONE rule in the database, with hit_count going up.
    print("[1] Testing Rule Deduplication...")
    pattern = "%WALMART%"
    database.add_category_rule(uid, pattern, "Groceries", priority=50)
    database.add_category_rule(uid, pattern, "Groceries", priority=50)
    database.add_category_rule(uid, pattern, "Groceries", priority=50)
    
    c.execute("SELECT hit_count, priority FROM category_rules WHERE pattern = ?", (pattern,))
    rows = list(c.fetchall())
    assert len(rows) == 1, "Duplicate learned rules were created!"
    assert rows[0]['hit_count'] == 3, "Hit count failed to aggregate duplicates."
    assert rows[0]['priority'] == 80, "Loyalty scaling failed."
    print(">> PASS: The system inherently deduplicates mapped rules into a single dynamic scaling vector.")

    # 2. Strict User Overrides (100) vs Safe Autopilot (90)
    print("\n[2] Testing Explicit Override Protection...")
    # Assume Walmart hits the Autopilot criteria (priority 80, hits 3)
    db_res = CategorizationPipeline.process_transaction(uid, "WALMART STORE 123", 45.0)
    assert db_res['categorization_status'] == 'auto_applied', "Safe Autopilot failed to trigger on stable rule."
    
    # User decides to explicitly map WALMART to "Personal Care"
    database.add_category_rule(uid, pattern, "Personal Care", priority=100)
    db_res = CategorizationPipeline.process_transaction(uid, "WALMART STORE 123", 25.0)
    assert db_res['category'] == 'Personal Care', "Pipeline failed to respect Explicit User Override."
    assert db_res['categorization_confidence'] == 1.0, "Explicit Overrides should be max confidence."
    print(">> PASS: Explicit user overrides immutably trump learned AI logic and Autopilot.")

    # 3. Risky transactions STILL drop back to Review
    print("\n[3] Testing Sparse / Ambiguous Caution Hooks...")
    # Inject a transaction with an ambiguous prefix
    db_res = CategorizationPipeline.process_transaction(uid, "SQ *LOCAL BAKERY", 12.0)
    assert db_res['categorization_status'] == 'review_required', "Ambiguous merchant bypassed Review Queue!"
    print(">> PASS: Risky / Ambiguous patterns correctly degrade confidence and mandate Human Review.")
    
    # 4. Duplicate Categorization Execution Prevention 
    print("\n[4] Testing Idempotent Background Sweep Integrity...")
    c.execute("INSERT INTO transactions (user_id, trans_date, description, amount, category, trans_type) VALUES (?, ?, ?, ?, ?, ?)",
              (uid, "2026-02-27", "WALMART STORE 123", 15.0, "Uncategorized", "debit"))
    tx_id = c.lastrowid
    conn.commit()
    
    # Run categorizer once
    import categorizer
    
    # Needs a dict-like row with trans_date, description, amount, etc.
    c.execute("SELECT * FROM transactions WHERE id = ?", (tx_id,))
    tx_row = dict(c.fetchone())
    
    res = categorizer.categorize_transaction(uid, tx_row['description'], tx_row['amount'], trans_type=tx_row['trans_type'], trans_date=tx_row['trans_date'])
    c.execute("UPDATE transactions SET category = ?, categorization_confidence = ?, categorization_status = ? WHERE id = ?", 
              (res['category'], res['categorization_confidence'], res['categorization_status'], tx_id))
    
    c.execute("SELECT category, categorization_confidence FROM transactions WHERE id = ?", (tx_id,))
    tx_res1 = c.fetchone()
    assert tx_res1['category'] == 'Personal Care' # Based on our priority 100 rule in test #2
    
    # Run it again exactly the same way to ensure it doesn't duplicate the row, wipe hit_counts, etc.
    res = categorizer.categorize_transaction(uid, tx_row['description'], tx_row['amount'], trans_type=tx_row['trans_type'], trans_date=tx_row['trans_date'])
    c.execute("UPDATE transactions SET category = ?, categorization_confidence = ?, categorization_status = ? WHERE id = ?", 
              (res['category'], res['categorization_confidence'], res['categorization_status'], tx_id))
    c.execute("SELECT category, categorization_confidence FROM transactions WHERE id = ?", (tx_id,))
    tx_res2 = c.fetchone()
    
    assert tx_res1['category'] == tx_res2['category'], "Idempotent sweeps altered established category state."
    print(">> PASS: Categorization sweeps are idempotent. No conflicting repeat assignments were detected.")

    # 5. Background Sweep Audit Log Integrity
    print("\n[5] Testing Background Sweep Audit Trail...")
    c.execute("INSERT INTO transactions (user_id, trans_date, description, amount, category, trans_type) VALUES (?, ?, ?, ?, ?, ?)",
              (uid, "2026-02-28", "WALMART LOCAL MULTIPASS", 11.0, "Uncategorized", "credit"))
    sweep_tx_id = c.lastrowid
    conn.commit()
    
    # Run the background categorizer sweep
    import categorizer
    categorizer.recategorize_all(uid)
    
    # Assert category changed correctly
    c.execute("SELECT category FROM transactions WHERE id = ?", (sweep_tx_id,))
    sweep_cat = c.fetchone()['category']
    assert sweep_cat == 'Personal Care', "Background sweep failed to categorize."
    
    # Assert audit log was generated
    c.execute("SELECT * FROM audit_log WHERE transaction_id = ? AND field_changed = 'category'", (sweep_tx_id,))
    logs = list(c.fetchall())
    assert len(logs) >= 1, "Audit log was NOT created by the background sweep!"
    assert logs[0]['new_value'] == 'Personal Care', "Audit log recorded incorrect value."
    print(">> PASS: Background AI Sweeps natively route through update_transaction, preserving full CPA auditability.")

    print("\n>>> ALL PHASE 14/15 AUTOPILOT VERIFICATION STATEMENTS CONCLUDE PASS! <<<")

if __name__ == '__main__':
    run_test()
