import sqlite3
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import init_db, get_db, add_category_rule, add_transaction, add_account
from categorizer import categorize_transaction
from merchant_normalizer import MerchantNormalizer

def run_test():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'test_audit.db')
    if os.path.exists(db_path):
        os.remove(db_path)
    os.environ['DB_PATH'] = db_path
    
    from app import app
    with app.app_context():
        init_db()

        conn = get_db()
        c = conn.cursor()

        c.execute("INSERT OR IGNORE INTO users (email, password_hash) VALUES ('test_calib@example.com', 'hash')")
        c.execute("SELECT id FROM users WHERE email = 'test_calib@example.com'")
        user_id = c.fetchone()['id']
        conn.commit()
        
        acct_id = add_account(user_id, 'Checking', '1234', 'Bank', 'depository', 'checking')

        c.execute("PRAGMA foreign_keys = OFF")
        c.execute("DELETE FROM transactions")
        c.execute("DELETE FROM category_rules")
        c.execute("DELETE FROM merchants")
        c.execute("DELETE FROM categories")
        c.execute("PRAGMA foreign_keys = ON")
        conn.commit()

        # Seed an ambiguous rule for 'SQ *' (Square POS)
        add_category_rule(user_id, 'SQ *%', 'Services', priority=40)
        
        # Seed a strong rule for Netflix
        add_category_rule(user_id, 'NETFLIX.COM', 'Entertainment', priority=80)

        # 1. Sparse History (Only 1 previous transaction for Netflix)
        m_netflix = MerchantNormalizer.learn_merchant_alias(user_id, "NETFLIX.COM", "NETFLIX")
        c.execute("INSERT INTO categories (user_id, name, category_type) VALUES (?, 'Entertainment', 'expense')", (user_id,))
        cat_ent = c.lastrowid
        c.execute("UPDATE merchants SET default_category_id=? WHERE id=?", (cat_ent, m_netflix))
        conn.commit()
        
        add_transaction(user_id, None, acct_id, "2026-01-01", "2026-01-01", "NETFLIX.COM", -15.99, "debit", category="Entertainment", is_approved=1, merchant_id=m_netflix)
        
        print("\n--- Running Confidence Calibration Smoke Tests ---\n")
        
        # Test 1: Ambiguous Text Penalty ("SQ * BOBS PLUMBING")
        # Expected: The rule 'SQ *%' provides 0.40 confidence. But because it has a broad prefix and no history, it should NOT reach 0.90 or even 0.65 easily.
        res1 = categorize_transaction(user_id, "SQ * BOBS PLUMBING", -150.00, account_id=acct_id)
        print(f"Test 1 (Ambiguous Text): {res1['category']} | Confidence: {res1.get('categorization_confidence')} | Expl: {res1.get('categorization_explanation')}")
        assert res1.get('categorization_confidence', 0) < 0.65 # Should be review_required!
        
        # Test 2: Sparse History Penalty
        # Expected: Rule priority 80 + Sparse frequency (1 count, no massive bonus) = Should cap at ~0.8-0.85, NOT >= 0.90 for auto-apply.
        res2 = categorize_transaction(user_id, "NETFLIX.COM", -15.99, account_id=acct_id)
        print(f"Test 2 (Sparse History): {res2['category']} | Confidence: {res2.get('categorization_confidence')} | Expl: {res2.get('categorization_explanation')}")
        assert res2.get('categorization_confidence', 0) < 0.90 # Must NOT auto-apply!
        
        # Let's add 10 more Netflix transactions to prove it can reach Auto-Apply (0.90+)
        for i in range(10):
            add_transaction(user_id, None, acct_id, f"2026-02-0{i+1}", f"2026-02-0{i+1}", "NETFLIX.COM", -15.99, "debit", category="Entertainment", is_approved=1, merchant_id=m_netflix)
            
        res3 = categorize_transaction(user_id, "NETFLIX.COM", -15.99, account_id=acct_id)
        print(f"Test 3 (Robust History): {res3['category']} | Confidence: {res3.get('categorization_confidence')} | Status: {res3.get('categorization_status')}")
        assert res3.get('categorization_confidence', 0) >= 0.90
        assert res3.get('categorization_status') == 'auto_applied'

if __name__ == "__main__":
    run_test()
