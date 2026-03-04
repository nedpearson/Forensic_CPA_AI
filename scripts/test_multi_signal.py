import sqlite3
import os
import sys

# Ensure tests can import app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import init_db, get_db, add_category_rule, add_transaction, add_account
from categorizer import categorize_transaction
from merchant_normalizer import MerchantNormalizer

def run_test():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'test_audit.db')
    if os.path.exists(db_path):
        os.remove(db_path)
    os.environ['DB_PATH'] = db_path
    init_db()

    conn = get_db()
    c = conn.cursor()

    # Create test user safely
    c.execute("INSERT OR IGNORE INTO users (email, password_hash) VALUES ('test_multi@example.com', 'hash')")
    c.execute("SELECT id FROM users WHERE email = 'test_multi@example.com'")
    user_id = c.fetchone()['id']
    conn.commit()
    
    # Create test account
    acct_id = add_account(user_id, 'Checking', '1234', 'Bank', 'depository', 'checking')

    # Seed an absolute rule (Priority 100)
    add_category_rule(user_id, '%STARBUCKS%', 'Personal - Dining', priority=100)
    
    # Seed a weak rule (Priority 40)
    add_category_rule(user_id, '%TARGET%', 'Business - Supplies', priority=40)
    
    # Seed historical DB logic: User has categorized "AMAZON" as "Software" 10 times for $12.00
    m_id = MerchantNormalizer.learn_merchant_alias(user_id, "AMAZON WEB", "AMAZON")
    c.execute("INSERT INTO categories (user_id, name, category_type) VALUES (?, 'Software', 'expense')", (user_id,))
    cat_software = c.lastrowid
    c.execute("UPDATE merchants SET default_category_id=? WHERE id=?", (cat_software, m_id))
    conn.commit()
    conn.close()

    for i in range(10):
        # Insert historical transactions
        add_transaction(user_id, None, acct_id, f"2026-01-0{i+1}", f"2026-01-0{i+1}", "AMAZON WEB SERVICES", -12.00, "debit", category="Software", is_approved=1, merchant_id=m_id)
        
    # Also add a wildly different Amazon transaction as "Business - Supplies" for $400
    add_transaction(user_id, None, acct_id, "2026-01-15", "2026-01-15", "AMAZON BULK", -400.00, "debit", category="Business - Supplies", is_approved=1, merchant_id=m_id)

    # Don't try to conn.commit() when conn is closed
    
    print("\n--- Running Multi-Signal Smoke Tests ---\n")
    
    # Test 1: Absolute Rule Match (Priority 100 -> Confidence 1.0)
    res1 = categorize_transaction(user_id, "STARBUCKS STORE #123", -5.50, account_id=acct_id)
    print(f"Test 1 (Priority 100): {res1['category']} | Confidence: {res1.get('categorization_confidence')} | Status: {res1.get('categorization_status')}")
    assert res1['category'] == 'Personal - Dining'
    assert res1['categorization_status'] == 'auto_applied'

    # Test 2: Weak Rule with expected Amount Match (Confidence gets boosted!)
    # AWS Historical is $12.00
    res2 = categorize_transaction(user_id, "AMAZON WEB", -12.00, account_id=acct_id)
    print(f"Test 2 (History + Merchant Match): {res2['category']} | Confidence: {res2.get('categorization_confidence')} | Expl: {res2.get('categorization_explanation')}")
    assert res2['category'] == 'Software'
    
    # Test 3: Conflict! Weak Rule / Merchant match but vastly wrong amount
    res3 = categorize_transaction(user_id, "AMAZON WEB", -5000.00, account_id=acct_id)
    print(f"Test 3 (Conflict - Huge Amount): {res3['category']} | Confidence: {res3.get('categorization_confidence')} | Status: {res3.get('categorization_status')}")
    assert res3['categorization_status'] in ['review_required', 'suggested'] # Confidence should be slashed

if __name__ == "__main__":
    run_test()
