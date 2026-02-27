import sqlite3
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import init_db, get_db, add_account, add_transaction, add_merchant_context_rule
from merchant_normalizer import MerchantNormalizer
from categorizer import categorize_transaction
from app import app

def run_test():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'test_audit.db')
    if os.path.exists(db_path):
        os.remove(db_path)
    os.environ['DB_PATH'] = db_path
    
    with app.app_context():
        init_db()

        conn = get_db()
        c = conn.cursor()

        c.execute("INSERT OR IGNORE INTO users (email, password_hash) VALUES ('test_ctx@example.com', 'hash')")
        c.execute("SELECT id FROM users WHERE email = 'test_ctx@example.com'")
        user_id = c.fetchone()['id']
        conn.commit()
        
        acct_cc = add_account(user_id, 'Biz Credit Card', '1234', 'credit_card', 'Bank', 'Biz')
        acct_bank = add_account(user_id, 'Checking Auth', '4321', 'depository', 'Bank', 'Auth')

        # Clean DB
        c.execute("PRAGMA foreign_keys = OFF")
        c.execute("DELETE FROM transactions")
        c.execute("DELETE FROM category_rules")
        c.execute("DELETE FROM merchants")
        c.execute("DELETE FROM categories")
        c.execute("PRAGMA foreign_keys = ON")
        conn.commit()
        
        # Seed Categories
        c.execute("INSERT INTO categories (user_id, name, category_type) VALUES (?, 'Business - Software', 'expense')", (user_id,))
        cat_software = c.lastrowid
        c.execute("INSERT INTO categories (user_id, name, category_type) VALUES (?, 'Sales Income', 'income')", (user_id,))
        cat_income = c.lastrowid
        c.execute("INSERT INTO categories (user_id, name, category_type) VALUES (?, 'Auto & Travel', 'expense')", (user_id,))
        cat_auto = c.lastrowid
        conn.commit()

        print("\n--- Phase 11: Merchant Contextual Intelligence Smoke Tests ---\n")

        # --- Test A: Hierarchical Parent Inheritance ---
        print("[A] Testing Merchant Hierarchy Inheritance...")
        # 1. Create a parent brand "CHEVRON" with a default category
        parent_id = MerchantNormalizer.learn_merchant_alias(user_id, "CHEVRON CORPORATE", "CHEVRON", category_id=cat_auto)
        
        # 2. Add a new explicit store "CHEVRON 0123" without a default category, but linking to the parent
        child_id = MerchantNormalizer.learn_merchant_alias(user_id, "CHEVRON 0123", "CHEVRON 0123", category_id=None, parent_merchant_id=parent_id)
        
        # 3. Categorize a new Chevron hit 
        # (It should resolve to 'CHEVRON 0123' via alias string matching, realize it has no category, and gracefully fallback to the 'CHEVRON' auto category)
        res_hierarchy = categorize_transaction(user_id, "CHEVRON 0123", -45.00, account_id=acct_cc)
        print(f"Hierarchical Result: {res_hierarchy['category']} | Confidence: {res_hierarchy.get('categorization_confidence')}")
        assert res_hierarchy['category'] == 'Auto & Travel'
        print(">> PASS: Child inherited Parent category safely.\n")


        # --- Test B: Contextual Overrides ---
        print("[B] Testing Context-Aware Category Overrides...")
        # 1. Define AMAZON as a default 'Business - Software' expense
        amazon_id = MerchantNormalizer.learn_merchant_alias(user_id, "AMAZON WEB SERVICES", "AMAZON", category_id=cat_software)
        
        # 2. Tell the CPA Engine: "If Amazon hits a depository checking account, it's actually Income."
        add_merchant_context_rule(user_id, amazon_id, 'account_type', 'depository', mapped_category_id=cat_income, priority=80)
        
        # 3. Run Transaction 1: Credit Card (Should hit base default: Business - Software)
        res_cc = categorize_transaction(user_id, "AMAZON WEB SERVICES", -150.00, account_id=acct_cc)
        print(f"Amazon on CC Result: {res_cc['category']} | Source: {res_cc.get('categorization_source')} | Confidence: {res_cc['categorization_confidence']}")
        assert res_cc['category'] == 'Business - Software'
        print(">> PASS: Base merchant mapping held on default context.")
        
        # 4. Run Transaction 2: Checking Account (Should trip the context hook: Sales Income)
        # We need to simulate history since amount mismatch lowers confidence and we want full pass.
        for i in range(5):
             add_transaction(user_id, None, acct_bank, "2026-01-01", "2026-01-01", "AMAZON WEB SERVICES", 500.00, "credit", category="Sales Income", is_approved=1, merchant_id=amazon_id)
        
        # DEBUG: Let's dump the DB states for accounts and rules to see why the hook isn't catching
        c.execute("SELECT id, account_type FROM accounts WHERE id = ?", (acct_bank,))
        acct_row = c.fetchone()
        print(f"DEBUG Account state: {dict(acct_row) if acct_row else 'None'}")
        
        c.execute("SELECT * FROM merchant_context_rules WHERE user_id = ? AND merchant_id = ?", (user_id, amazon_id))
        print(f"DEBUG Rule state: {[dict(r) for r in c.fetchall()]}")
        
        res_bank = categorize_transaction(user_id, "AMAZON WEB SERVICES", 500.00, account_id=acct_bank)
        print(f"Amazon on Checking Result: {res_bank.get('category')} | Source: {res_bank.get('categorization_source')} | Confidence: {res_bank.get('categorization_confidence')}")
        assert res_bank.get('category') == 'Sales Income'
        assert 'context_rule' in res_bank.get('categorization_source', '')
        print(">> PASS: Context hook triggered successfully and overrode the default mapping based on account_type.\n")

if __name__ == "__main__":
    run_test()
