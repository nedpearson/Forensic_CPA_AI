import os
os.environ['TESTING'] = 'true'
import json
from database import init_db, get_db
from merchant_normalizer import MerchantNormalizer
from categorizer import categorize_transaction

def setup_db():
    try:
        if os.path.exists('test_pipeline.db'):
            os.remove('test_pipeline.db')
    except:
        pass
    os.environ['SQLITE_DB_PATH'] = 'test_pipeline.db'
    init_db()

    conn = get_db()
    cursor = conn.cursor()
    # Insert dummy user
    cursor.execute("INSERT OR IGNORE INTO users (email, password_hash) VALUES ('test_new@example.com', 'has')")
    cursor.execute("SELECT id FROM users WHERE email = 'test_new@example.com'")
    user_id = cursor.fetchone()['id']
    
    # Insert dummy categories
    cursor.execute("INSERT INTO categories (user_id, name) VALUES (?, 'Automotive')", (user_id,))
    cat_auto = cursor.lastrowid
    cursor.execute("INSERT INTO categories (user_id, name) VALUES (?, 'Business Services')", (user_id,))
    cat_bus = cursor.lastrowid
    
    conn.commit()
    conn.close()
    return user_id, cat_auto, cat_bus

def test_merchant_normalizer():
    assert MerchantNormalizer.clean_raw_string("POS PURCHASE WITH PIN CHEVRON #1234") == "CHEVRON"
    assert MerchantNormalizer.clean_raw_string("TST* WILLIES 800-555-1234") == "TST* WILLIES"
    assert MerchantNormalizer.clean_raw_string("SQ *LOCAL CAFE") == "SQ* LOCAL CAFE"
    assert MerchantNormalizer.clean_raw_string("RECURRING PAYMENT AUTHORIZED ON 12/31 NETFLIX") == "NETFLIX"
    print("OK Normalizer String Cleaning Tests Passed")

def test_pipeline_alias(user_id, cat_auto):
    m_id = MerchantNormalizer.learn_merchant_alias(
        user_id=user_id,
        raw_desc="POS PURCHASE CHEVRON #1234",
        canonical_name="Chevron Corporation",
        category_id=cat_auto,
        is_business=1
    )
    result = categorize_transaction(user_id, "POS PURCHASE NON-PIN CHEVRON", 45.0)
    assert result['category'] == 'Automotive', f"Expected Automotive, got {result['category']}"
    assert result['categorization_source'] == 'learned_rule', f"Source was {result['categorization_source']}"
    assert result['is_business'] == 1, "Expected is_business=1 to carry over from merchant"
    print("OK Pipeline strictly honored User Learned Alias (Precedence 2)")

def test_pipeline_rule(user_id, cat_bus):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO category_rules (user_id, pattern, category, priority) VALUES (?, '%AWS%', 'Business Services', 10)", (user_id,))
    conn.commit()
    conn.close()
    
    result = categorize_transaction(user_id, "AWS CLOUD STARTUP", 10.0)
    assert result['category'] == 'Business Services', f"Expected Business Services, got {result['category']}"
    assert result['categorization_source'] == 'deterministic_rule'
    print("OK Pipeline properly fell back to Deterministic SQL Rule (Precedence 3)")

if __name__ == '__main__':
    test_merchant_normalizer()
    uid, cat_auto, cat_bus = setup_db()
    test_pipeline_alias(uid, cat_auto)
    test_pipeline_rule(uid, cat_bus)
    print("ALL TESTS PASSED: Merchant Normalization and Deterministic Pipeline")
