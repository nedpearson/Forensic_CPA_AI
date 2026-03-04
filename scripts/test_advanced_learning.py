import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import database

def setup_db():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'test_adv_learning.db')
    if os.path.exists(db_path):
        os.remove(db_path)
    os.environ['DB_PATH'] = db_path
    database.DB_PATH = db_path
    database.init_db()

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (email, password_hash) VALUES ('test_adv@example.com', 'has')")
    cursor.execute("SELECT id FROM users WHERE email='test_adv@example.com'")
    user_id = cursor.fetchone()['id']
    conn.commit()
    conn.close()
    
    return user_id

def get_rule_state(uid, pattern):
    rules = database.get_category_rules(uid)
    for r in rules:
        if r['pattern'] == pattern:
            return r
    return None

def run_test():
    uid = setup_db()
    print("\n--- Phase 12/13: Advanced Continuous Learning Smoke Tests ---\n")
    
    pattern = "%AMAZON AWS%"
    
    # 1. AI background task creates a weak rule (Priority 40)
    database.add_category_rule(user_id=uid, pattern=pattern, category="Travel", priority=40)
    rule = get_rule_state(uid, pattern)
    assert rule['category'] == 'Travel'
    assert rule['priority'] == 40
    print("[PASS] AI initial weak rule created (Priority 40)")
    
    # 2. User edits inline (Priority 50) -> Correction jump
    # Should correct to 60 and hit_count 1
    database.add_category_rule(user_id=uid, pattern=pattern, category="Business - Software", priority=50)
    rule = get_rule_state(uid, pattern)
    assert rule['category'] == 'Business - Software'
    assert rule['priority'] == 60
    assert rule['hit_count'] == 1
    print("[PASS] User inline correction jumped priority to 60")
    
    # 3. User confirms same category 4 more times (total 5 hits)
    database.add_category_rule(user_id=uid, pattern=pattern, category="Business - Software", priority=50) # hit 2 -> 65
    rule = get_rule_state(uid, pattern)
    assert rule['priority'] == 65
    
    database.add_category_rule(user_id=uid, pattern=pattern, category="Business - Software", priority=50) # hit 3 -> 80
    rule = get_rule_state(uid, pattern)
    assert rule['priority'] == 80
    
    database.add_category_rule(user_id=uid, pattern=pattern, category="Business - Software", priority=50) # hit 4 -> 85
    rule = get_rule_state(uid, pattern)
    assert rule['priority'] == 85
    
    database.add_category_rule(user_id=uid, pattern=pattern, category="Business - Software", priority=50) # hit 5 -> 95
    rule = get_rule_state(uid, pattern)
    assert rule['priority'] == 95
    assert rule['hit_count'] == 5
    print("[PASS] Loyalty scaling pushed rule to 95 Priority (Highly Trusted)")
    
    # 4. Decay Penalty (Stability Safeguard)
    # A user makes a single passive edit (50) to a different category "Hobbies".
    # Because priority is 95 (>= 80), it should decay by 20 -> 75, but KEEP the original category.
    database.add_category_rule(user_id=uid, pattern=pattern, category="Hobbies", priority=50)
    rule = get_rule_state(uid, pattern)
    assert rule['category'] == 'Business - Software'
    assert rule['priority'] == 75
    print("[PASS] Stability Safeguard protected rule. Decayed from 95 to 75 without flipping.")
    
    # 5. Overwriting the decayed rule
    # The rule is now 75. A user edits it again to "Hobbies" (50).
    # Since 75 < 80, it will now flip and jump to 60.
    database.add_category_rule(user_id=uid, pattern=pattern, category="Hobbies", priority=50)
    rule = get_rule_state(uid, pattern)
    assert rule['category'] == 'Hobbies'
    assert rule['priority'] == 60
    assert rule['hit_count'] == 1
    print("[PASS] Faster Correction Recovery flipped the rule after repeated corrections.")
    
    # 6. Explicit Override
    # User selects "Remember this choice" (100)
    database.add_category_rule(user_id=uid, pattern=pattern, category="Explicit Category", priority=100)
    rule = get_rule_state(uid, pattern)
    assert rule['category'] == 'Explicit Category'
    assert rule['priority'] == 100
    print("[PASS] Explicit User Rule bypassed all safeguards cleanly.")
    
    # 7. AI bounce off explicit rule
    database.add_category_rule(user_id=uid, pattern=pattern, category="Trash", priority=40)
    rule = get_rule_state(uid, pattern)
    assert rule['category'] == 'Explicit Category'
    assert rule['priority'] == 100
    print("[PASS] Weak AI suggestion securely rejected by Explicit Rule.")
    
    # 8. Test Safe Autopilot Gating
    print("\n--- Testing Safe Autopilot Gating Pipeline ---")
    from categorization_pipeline import CategorizationPipeline
    
    # Process a transaction that hits a Highly Trusted rule
    database.add_category_rule(user_id=uid, pattern="%TEST_SAFE_AUTO%", category="Income", priority=85)
    # add_category_rule sets hit_count to 1 since it's a new context. Let's artificially boost it to simulate usage over time!
    conn = database.get_db()
    c = conn.cursor()
    c.execute("UPDATE category_rules SET hit_count = 5, priority = 95 WHERE pattern = '%TEST_SAFE_AUTO%'")
    conn.commit()
    conn.close()
    
    res = CategorizationPipeline.process_transaction(uid, "TEST_SAFE_AUTO 123", 100.0)
    assert res['categorization_status'] == 'auto_applied'
    assert 'Safe Autopilot Gating' in res['categorization_explanation']
    print("[PASS] Safe Autopilot successfully elevated trusted logic to auto_applied despite sparse history!")

    print("\n>>> All Advanced Learning & Review Optimization checks passed! <<<\n")

if __name__ == '__main__':
    run_test()
