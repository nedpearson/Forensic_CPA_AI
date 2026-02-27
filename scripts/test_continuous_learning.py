import os
os.environ['TESTING'] = 'true'
import database

def setup_db():
    db_path = 'test_learning.db'
    if os.path.exists(db_path):
        os.remove(db_path)
    database.DB_PATH = db_path
    database.init_db()

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (email, password_hash) VALUES ('test_lrn@example.com', 'has')")
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return user_id

def run_test():
    uid = setup_db()
    
    # 1. AI background task creates a weak rule (Priority 40)
    database.add_category_rule(
        user_id=uid,
        pattern="%UBER%",
        category="Travel",
        priority=40
    )
    
    rules = database.get_category_rules(uid)
    assert len(rules) == 1
    assert rules[0]['category'] == 'Travel'
    assert rules[0]['priority'] == 40
    
    # 2. User edits inline, silently soft-learning (Priority 50) and overriding
    # Simulation: suggest_rule_from_edit returned "%UBER%" -> "Transportation"
    database.add_category_rule(
        user_id=uid,
        pattern="%UBER%",
        category="Transportation",
        priority=50   # Overwrite allowed because 50 >= 40
    )
    
    rules = database.get_category_rules(uid)
    assert len(rules) == 1
    assert rules[0]['category'] == 'Transportation'
    assert rules[0]['priority'] == 50
    
    # 3. User edits another transaction to the SAME category (Transportation)
    # The system should strengthen the rule (+5)
    database.add_category_rule(
        user_id=uid,
        pattern="%UBER%",
        category="Transportation",
        priority=50 
    )
    
    rules = database.get_category_rules(uid)
    assert len(rules) == 1
    assert rules[0]['category'] == 'Transportation'
    assert rules[0]['priority'] == 55
    
    # 4. Explicit UI "Remember this choice" (Priority 100)
    database.add_category_rule(
        user_id=uid,
        pattern="%UBER%",
        category="Rideshare",
        priority=100  # Overwrite allowed because 100 >= 55
    )
    
    rules = database.get_category_rules(uid)
    assert len(rules) == 1
    assert rules[0]['category'] == 'Rideshare'
    assert rules[0]['priority'] == 100
    
    # 5. Weak AI background process comes back and tries to push "Travel" again at Priority 40
    database.add_category_rule(
        user_id=uid,
        pattern="%UBER%",
        category="Travel",
        priority=40
    )
    
    rules = database.get_category_rules(uid)
    assert len(rules) == 1
    # MUST remain Rideshare at 100. The weak 40 was rejected.
    assert rules[0]['category'] == 'Rideshare'
    assert rules[0]['priority'] == 100

    print("All Continuous Learning priority persistence checks passed!")

if __name__ == '__main__':
    run_test()
