import os
from database import init_db, create_user, get_categories, get_category_rules, delete_category, delete_category_rule

# Initialize DB connection and schema
init_db()

# Create a fresh user
test_email = "test_seed_" + os.urandom(4).hex() + "@example.com"
user_id = create_user(test_email, "password123")
print(f"Created new user {test_email} with ID {user_id}")

# Fetch their seeded categories and rules
cats = get_categories(user_id)
rules = get_category_rules(user_id)

print(f"Categories seeded: {len(cats)}")
print(f"Rules seeded: {len(rules)}")

if len(cats) > 0:
    print(f"Sample category: {cats[0]['name']}")
    
if len(rules) > 0:
    print(f"Sample rule: {rules[0]['pattern']} -> {rules[0]['category']}")

# Test deletions
if len(cats) > 0:
    cat_id_to_delete = cats[0]['id']
    delete_category(user_id, cat_id_to_delete)
    cats_after = get_categories(user_id)
    print(f"Categories after deleting one: {len(cats_after)}")

if len(rules) > 0:
    rule_id_to_delete = rules[0]['id']
    delete_category_rule(user_id, rule_id_to_delete)
    rules_after = get_category_rules(user_id)
    print(f"Rules after deleting one: {len(rules_after)}")
