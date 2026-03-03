import re

def fix_database_pg():
    with open('database_pg.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # We know the exact 13 occurrences since it's from SQLite code.
    # 1. init_db()
    content = content.replace(
        'cursor.execute("INSERT INTO fcpa_users (email, password_hash) VALUES (%s, %s)", ("root@system.local", hashed))\n        root_id = cursor.lastrowid',
        'cursor.execute("INSERT INTO fcpa_users (email, password_hash) VALUES (%s, %s) RETURNING id", ("root@system.local", hashed))\n        root_id = cursor.fetchone()[\'id\']'
    )
    
    # 2. create_user()
    content = content.replace(
        'cursor.execute("INSERT INTO fcpa_users (email, password_hash, role) VALUES (%s, %s, %s)", (email, hashed, role))\n        user_id = cursor.lastrowid',
        'cursor.execute("INSERT INTO fcpa_users (email, password_hash, role) VALUES (%s, %s, %s) RETURNING id", (email, hashed, role))\n        user_id = cursor.fetchone()[\'id\']'
    )
    
    # 3. create_demo_user()
    content = content.replace(
        'cursor.execute(\n                "INSERT INTO fcpa_users (email, password_hash, is_demo) VALUES (%s, %s, 1)", \n                (email, hashed)\n            )\n            user_id = cursor.lastrowid',
        'cursor.execute(\n                "INSERT INTO fcpa_users (email, password_hash, is_demo) VALUES (%s, %s, 1) RETURNING id", \n                (email, hashed)\n            )\n            user_id = cursor.fetchone()[\'id\']'
    )
    
    # 4. add_account()
    content = content.replace(
        'cursor.execute(\n        "INSERT INTO fcpa_accounts (user_id, account_name, account_number, account_type, institution, cardholder_name, card_last_four, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",\n        (user_id, account_name, account_number, account_type, institution, cardholder_name, card_last_four, notes)\n    )\n    account_id = cursor.lastrowid',
        'cursor.execute(\n        "INSERT INTO fcpa_accounts (user_id, account_name, account_number, account_type, institution, cardholder_name, card_last_four, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",\n        (user_id, account_name, account_number, account_type, institution, cardholder_name, card_last_four, notes)\n    )\n    account_id = cursor.fetchone()[\'id\']'
    )
    
    # 5. add_document()
    content = content.replace(
        'cursor.execute(\n        "INSERT INTO fcpa_documents (user_id, filename, original_path, file_type, doc_category, account_id, statement_start_date, statement_end_date, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",\n        (user_id, filename, original_path, file_type, doc_category, account_id, statement_start, statement_end, notes)\n    )\n    doc_id = cursor.lastrowid',
        'cursor.execute(\n        "INSERT INTO fcpa_documents (user_id, filename, original_path, file_type, doc_category, account_id, statement_start_date, statement_end_date, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",\n        (user_id, filename, original_path, file_type, doc_category, account_id, statement_start, statement_end, notes)\n    )\n    doc_id = cursor.fetchone()[\'id\']'
    )
    
    # 6. add_transaction()
    content = content.replace(
        'is_flagged\', 0), kwargs.get(\'flag_reason\'),\n        kwargs.get(\'auto_categorized\', 1), kwargs.get(\'manually_edited\', 0)\n    ))\n    trans_id = cursor.lastrowid',
        'is_flagged\', 0), kwargs.get(\'flag_reason\'),\n        kwargs.get(\'auto_categorized\', 1), kwargs.get(\'manually_edited\', 0)\n    ))\n    trans_id = cursor.fetchone()[\'id\']'
    )
    content = content.replace(
        'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)\n    """',
        'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id\n    """'
    )
    
    # 7. add_note() [actually all following inserts]
    # Let's do a regex replacement for the remaining simpler ones
    
    content = re.sub(
        r'(cursor\.execute\s*\(\s*["\']INSERT INTO ([a-z_]+)\s*\((.*?)\)\s*VALUES\s*\((.*?)\)["\']\s*,\s*\((.*?)\)\s*\)\n\s*([a-zA-Z_]+)\s*=\s*cursor\.lastrowid)',
        r'cursor.execute("INSERT INTO \2 (\3) VALUES (\4) RETURNING id", (\5))\n    \6 = cursor.fetchone()[\'id\']',
        content
    )
    
    with open('database_pg.py', 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == '__main__':
    fix_database_pg()
