import sqlite3

conn = sqlite3.connect('data/forensic_audit.db')
conn.row_factory = sqlite3.Row

cursor = conn.cursor()
print("USERS:")
users = cursor.execute("SELECT id, email, role, is_demo FROM users").fetchall()
for u in users:
    print(dict(u))

print("\nDOCUMENTS:")
docs = cursor.execute("SELECT id, user_id, filename, doc_category FROM documents").fetchall()
for d in docs:
    print(dict(d))

