import os
import sqlite3
from tabulate import tabulate

db_path = os.path.join('data', 'forensic_audit.db')
if not os.path.exists(db_path):
    print(f"Database not found at {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Get all users
cursor.execute("SELECT id, email, role, is_demo FROM users ORDER BY id")
users = cursor.fetchall()

results = []
for user in users:
    uid = user['id']
    email = user['email']
    role = user['role']
    is_demo = bool(user['is_demo'])
    
    # Count transactions
    cursor.execute("SELECT COUNT(*) FROM transactions WHERE user_id = ?", (uid,))
    tx_count = cursor.fetchone()[0]
    
    # Count documents
    cursor.execute("SELECT COUNT(*) FROM documents WHERE user_id = ?", (uid,))
    doc_count = cursor.fetchone()[0]
    
    # Count categories
    cursor.execute("SELECT COUNT(*) FROM categories WHERE user_id = ?", (uid,))
    cat_count = cursor.fetchone()[0]
    
    # Count taxonomy configs
    cursor.execute("SELECT COUNT(*) FROM taxonomy_config WHERE user_id = ?", (uid,))
    tax_count = cursor.fetchone()[0]
    
    results.append([uid, email, role, is_demo, tx_count, doc_count, cat_count, tax_count])

conn.close()

headers = ["ID", "Email", "Role", "Is Demo", "Transactions", "Documents", "Categories", "Taxonomies"]
print("\n--- Forensic CPA AI Database State ---\n")
print(tabulate(results, headers=headers, tablefmt="grid"))
print("\n--------------------------------------\n")
