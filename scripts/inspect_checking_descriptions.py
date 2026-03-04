import sqlite3
import json

conn=sqlite3.connect('data/forensic_audit.db')
c=conn.cursor()
c.execute('SELECT account_name, description FROM transactions t JOIN accounts a ON t.account_id = a.id WHERE a.account_type = "Checking" OR a.account_name LIKE "%Gulf Coast%" LIMIT 100')
rows = c.fetchall()
conn.close()

results = []
for r in rows:
    results.append(f"{r[0]}: {r[1]}")
    
print(json.dumps(results[:50], indent=2))
