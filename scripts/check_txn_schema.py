import sqlite3

conn = sqlite3.connect('/var/www/Forensic_CPA_AI/data/forensic_audit.db')
c = conn.cursor()
c.execute("PRAGMA table_info(transactions)")
cols = [row[1] for row in c.fetchall()]
print("transactions columns:", cols)

missing = []
for col, definition in [('cardholder_name', 'TEXT'), ('company_id', 'INTEGER')]:
    if col not in cols:
        missing.append((col, definition))
        c.execute(f"ALTER TABLE transactions ADD COLUMN {col} {definition}")
        print(f"Added column: {col}")
    else:
        print(f"Column exists: {col}")

conn.commit()
conn.close()
