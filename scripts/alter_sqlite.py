import sqlite3
conn = sqlite3.connect('/var/www/Forensic_CPA_AI/data/forensic_audit.db')
c = conn.cursor()
try:
    c.execute("ALTER TABLE transactions ADD COLUMN source_system TEXT;")
    print("Added source_system")
except sqlite3.OperationalError as e:
    print(e)
try:
    c.execute("ALTER TABLE transactions ADD COLUMN source_transaction_id TEXT;")
    print("Added source_transaction_id")
except sqlite3.OperationalError as e:
    print(e)
conn.commit()
conn.close()
