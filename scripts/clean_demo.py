import sqlite3

import os
db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'forensic_audit.db')
conn = sqlite3.connect(db_path)
c = conn.cursor()

# 1. Remove all QuickBooks demo transactions
c.execute("DELETE FROM transactions WHERE source_provider = 'quickbooks'")
print(f"Deleted {c.rowcount} QuickBooks demo transactions")

# 2. Disconnect QuickBooks integration (set to 'Disconnected')
c.execute("UPDATE integrations SET status = 'Disconnected', access_token = NULL, refresh_token = NULL WHERE provider = 'quickbooks'")
print(f"Disconnected {c.rowcount} QuickBooks integration(s)")

conn.commit()
conn.close()
print("Done. App is clean for the demo.")
