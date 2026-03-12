import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
from database import get_db

conn = get_db()
c = conn.cursor()
c.execute("ALTER TABLE fcpa_transactions ADD COLUMN IF NOT EXISTS source_system TEXT;")
c.execute("ALTER TABLE fcpa_transactions ADD COLUMN IF NOT EXISTS source_transaction_id TEXT;")
conn.commit()
print("ALTER TABLE executed successfully.")
