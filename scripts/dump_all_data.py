import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import get_db

with app.app_context():
    conn = get_db()
    conn.row_factory = __import__('sqlite3').Row
    cursor = conn.cursor()
    cursor.execute("SELECT company_id, COUNT(*) FROM transactions GROUP BY company_id")
    rows = cursor.fetchall()
    print("Transactions per company:")
    for row in rows:
        print(f"Company ID: {row['company_id']}, Count: {row['COUNT(*)']}")
        
    cursor.execute("SELECT id, name FROM companies")
    comps = cursor.fetchall()
    print("\nCompanies in DB:")
    for comp in comps:
        print(dict(comp))
        
    cursor.execute("SELECT id, status FROM documents")
    docs = cursor.fetchall()
    print("\nDocuments in DB:")
    for d in docs:
        print(dict(d))

