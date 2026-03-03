import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import get_db

with app.app_context():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM transactions WHERE company_id = 1")
    count = cursor.fetchone()[0]
    print(f"Total Transactions for Company 1: {count}")
    
    cursor.execute("SELECT COUNT(*) FROM accounts WHERE company_id = 1")
    count_acc = cursor.fetchone()[0]
    print(f"Total Accounts for Company 1: {count_acc}")

    cursor.execute("SELECT COUNT(*) FROM documents WHERE company_id = 1")
    count_doc = cursor.fetchone()[0]
    print(f"Total Documents for Company 1: {count_doc}")
