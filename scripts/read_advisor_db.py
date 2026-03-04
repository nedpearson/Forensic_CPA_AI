import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import get_db

print("Checking advisor_company_state directly in DB...")
with app.app_context():
    conn = get_db()
    conn.row_factory = __import__('sqlite3').Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM advisor_company_state WHERE company_id = 1")
    row = cursor.fetchone()
    
    if row:
        print(dict(row))
    else:
        print("Empty table row! State never initialized.")
