import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import get_db

print("Checking advisor_company_state table via Flask context...")
with app.app_context():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT status, needs_refresh FROM advisor_company_state WHERE company_id = 1")
    row = cursor.fetchone()
    
    if row:
        print(f"Company 1 State -> Status: {row['status']}, Needs Refresh: {row['needs_refresh']}")
    else:
        print("No row found for Company 1! This means the state was never initialized.")
