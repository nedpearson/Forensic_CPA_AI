import sys
import os
import json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import get_db

with app.app_context():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT last_result_json FROM advisor_company_state WHERE company_id=2')
    row = cursor.fetchone()
    if row and row[0]:
        try:
            data = json.loads(row[0])
            print(json.dumps(data, indent=2)[:20000] + "...\n[TRUNCATED]")
        except Exception as e:
            print("JSON Error:", e)
    else:
        print("NO DATA")

    cursor.execute("UPDATE advisor_company_state SET needs_refresh=1, status='queued' WHERE company_id=2")
    conn.commit()
    print("Updated Database state to force refresh!")
