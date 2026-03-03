import sys
import os
import json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import get_db

with app.app_context():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT company_id, last_result_json FROM advisor_company_state')
    
    rows = cursor.fetchall()
    for row in rows:
        cid = row[0]
        json_str = row[1]
        print(f"--- Company {cid} ---")
        if json_str:
            data = json.loads(json_str)
            print(json.dumps(data.get('fraud_red_flags', []), indent=2))
        else:
            print("NO DATA")
    
    conn.close()
