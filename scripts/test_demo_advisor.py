import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import get_db
import json
from advisor_service import get_advisor_aggregation_payload
from advisor_orchestrator import run_advisor_orchestration

with app.app_context():
    conn = get_db()
    conn.row_factory = __import__('sqlite3').Row
    cursor = conn.cursor()
    
    # 1. Get Demo user ID
    cursor.execute("SELECT id FROM users WHERE email = 'demo@forensiccpa.ai'")
    demo_user = cursor.fetchone()
    if not demo_user:
        print("Demo user not found!")
        sys.exit(1)
    
    user_id = demo_user['id']
    
    # 2. Get Demo Workspace company ID
    cursor.execute("SELECT id, name FROM companies WHERE owner_user_id = ? AND name = 'Demo''s Workspace'", (user_id,))
    comp = cursor.fetchone()
    if comp:
        company_id = comp['id']
        print(f"Found Demo Workspace: ID {company_id}")
    else:
        print("Demo Workspace not found, falling back to ID 2 (from dump)")
        company_id = 2
        
    print(f"Executing aggregation payload for User {user_id}, Company {company_id}...")
    
    payload = get_advisor_aggregation_payload(user_id, company_id)
    
    print("----- PAYLOAD STATS -----")
    print(f"Transactions (Flagged): {len(payload.get('flagged_transactions', []))}")
    print("Analytics block:")
    print(json.dumps(payload.get('analytics', {}), indent=2))
    
    print("\n----- ORCHESTRATOR OUTPUT -----")
    results = run_advisor_orchestration(payload)
    print(json.dumps(results.get('executive_summary', {}), indent=2))

