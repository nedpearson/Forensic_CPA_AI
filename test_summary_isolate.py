import app
from database import get_summary_stats, get_accounts

with app.app.test_request_context():
    stats_demo = get_summary_stats(2) # Assume ID 2 or 3 is the demo
    # We shouldn't crash
    acc_demo = get_accounts(2)
    print("Demo Accounts:", acc_demo)
    
    stats_admin = get_summary_stats(1) # ID 1 is nedpearson
    acc_admin = get_accounts(1)
    
    # Are demo accounts bleeding into admin? Let's see if 1 has 2's accounts
    # After fixing they shouldn't share
    a_demo_ids = [a['id'] for a in acc_demo]
    a_admin_ids = [a['id'] for a in acc_admin]
    intersect = set(a_demo_ids).intersection(set(a_admin_ids))
    print("Intersection Accounts:", intersect)
