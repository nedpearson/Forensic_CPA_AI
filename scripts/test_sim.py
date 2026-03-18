import database_sqlite as db
import scenario_engine as se
import json

uid = db.create_demo_user(wipe_data=True)
conn = db.get_db()
c = conn.cursor()
cid = c.execute('SELECT company_id FROM company_memberships WHERE user_id = ?', (uid,)).fetchone()[0]

print(f"User ID: {uid}, Company ID: {cid}")

# Seed data
db.seed_comprehensive_demo_data(uid, cid)

# 1. Test Remediation Tasks
print("--- REMEDIATION TASKS ---")
tasks = db.get_remediation_tasks(cid)
print(f"Found {len(tasks)} tasks")
for t in tasks:
    print(t['finding_id'], t['task_description'], t['finding_title'])

# 2. Test Scenario Simulator
print("\n--- SCENARIO SIMULATOR ---")
res = se.run_simulation(cid, 'controls_remediation', {'expense_reduction_goal': 20})
print("Controls Remediation Status:", res.get('status'))
if res.get('status') == 'success':
    print("Baseline PnL:", res['baseline']['pnl'])
    print("Simulated PnL:", res['simulated']['pnl'])

res2 = se.run_simulation(cid, 'capitalization', {'target_category': 'Office Supplies', 'amount_threshold': 2000})
print("Capitalization Status:", res2.get('status'))
if res2.get('status') == 'success':
    print("Simulated Assets:", res2['simulated']['balance_sheet']['assets'])
