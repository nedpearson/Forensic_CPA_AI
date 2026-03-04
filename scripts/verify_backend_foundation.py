import os
os.environ['TESTING'] = 'true'
os.environ['FLASK_APP'] = 'app.py'

from database import init_db, get_db

init_db()

try:
    from database import add_transaction
    trans_id, _ = add_transaction(
        user_id=1, doc_id=None, account_id=None, 
        trans_date='2026-02-27', post_date='2026-02-27', 
        description='TEST MERCHANT', amount=-10.0, trans_type='debit', 
        category='Uncategorized', subcategory=None,
        merchant_id=None, 
        categorization_confidence=0.92,
        categorization_source='ai_inference',
        categorization_status='suggested',
        categorization_explanation='Decided by LLM context'
    )
    print(f"Successfully added test transaction with ID {trans_id}")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT categorization_confidence, categorization_source FROM transactions WHERE id = ?", (trans_id,))
    t = cursor.fetchone()
    if t:
        print(f"Retrieved: confidence={t[0]}, source={t[1]}")
    else:
        print("Failed to retrieve transaction.")
except Exception as e:
    print(f"Error testing transactions interface: {e}")
