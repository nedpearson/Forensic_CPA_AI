import sys
import os
import sqlite3
from app import app, get_db

def test_api():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, user_id FROM transactions LIMIT 1")
        test_row = cursor.fetchone()
        if not test_row:
            print("No real DB transactions found. Test 1 aborted.")
            return

        test_t_id, correct_u_id = test_row

        from database import get_transactions
        # pass empty filters explicitly simulating blank query injection
        all_txns = get_transactions(user_id=correct_u_id, filters=None)
        all_txns_empty_dict = get_transactions(user_id=correct_u_id, filters={})

        if len(all_txns) > 0 and len(all_txns) == len(all_txns_empty_dict):
            print(f"Test 1 PASS: Blank filters safely fetch all transactions ({len(all_txns)} total).")
        else:
            print(f"Test 1 FAIL: TotalDB={len(all_txns)}, FilterEmpty={len(all_txns_empty_dict)}")


        # Test 2: Cross-user Leakage Checks
        cursor.execute("INSERT INTO users (email, password_hash) VALUES ('testleak@example.com', 'x')")
        user2_id = cursor.lastrowid
        cursor.execute("INSERT INTO transactions (user_id, created_at, document_id, trans_date, amount, trans_type, description) VALUES (?, datetime('now'), NULL, '2023-01-01', 10.0, 'expense', 'Leak Test')", (user2_id,))
        leak_t_id = cursor.lastrowid
        conn.commit()

        u1_txns = get_transactions(user_id=correct_u_id, filters=None)
        leak_found = any(t['id'] == leak_t_id for t in u1_txns)

        if not leak_found:
            print("Test 2 PASS: Cross-user leakage prevented natively for default queries.")
        else:
            print(f"Test 2 FAIL: User 1 could see User 2's transaction id {leak_t_id}.")
            
        cursor.execute("DELETE FROM transactions WHERE id = ?", (leak_t_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user2_id,))
        conn.commit()


if __name__ == '__main__':
    test_api()
