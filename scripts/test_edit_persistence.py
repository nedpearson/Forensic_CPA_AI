import sys
import os
import sqlite3
from app import app, get_db

def test_api():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        
        # Get a transaction
        cursor.execute("SELECT id, user_id, category, is_personal, is_business FROM transactions LIMIT 1")
        row = cursor.fetchone()
        if not row:
            print("No transactions found.")
            return

        t_id, u_id, cat, is_p, is_b = row
        print(f"Testing Transaction {t_id}")
        print(f"Old: Cat={cat}, Personal={is_p}, Business={is_b}")

        from database import update_transaction
        
        update_transaction(u_id, t_id, **{
            'category': 'Test Category',
            'is_personal': 1 if not is_p else 0,
            'is_business': 1 if not is_b else 0
        })

        cursor.execute("SELECT category, is_personal, is_business FROM transactions WHERE id = ?", (t_id,))
        new_row = cursor.fetchone()
        print(f"New: Cat={new_row['category']}, Personal={new_row['is_personal']}, Business={new_row['is_business']}")
        
        # Reset
        update_transaction(u_id, t_id, **{
            'category': cat,
            'is_personal': is_p,
            'is_business': is_b
        })

if __name__ == '__main__':
    test_api()
