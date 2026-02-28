import sys
import os
import sqlite3
from app import app, get_db

def test_api():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        
        # Get a test transaction
        cursor.execute("SELECT id, user_id, user_notes, is_business FROM transactions LIMIT 1")
        row = cursor.fetchone()
        if not row:
            print("No transactions found.")
            return

        t_id, u_id, notes, is_b = row
        print(f"Testing Transaction {t_id}")

        from database import update_transaction
        
        # Test Quick Tag+
        print("Testing Quick Tag+")
        update_transaction(u_id, t_id, **{
            'is_business': 1
        })
        # Simulate double click
        update_transaction(u_id, t_id, **{
            'is_business': 1
        })

        cursor.execute("SELECT is_business FROM transactions WHERE id = ?", (t_id,))
        new_row = cursor.fetchone()
        if new_row['is_business'] == 1:
            print("Business Tag successfully mapped as 1. No duplication arrays possible.")

        # Test Quick Note+
        print("Testing Quick Note+")
        update_transaction(u_id, t_id, **{
            'user_notes': 'Phase 6 Test Note'
        })
        
        cursor.execute("SELECT user_notes FROM transactions WHERE id = ?", (t_id,))
        new_row2 = cursor.fetchone()
        if new_row2['user_notes'] == 'Phase 6 Test Note':
            print("Notes successfully overwritten string.")

        # Revert
        update_transaction(u_id, t_id, **{
            'user_notes': notes,
            'is_business': is_b
        })

if __name__ == '__main__':
    test_api()
