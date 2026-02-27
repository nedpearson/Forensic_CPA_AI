import sqlite3
conn = sqlite3.connect('data/forensic_audit.db')
conn.execute('PRAGMA foreign_keys = ON')
try:
    with conn:
        conn.executescript('''
            DELETE FROM proof_links WHERE user_id = 4;
            DELETE FROM audit_log WHERE user_id = 4;
            DELETE FROM transactions WHERE user_id = 4;
            DELETE FROM documents WHERE user_id = 4;
            DELETE FROM accounts WHERE user_id = 4;
            DELETE FROM case_notes WHERE user_id = 4;
            DELETE FROM saved_filters WHERE user_id = 4;
        ''')
        print("Success clear_all_data")
except Exception as e:
    import traceback
    traceback.print_exc()
