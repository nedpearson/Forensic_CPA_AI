import os
import sqlite3

def migrate():
    db_path = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), '..', 'data', 'forensic_audit.db'))
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}, skipping migration.")
        return
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Migrate 'admin' to 'SUPER_ADMIN' (or 'ADMIN' based on intent, let's use SUPER_ADMIN for old admins)
    cursor.execute("UPDATE users SET role = 'SUPER_ADMIN' WHERE role = 'admin'")
    
    # Migrate 'user' to 'USER'
    cursor.execute("UPDATE users SET role = 'USER' WHERE role = 'user'")
    conn.commit()
    conn.close()
    print("Role migration complete.")

if __name__ == "__main__":
    migrate()
