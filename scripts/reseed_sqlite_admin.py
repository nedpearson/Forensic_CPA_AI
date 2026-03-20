import os
import sys
import sqlite3
import argparse
from werkzeug.security import generate_password_hash

# Set to SQLite explicitly
os.environ['DB_DIALECT'] = 'sqlite'
# Calculate the absolute path to the data folder from the script's location
DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'forensic_audit.db'))

def seed_sqlite_admin(email, password):
    print(f"Executing manual seed for {email} on SQLite DB...\nPath: {DB_PATH}")
    
    if not os.path.exists(DB_PATH):
        print(f"Error: Database file not found at {DB_PATH}")
        sys.exit(1)
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    user = cursor.execute("SELECT id, role, password_hash FROM users WHERE email=?", (email,)).fetchone()
    
    if user:
        print(f"User {email} already exists (ID: {user['id']}, Role: {user['role']}).")
        pwd_hash = generate_password_hash(password)
        cursor.execute("UPDATE users SET password_hash=?, role='SUPER_ADMIN' WHERE email=?", (pwd_hash, email))
        conn.commit()
        print("-> Updated role to SUPER_ADMIN and reset password.")
    else:
        print(f"Creating new user {email}...")
        pwd_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            (email, pwd_hash, 'SUPER_ADMIN')
        )
        new_id = cursor.lastrowid
        conn.commit()
        print(f"-> Created SUPER_ADMIN with ID: {new_id}")

    conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed super admin on SQLite database")
    parser.add_argument('--email', default="nedpearson@gmail.com", help="Email of the super admin")
    parser.add_argument('--password', default="1Pearson2", help="Password for the super admin")
    
    args = parser.parse_args()
    seed_sqlite_admin(args.email, args.password)
