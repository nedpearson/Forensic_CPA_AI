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
    
    # 1. Handle User
    user = cursor.execute("SELECT id, role, password_hash FROM users WHERE email=?", (email,)).fetchone()
    user_id = None
    
    if user:
        user_id = user['id']
        print(f"User {email} already exists (ID: {user_id}, Role: {user['role']}).")
        pwd_hash = generate_password_hash(password)
        cursor.execute("UPDATE users SET password_hash=?, role='SUPER_ADMIN' WHERE email=?", (pwd_hash, email))
        print("-> Updated role to SUPER_ADMIN and reset password.")
    else:
        print(f"Creating new user {email}...")
        pwd_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            (email, pwd_hash, 'SUPER_ADMIN')
        )
        user_id = cursor.lastrowid
        print(f"-> Created SUPER_ADMIN with ID: {user_id}")

    # 2. Handle Default Company
    company_name = "Pearson Forensic Audit"
    company = cursor.execute("SELECT id FROM companies WHERE name=?", (company_name,)).fetchone()
    company_id = None
    
    if company:
        company_id = company['id']
        print(f"Company '{company_name}' already exists (ID: {company_id}).")
    else:
        print(f"Creating default company '{company_name}'...")
        cursor.execute(
            "INSERT INTO companies (name, created_by, owner_user_id) VALUES (?, ?, ?)",
            (company_name, user_id, user_id)
        )
        company_id = cursor.lastrowid
        print(f"-> Created company with ID: {company_id}")

    # 3. Handle Membership
    membership = cursor.execute(
        "SELECT id FROM company_memberships WHERE user_id=? AND company_id=?", 
        (user_id, company_id)
    ).fetchone()
    
    if membership:
        print(f"User is already a member of the company.")
        cursor.execute(
            "UPDATE company_memberships SET role='owner', is_default=1 WHERE user_id=? AND company_id=?",
            (user_id, company_id)
        )
    else:
        print(f"Linking user to company...")
        cursor.execute(
            "INSERT INTO company_memberships (user_id, company_id, role, is_default) VALUES (?, ?, ?, ?)",
            (user_id, company_id, 'owner', 1)
        )
        print(f"-> Linked user {user_id} to company {company_id} as owner.")

    conn.commit()
    conn.close()
    print("\nExtraction finished successfully. Ned should now have a default company context.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed super admin and default company on SQLite database")
    parser.add_argument('--email', default="nedpearson@gmail.com", help="Email of the super admin")
    parser.add_argument('--password', default="1Pearson2", help="Password for the super admin")
    
    args = parser.parse_args()
    seed_sqlite_admin(args.email, args.password)
