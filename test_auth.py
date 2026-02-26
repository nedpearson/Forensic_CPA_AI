import requests
import json

base_url = "http://127.0.0.1:3006"
session = requests.Session()

# 1. Check health
resp = session.get(f"{base_url}/api/health")
print(f"Health: {resp.status_code} - {resp.text}")

# 2. Try fetching data without login
resp = session.get(f"{base_url}/api/transactions")
print(f"Transactions (No Auth): {resp.status_code} - {resp.text}")

# 3. Create dummy user directly in DB (if needed)
import sqlite3
import werkzeug.security
import os
db_path = os.path.join('data', 'forensic_audit.db')
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
hashed = werkzeug.security.generate_password_hash("password123")
try:
    cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", ("testuser@example.com", hashed))
    conn.commit()
    print("Test user created.")
except sqlite3.IntegrityError:
    print("Test user already exists.")
except sqlite3.OperationalError as e:
    print(f"OperationalError: {e}. Is the DB initialized?")
conn.close()

# 4. Login
login_data = {"email": "testuser@example.com", "password": "password123"}
resp = session.post(f"{base_url}/api/auth/login", json=login_data)
print(f"Login: {resp.status_code} - {resp.text}")

# 5. Fetch transactions after login
resp = session.get(f"{base_url}/api/transactions")
print(f"Transactions (Auth): {resp.status_code}")
if resp.status_code == 200:
    print(f"Loaded {len(resp.json())} transactions.")
    
# 6. Fetch stats
resp = session.get(f"{base_url}/api/stats")
print(f"Stats (Auth): {resp.status_code}")
