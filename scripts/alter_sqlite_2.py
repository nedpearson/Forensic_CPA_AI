import sqlite3
import secrets

# Database Alteration
conn = sqlite3.connect('/var/www/Forensic_CPA_AI/data/forensic_audit.db')
c = conn.cursor()
try:
    c.execute("ALTER TABLE sync_jobs ADD COLUMN user_id INTEGER REFERENCES users(id);")
    print("Added user_id to sync_jobs")
except sqlite3.OperationalError as e:
    print(e)
conn.commit()
conn.close()

# Env alteration
env_path = '/var/www/Forensic_CPA_AI/.env'
key_exists = False
with open(env_path, 'r') as f:
    if 'OAUTH_ENCRYPTION_KEY' in f.read():
        key_exists = True

if not key_exists:
    key = secrets.token_urlsafe(32)
    with open(env_path, 'a') as f:
        f.write(f"\nOAUTH_ENCRYPTION_KEY={key}\n")
    print("Added OAUTH_ENCRYPTION_KEY to .env")
