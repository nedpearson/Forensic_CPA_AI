import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import database

conn = database.get_db()
c = conn.cursor()
c.execute("UPDATE company_memberships SET role = ? WHERE user_id = ?", ("admin", 2))
conn.commit()
print("Demo user promoted to ADMIN")
