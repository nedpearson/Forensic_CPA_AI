import psycopg2
try:
    conn = psycopg2.connect("postgresql://postgres.your-tenant-id:1236ece2b817b9c8241d204edc004911b29405978a42b7cff4e956b26a919b14@db.sisifoai.com:5432/postgres")
    cur = conn.cursor()
    cur.execute("SELECT 1;")
    print("SUCCESS: Connection to db.sisifoai.com works! SELECT 1 returned:", cur.fetchone())
    conn.close()
except Exception as e:
    print("FAILED:", e)
