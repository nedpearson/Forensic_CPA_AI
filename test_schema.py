import sqlite3; c = sqlite3.connect('data/forensic_audit.db').cursor(); c.execute('PRAGMA table_info(companies)'); print([row[1] for row in c.fetchall()])
