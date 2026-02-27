import sqlite3; conn = sqlite3.connect('data/forensic_audit.db'); conn.row_factory=sqlite3.Row; c = conn.cursor(); c.execute('SELECT * FROM users'); print([dict(r) for r in c.fetchall()])
