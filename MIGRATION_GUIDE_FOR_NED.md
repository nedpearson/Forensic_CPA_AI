# Supabase (PostgreSQL) Migration Guide & Handover Notes

**To: Ned (and Ned's AI Agent)**
**From: The Migration Team**

We have successfully migrated the production environment to use a self-hosted Supabase (PostgreSQL) instance. This document outlines the architectural changes, how the new hybrid database system works, and how to continue developing without breaking the production environment.

## 🏛️ The Hybrid Architecture (The "Router")

To ensure that local development remains fast and doesn't require a local PostgreSQL setup, we implement a **Router Architecture**. The application can run on either SQLite (for local dev) or PostgreSQL (for production).

1. **`database.py` (The Router):** 
   This file no longer contains the database logic. Instead, it checks the `.env` variable `DB_DIALECT`.
   - If `DB_DIALECT=postgres`: It imports everything from `database_pg.py`.
   - If `DB_DIALECT=sqlite` (or empty): It imports everything from `database_sqlite.py`.

2. **`database_sqlite.py`:**
   This is the exact same SQLite code you have been writing. **All new database features, queries, and schema changes should be written here.**

3. **`database_pg.py`:**
   This file is **auto-generated**. It contains the exact same functions as the SQLite version but translated to PostgreSQL syntax (e.g., using `psycopg2`, `%s` instead of `?`, and `RETURNING id` instead of `lastrowid`).

## ⚙️ How to Develop New Features

You can and should continue developing locally using SQLite exactly as you always have. Your workflow does not need to change.

1. **Write your code:** Make your changes to `database_sqlite.py` and test them locally.
2. **Dynamic Migrations:** If you add new tables or use `ALTER TABLE` to add columns dynamically, write them in the `init_db()` function inside `database_sqlite.py`.
3. **Run the Converter:** Before pushing to production, you (or your agent) must run the conversion scripts to generate the PostgreSQL equivalents:
   ```bash
   python scripts/convert_db.py
   python scripts/fix_id.py
   ```
4. **Update Supabase SQL:** Supabase does not run Python's `init_db()` to create tables. We maintain a static SQL file at `scripts/supabase_schema_fcpa.sql`. If you add a new table or column, you **must** manually add it to this SQL file so the production database can be updated.

## 🛑 Critical Changes & Gotchas

* **Table Prefix:** All tables in PostgreSQL are now prefixed with `fcpa_` (e.g., `fcpa_users`, `fcpa_companies`). The `convert_db.py` script automatically handles adding this prefix to your SQLite queries.
* **`lastrowid` vs `RETURNING id`:** SQLite uses `cursor.lastrowid` to get the ID of an inserted row. PostgreSQL requires `RETURNING id`. The `fix_id.py` script automatically patches this in `database_pg.py`.
* **Closing Connections:** Always use our custom `close_db(conn)` helper instead of `conn.close()` to ensure compatibility with both the SQLite connection object and the PostgreSQL connection pool.
* **`psycopg2` vs `sqlite3` Exceptions:** The translation script automatically changes `sqlite3.IntegrityError` to `psycopg2.IntegrityError` inside `database_pg.py`.

## 🚀 Summary for Ned's AI Agent
1. Develop locally on `database_sqlite.py`.
2. Do not manually edit `database_pg.py`.
3. When schema or DB logic changes are made in `sqlite`, rerun `scripts/convert_db.py` and `scripts/fix_id.py` to sync the changes to the Postgres layer.
4. If you change the schema (new tables or columns), update `scripts/supabase_schema_fcpa.sql`.
