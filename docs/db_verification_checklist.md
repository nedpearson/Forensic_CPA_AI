# DB Verification Checklist

This checklist provides the necessary queries to verify that the phase 1 multi-tenant structures were applied correctly, and that existing un-scoped queries (which the legacy app currently relies on) still function without breaking.

## 1. Schema Verification

Ensure the new tables were created properly:

```sql
SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users', 'cases');
-- Expected: Both 'users' and 'cases' should be returned.
```

Verify that domain tables received the `user_id` and `case_id` additions (e.g., the `transactions` table):

```sql
PRAGMA table_info(transactions);
-- Expected: You should see `user_id` and `case_id` listed without any NOT NULL constraints.
-- Nullable constraints ensure legacy data inserts without these scopes do not crash the DB until we are ready.
```

## 2. Data Integrity & Backfill Verification

Check that the default demo user and case were provisioned:

```sql
SELECT id, email, role, is_demo FROM users WHERE id = 1;
-- Expected: 1 | demo@forensiccpa.ai | admin | 1

SELECT id, name FROM cases WHERE id = 1;
-- Expected: 1 | Default Audit Case
```

Check that existing records properly inherited `user_id = 1` and `case_id = 1`:

```sql
SELECT count(*) FROM transactions WHERE user_id IS NULL;
-- Expected: 0 (All records should have been backfilled)

SELECT count(*) FROM accounts WHERE user_id = 1;
-- Expected: Non-zero (assuming there were existing accounts before the script ran)
```

## 3. Legacy Application Compatibility

The ultimate test for phase 1 is that **no existing queries broke**. The application's `app.py` or legacy `database.py` functions currently do not look for `user_id`. Because the column is nullable and we haven't dropped any existing constraints, the current queries will simply continue returning all rows.

```sql
-- Legacy style query the app still runs:
SELECT count(*) FROM transactions;
-- Expected: This should succeed and return the exact same count as before the migration.
```

## Automated Verification

You can run the included PowerShell script to automate these checks:

```powershell
.\scripts\verify_db.ps1 -DbPath "data\forensic_audit.db"
```

## Reversing the Migration

If any legacy query breaks unexpectedly due to these structural additions, you can cleanly revert the database back to its exact pre-migration state using the `down` script:

```powershell
.\scripts\migrate.ps1 -Direction down -DbPath "data\forensic_audit.db"
```

## Next Steps

Once the schema migration is fully verified locally using these queries, we can move on to **Phase 2**, which will involve safely updating the application runtime logic to dynamically filter by `user_id` on every query explicitly (`WHERE user_id = ?`).
