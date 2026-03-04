import os

dialect = os.environ.get('DB_DIALECT', 'sqlite').lower()

if dialect == 'postgres':
    from database_pg import *
    from database_pg import close_db
else:
    from database_sqlite import *
    from database_sqlite import close_db
