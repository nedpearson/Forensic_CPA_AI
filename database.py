import os

dialect = os.environ.get('DB_DIALECT', 'sqlite').lower()

if dialect == 'postgres':
    from database_pg import *
else:
    from database_sqlite import *
