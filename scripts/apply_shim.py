import os
import re

db_path = "database.py"
with open(db_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Add shim injection to database.py
if "def _get_active_company_id_shim():" not in content:
    shim_code = """
def _get_active_company_id_shim():
    # TODO: Phase 4 remove this shim when all signatures explicitly pass company_id.
    try:
        from flask import session
        if session:
            return session.get('active_company_id')
    except Exception:
        pass
    return None
"""
    # Insert right after the imports
    content = content.replace("from dotenv import load_dotenv", "from dotenv import load_dotenv\n" + shim_code)


with open(db_path, "w", encoding="utf-8") as f:
    f.write(content)
print("done")
