import sys
import os

project_root = r"c:\dev\github\business\Forensic_CPA_AI"
sys.path.insert(0, project_root)

from parsers import parse_pdf_tables

pdf_path = os.path.join(project_root, "uploads", "EStatement_0109_D_20251031_000000_000.pdf")
tables = parse_pdf_tables(pdf_path)

print(f"Extracted {len(tables)} tables.")
if tables:
    for t in tables[:2]:
        print(f"--- Table from Page {t['page']} ---")
        for row in t['data'][:10]:
            print(row)
