import sys
import os

project_root = r"c:\dev\github\business\Forensic_CPA_AI"
sys.path.insert(0, project_root)

from parsers import parse_document

pdf_path = os.path.join(project_root, "uploads", "Statement_022026_6248.pdf")
print("Parsing Capital One PDF...")
# 'auto' should classify it as 'credit_card' after my fix
transactions, account_info = parse_document(pdf_path, 'auto')

print(f"\nAccount Info: {account_info}")
print(f"Extracted {len(transactions)} transactions.")
for t in transactions[:3]:
    print(t)
