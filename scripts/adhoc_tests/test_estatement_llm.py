import sys
import os

project_root = r"c:\dev\github\business\Forensic_CPA_AI"
sys.path.insert(0, project_root)

from parsers import parse_document

pdf_path = os.path.join(project_root, "uploads", "EStatement_0109_D_20251031_000000_000.pdf")
print("Parsing EStatement PDF with LLM...")
transactions, account_info = parse_document(pdf_path, 'bank_statement')

print(f"\nAccount Info: {account_info}")
print(f"Extracted {len(transactions)} transactions.")
for t in transactions[:3]:
    print(t)
