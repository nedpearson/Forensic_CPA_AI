import sys
from app import app
from parsers import parse_bank_statement

f_path = r'C:\dev\github\business\Forensic_CPA_AI\uploads\EStatement_Bulk_Out_70660fa3-3aeb-4ce0-98d3-c303f1bad663_3_test_extracted_auto\EStatement_0109_D_20250331_000000_000.pdf'
t, ai = parse_bank_statement(f_path)
print('Transactions:', len(t))
print('Account Info:', ai)
