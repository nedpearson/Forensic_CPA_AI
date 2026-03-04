import os
import sys

from app import app
from parsers import parse_pdf_text, parse_bank_statement
import zipfile

zip_path = r'C:\dev\github\business\Forensic_CPA_AI\uploads\EStatement_Bulk_Out_70660fa3-3aeb-4ce0-98d3-c303f1bad663_3.zip'
extracted_dir = zip_path + '_test_extracted_new2'

os.makedirs(extracted_dir, exist_ok=True)

try:
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extracted_dir)
        
    for root, _, inner_files in os.walk(extracted_dir):
        for f in inner_files:
            if f.startswith('._') or '__MACOSX' in root:
                continue
            if not f.lower().endswith('.pdf'):
                continue
                
            f_path = os.path.join(root, f)
            print(f'\n--- Processing {f} ---')
            try:
                # 1. Test OCR directly
                print("Running OCR / Text Extraction...")
                pages = parse_pdf_text(f_path)
                full_text = "\n".join(pages)
                print(f"Extracted {len(full_text)} characters.")
                
                if len(full_text) < 100:
                    print(f"Warning: Very little text extracted. OCR might have failed.")
                    print(f"Sample: {full_text[:200]}")
                else:
                    print("Text extraction succeeded. Running LLM categorization...")
                    # 2. Test LLM parsing
                    t, ai = parse_bank_statement(f_path)
                    print(f'LLM returned {len(t) if t else 0} transactions.')
                    if t:
                        print('First transaction:', t[0])
            except Exception as e:
                print(f'Failed to parse: {e}')
            
            # just test the first PDF
            break
            
except Exception as e:
    print(f'Fatal error: {e}')
