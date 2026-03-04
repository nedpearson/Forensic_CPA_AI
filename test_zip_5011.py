import os
import sys

from app import app
from parsers import parse_document, parse_pdf_text
import zipfile
from dotenv import load_dotenv
load_dotenv()

zip_path = r'C:\dev\github\business\Forensic_CPA_AI\uploads\EStatement_Bulk_Out_50115c27-31af-46b3-b469-70e444a83a43_11.zip'
extracted_dir = zip_path + '_test_extracted_auto'

os.makedirs(extracted_dir, exist_ok=True)

try:
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extracted_dir)
    total_transactions = 0
    for root, _, inner_files in os.walk(extracted_dir):
        for f in inner_files:
            if f.startswith('._') or '__MACOSX' in root:
                continue
            if not f.lower().endswith('.pdf'):
                continue
                
            f_path = os.path.join(root, f)
            print(f'\n--- Processing {f} using "auto" ---')
            try:
                t, ai = parse_document(f_path, 'auto')
                print(f'LLM returned {len(t) if t else 0} transactions.')
                total_transactions += len(t) if t else 0
            except Exception as e:
                print(f'Failed to parse inner zip file {f}: {e}')
                    
    print(f"\nTotal transactions extracted across all files: {total_transactions}")
except Exception as e:
    print(f'Fatal error: {e}')
