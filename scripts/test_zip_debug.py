from app import app
from parsers import parse_document
import zipfile
import os

zip_path = r'C:\dev\github\business\Forensic_CPA_AI\uploads\EStatement_Bulk_Out_70660fa3-3aeb-4ce0-98d3-c303f1bad663_3.zip'
extracted_dir = zip_path + '_test_extracted'

try:
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extracted_dir)
        
    for root, _, inner_files in os.walk(extracted_dir):
        for f in inner_files:
            if f.startswith('._') or '__MACOSX' in root:
                continue
            f_path = os.path.join(root, f)
            print(f'\\n--- Processing {f} ---')
            try:
                t, ai = parse_document(f_path, 'bank_statement')
                print(f'Transactions extracted: {len(t) if t else 0}')
                if t:
                    print(t[0])
            except Exception as e:
                print(f'Failed to parse: {e}')
except Exception as e:
    print(f'Fatal error: {e}')
