import os
import sys
from dotenv import load_dotenv
load_dotenv()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from parsers import parse_document, parse_pdf_text

def test_all_pdfs():
    uploads_dir = os.path.join(PROJECT_ROOT, 'uploads')
    found_any = False
    for filename in os.listdir(uploads_dir):
        if not filename.lower().endswith('.pdf'):
            continue
        pdf_path = os.path.join(uploads_dir, filename)
        try:
            pages = parse_pdf_text(pdf_path)
            full_text = "\n".join(pages).upper() if pages else ""
            if "POS PURCHASE" in full_text or "DEPOSIT" in full_text:
                print(f"Found candidate: {filename}")
                transactions, account_info = parse_document(pdf_path, 'bank_statement')
                print(f"Transactions found: {len(transactions)}")
                if len(transactions) > 0:
                    for i, t in enumerate(transactions[:5]):
                        print(f"[{i}] {t}")
                    found_any = True
                    break
                else:
                    lines = pages[0].split('\n')
                    print(f"Raw text preview (first 10 lines):")
                    for i, line in enumerate(lines[:10]):
                        print(f"  {i}: {line}")
        except Exception as e:
            pass

    if not found_any:
        print("No transactions were found in any candidate PDF.")

if __name__ == "__main__":
    test_all_pdfs()
