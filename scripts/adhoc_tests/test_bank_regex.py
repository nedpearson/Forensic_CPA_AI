import os
import sys

project_root = r"c:\dev\github\business\Forensic_CPA_AI"
sys.path.insert(0, project_root)

# Set dummy API key to force LLM failure
os.environ["OPENAI_API_KEY"] = "bad_key"

from parsers import parse_document

def main():
    pdf_path = os.path.join(project_root, "uploads", "EStatement_0109_D_20251031_000000_000.pdf")
    if not os.path.exists(pdf_path):
        print(f"Error: PDF not found at {pdf_path}")
        return
        
    print(f"Parsing {pdf_path}...")
    transactions, account_info = parse_document(pdf_path, 'bank_statement')
    
    print(f"\nExtracted Account Info: {account_info}")
    print(f"Extracted {len(transactions)} transactions.")
    
    if len(transactions) > 0:
        print("\nFirst 3 transactions:")
        for t in transactions[:3]:
            print(f"  {t['trans_date']}: {t['description']} | Amt: {t['amount']} | Type: {t['trans_type']}")

if __name__ == "__main__":
    main()
