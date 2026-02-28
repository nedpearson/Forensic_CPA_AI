import sqlite3
import glob
import re
import sys
import os

# Add parent dir to path so we can import parsers
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parsers import parse_pdf_text, _normalize_bank_date

conn = sqlite3.connect('data/forensic_audit.db')
c = conn.cursor()

# Get all POS transactions for account 38
c.execute("SELECT id, trans_date, amount, description FROM transactions WHERE account_id=38 AND description LIKE '%POS PURCHASE%'")
db_txns = c.fetchall()

pdf_files = glob.glob('uploads/EStatement_0109_D*.pdf')
extracted_matches = []

print(f"Scanning {len(pdf_files)} checking statements for card numbers...")

for pdf in pdf_files:
    pages = parse_pdf_text(pdf)
    full_text = "\n".join(pages)
    
    blocks = full_text.split("POS PURCHASE")
    for i in range(1, len(blocks)):
        prev_lines = blocks[i-1].strip().split('\n')
        if not prev_lines: continue
        last_line = prev_lines[-1].strip()
        date_match = re.search(r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{2})$', last_line, re.IGNORECASE)
        date_str = ""
        if date_match:
            date_str = f"{date_match.group(1)} {date_match.group(2)}"
        
        # Look forward for the amount and the card digits
        next_chunk = blocks[i][:500] # look only ~500 chars ahead
        amount_match = re.search(r'(\d+\.\d{2})\s+[\d,]+\.\d{2}', next_chunk)
        card_match = re.search(r'\*+(\d{4})', next_chunk)
        
        if date_str and amount_match and card_match:
            amt = float(amount_match.group(1))
            norm_date = _normalize_bank_date(date_str, '2024')
            card_last_four = card_match.group(1)
            extracted_matches.append({
                'date': norm_date,
                'amount': -amt, # debits are negative in DB
                'card_last_four': card_last_four
            })

print(f"Extracted {len(extracted_matches)} POS matches from PDFs.")
updated = 0
not_found = 0
for ext in extracted_matches:
    found_match = False
    for row in db_txns:
        tx_id, tx_date, tx_amt, tx_desc = row
        if tx_date == ext['date'] and abs(tx_amt - ext['amount']) < 0.01:
            c.execute("UPDATE transactions SET card_last_four = ? WHERE id = ?", (ext['card_last_four'], tx_id))
            found_match = True
            updated += 1
            break # update only one if multi-match
    if not found_match:
        not_found += 1 

conn.commit()
print(f"Updated {updated} database rows securely. {not_found} could not be matched precisely.")
conn.close()
