import sys
import os
import re
project_root = r"c:\dev\github\business\Forensic_CPA_AI"
sys.path.insert(0, project_root)

from parsers import parse_pdf_text

pdf_path = os.path.join(project_root, "uploads", "EStatement_0109_D_20251031_000000_000.pdf")
pages = parse_pdf_text(pdf_path)

prev_balance = None
transactions = []

# Pattern: Month Day at start of line, then description, then 1-2 amounts at end
line_pattern = re.compile(
    r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+'  # date
    r'(.+?)\s+'                                                            # description
    r'([\d,]+\.\d{2})\s+'                                                 # amount1
    r'([\d,]+\.\d{2})\s*$',                                               # balance
    re.IGNORECASE
)

for page_text in pages:
    lines = page_text.split('\n')
    for line in lines:
        line = line.strip()
        match = line_pattern.match(line)
        if match:
            print(f"Matched line: {line}")
            
# Testing a looser pattern matching the bank format
# Oct 01 POS PURCHASE NON-PIN BULLDOG BATON
print("\nTesting looser pattern:")
loose_pattern = re.compile(
    r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(.+)$', re.IGNORECASE
)

buffer = ""
for page_text in pages:
    lines = page_text.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
            
        match = loose_pattern.match(line)
        if match:
            print(f"Starts with date: {line}")
        elif buffer:
            # check if it continues a previous transaction
            pass
