import os
import re

project_root = r"c:\dev\github\business\Forensic_CPA_AI"
dump_path = os.path.join(project_root, "pdf_dump_bank.txt")

with open(dump_path, "r", encoding="utf-8") as f:
    text = f.read()

pages = text.split("\n\n---PAGE---\n\n")

print("Testing loose pattern on text dump:")
loose_pattern = re.compile(
    r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(.+)$', re.IGNORECASE
)

for p_num, page_text in enumerate(pages):
    lines = page_text.split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        match = loose_pattern.match(line)
        if match:
            print(f"Page {p_num+1} Match: {line}")
