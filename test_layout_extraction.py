import sys
import os
import pdfplumber

project_root = r"c:\dev\github\business\Forensic_CPA_AI"
sys.path.insert(0, project_root)

pdf_path = os.path.join(project_root, "uploads", "EStatement_0109_D_20251031_000000_000.pdf")

print("Extracting with layout=True...")
pages = []
with pdfplumber.open(pdf_path) as pdf:
    for page in pdf.pages[:3]:
        text = page.extract_text(layout=True)
        if text:
            pages.append(text)

with open(r"c:\dev\github\business\Forensic_CPA_AI\pdf_dump_layout.txt", "w", encoding="utf-8") as f:
    f.write("\n\n---PAGE---\n\n".join(pages))

print("Dumped first 3 pages with layout=True to pdf_dump_layout.txt")
