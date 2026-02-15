"""
Document parsers for bank statements, credit card statements, Venmo exports, Excel, and Word.
Extracts transactions from uploaded PDFs and spreadsheets.
"""
import re
import os
import pdfplumber
import pandas as pd
from datetime import datetime
from openpyxl import load_workbook
from docx import Document as DocxDocument


def parse_pdf_text(filepath):
    """Extract all text from a PDF file, page by page."""
    pages = []
    with pdfplumber.open(filepath) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                pages.append(text)
    return pages


def parse_pdf_tables(filepath):
    """Extract tables from a PDF file."""
    all_tables = []
    with pdfplumber.open(filepath) as pdf:
        for i, page in enumerate(pdf.pages):
            tables = page.extract_tables()
            for table in tables:
                all_tables.append({'page': i + 1, 'data': table})
    return all_tables


# --- Bank of St. Francisville Statement Parser ---

def parse_bank_statement(filepath):
    """Parse Bank of St. Francisville PDF statements."""
    pages = parse_pdf_text(filepath)
    full_text = "\n".join(pages)

    transactions = []
    account_info = {
        'institution': 'Bank of St. Francisville',
        'account_type': 'bank',
        'account_number': '',
        'statement_start': '',
        'statement_end': '',
    }

    # Try to extract account number
    acct_match = re.search(r'Account\s*(?:Number|#|No\.?)[:\s]*(\d+)', full_text, re.IGNORECASE)
    if acct_match:
        account_info['account_number'] = acct_match.group(1)

    # Try to find statement date range
    date_match = re.search(r'(\w+\s+\d{1,2},?\s+\d{4})\s*(?:through|to|-)\s*(\w+\s+\d{1,2},?\s+\d{4})', full_text, re.IGNORECASE)
    if date_match:
        account_info['statement_start'] = date_match.group(1)
        account_info['statement_end'] = date_match.group(2)

    # Parse transaction lines - bank statements typically have date, description, amount patterns
    # Pattern: date followed by description and amount
    trans_pattern = re.compile(
        r'(\d{1,2}[/-]\d{1,2}(?:[/-]\d{2,4})?)\s+'   # date
        r'(.+?)\s+'                                      # description
        r'(-?\$?[\d,]+\.\d{2})\s*'                       # amount
        r'(\$?[\d,]+\.\d{2})?',                          # optional balance
        re.MULTILINE
    )

    # Also try: Mon DD  Description  Amount  Balance
    alt_pattern = re.compile(
        r'(\w{3}\s+\d{1,2})\s+'                          # date like "Aug 01"
        r'(.+?)\s+'                                       # description
        r'(-?\$?[\d,]+\.\d{2})\s*'                        # amount
        r'(\$?[\d,]+\.\d{2})?',                           # optional balance
        re.MULTILINE
    )

    for page_text in pages:
        lines = page_text.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Skip header/footer lines
            if any(skip in line.upper() for skip in ['PAGE ', 'ACCOUNT SUMMARY', 'PREVIOUS BALANCE', 'NEW BALANCE', 'PAYMENT DUE', 'BILLING CYCLE']):
                continue

            # Try primary pattern
            match = trans_pattern.search(line)
            if not match:
                match = alt_pattern.search(line)

            if match:
                date_str = match.group(1)
                desc = match.group(2).strip()
                amount_str = match.group(3).replace('$', '').replace(',', '')

                # Skip if description looks like a header
                if desc.upper() in ['DESCRIPTION', 'TRANS DATE', 'POST DATE']:
                    continue

                try:
                    amount = float(amount_str)
                except ValueError:
                    continue

                # Determine if debit or credit based on context
                trans_type = 'debit' if amount < 0 or 'DEBIT' in line.upper() else 'credit'
                if 'DEPOSIT' in desc.upper():
                    trans_type = 'deposit'
                    if amount < 0:
                        amount = abs(amount)

                transactions.append({
                    'trans_date': date_str,
                    'post_date': date_str,
                    'description': desc,
                    'amount': amount,
                    'trans_type': trans_type,
                    'cardholder_name': '',
                    'card_last_four': '',
                    'payment_method': 'debit',
                })

    return transactions, account_info


# --- Capital One Credit Card Statement Parser ---

def parse_capital_one_statement(filepath):
    """Parse Capital One Spark Cash Plus credit card PDF statements."""
    pages = parse_pdf_text(filepath)
    full_text = "\n".join(pages)

    transactions = []
    account_info = {
        'institution': 'Capital One',
        'account_type': 'credit_card',
        'account_number': '',
        'account_name': '',
        'statement_start': '',
        'statement_end': '',
    }

    # Extract account ending number
    acct_match = re.search(r'ending in (\d{4})', full_text)
    if acct_match:
        account_info['account_number'] = acct_match.group(1)

    # Extract billing cycle dates
    cycle_match = re.search(r'(\w{3}\s+\d{1,2},?\s+\d{4})\s*-\s*(\w{3}\s+\d{1,2},?\s+\d{4})', full_text)
    if cycle_match:
        account_info['statement_start'] = cycle_match.group(1)
        account_info['statement_end'] = cycle_match.group(2)

    # Extract cardholder name from header
    name_match = re.search(r'(GERALD T PEARSON|JAMES HENDRICK)', full_text)
    if name_match:
        account_info['account_name'] = name_match.group(1)

    # Parse transactions by cardholder section
    # Capital One statements group transactions under each cardholder
    current_cardholder = ''
    current_card = ''
    current_section = ''  # 'payments' or 'transactions'

    for page_text in pages:
        lines = page_text.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Detect cardholder section headers
            cardholder_match = re.match(r'([\w\s]+?)\s*#(\d{4}):\s*(Payments.*|Transactions)', line)
            if cardholder_match:
                current_cardholder = cardholder_match.group(1).strip()
                current_card = cardholder_match.group(2)
                section_type = cardholder_match.group(3)
                current_section = 'payment' if 'Payment' in section_type else 'transaction'
                continue

            # Skip headers
            if line.startswith('Trans Date') or line.startswith('Description'):
                continue

            # Parse transaction lines: "Mon DD  Mon DD  Description  $Amount"
            trans_match = re.match(
                r'(\w{3}\s+\d{1,2})\s+(\w{3}\s+\d{1,2})\s+(.+?)\s+\$?([\d,]+\.\d{2})\s*$',
                line
            )
            if not trans_match:
                # Try: "Mon DD  Mon DD  Description  -$Amount"
                trans_match = re.match(
                    r'(\w{3}\s+\d{1,2})\s+(\w{3}\s+\d{1,2})\s+(.+?)\s+-?\$?([\d,]+\.\d{2})\s*$',
                    line
                )

            if trans_match:
                trans_date = trans_match.group(1)
                post_date = trans_match.group(2)
                desc = trans_match.group(3).strip()
                amount_str = trans_match.group(4).replace(',', '')

                try:
                    amount = float(amount_str)
                except ValueError:
                    continue

                # Payments/credits are positive (reduce balance), charges are negative
                if current_section == 'payment':
                    trans_type = 'payment'
                    amount = amount  # credit
                else:
                    trans_type = 'debit'
                    amount = -amount  # charge

                # Check for fees
                if 'FEE' in desc.upper():
                    trans_type = 'fee'
                    amount = -abs(amount)

                transactions.append({
                    'trans_date': trans_date,
                    'post_date': post_date,
                    'description': desc,
                    'amount': amount,
                    'trans_type': trans_type,
                    'cardholder_name': current_cardholder,
                    'card_last_four': current_card,
                    'payment_method': 'credit',
                })

    # Also parse the Fees section at the bottom
    fees_section = re.search(r'Fees\s*\n(.*?)(?:Total Fees|$)', full_text, re.DOTALL)
    if fees_section:
        fee_lines = fees_section.group(1).strip().split('\n')
        for line in fee_lines:
            fee_match = re.match(
                r'(\w{3}\s+\d{1,2})\s+(\w{3}\s+\d{1,2})\s+(.+?)\s+\$?([\d,]+\.\d{2})',
                line.strip()
            )
            if fee_match:
                # Check if this fee was already added
                desc = fee_match.group(3).strip()
                amt = float(fee_match.group(4).replace(',', ''))
                already_exists = any(
                    t['description'] == desc and abs(t['amount']) == amt
                    for t in transactions
                )
                if not already_exists:
                    transactions.append({
                        'trans_date': fee_match.group(1),
                        'post_date': fee_match.group(2),
                        'description': desc,
                        'amount': -amt,
                        'trans_type': 'fee',
                        'cardholder_name': '',
                        'card_last_four': account_info.get('account_number', ''),
                        'payment_method': 'credit',
                    })

    return transactions, account_info


# --- Venmo Statement Parser ---

def parse_venmo_statement(filepath):
    """Parse Venmo CSV or PDF exports."""
    ext = os.path.splitext(filepath)[1].lower()

    if ext == '.csv':
        return parse_venmo_csv(filepath)
    elif ext == '.pdf':
        return parse_venmo_pdf(filepath)
    elif ext in ('.xlsx', '.xls'):
        return parse_venmo_excel(filepath)
    return [], {}


def parse_venmo_csv(filepath):
    """Parse Venmo CSV export."""
    df = pd.read_csv(filepath, skiprows=lambda x: x < 2 if x < 5 else False)
    transactions = []

    # Venmo CSV columns vary but typically include: ID, Datetime, Type, Status, Note, From, To, Amount
    for _, row in df.iterrows():
        try:
            amount_str = str(row.get('Amount (total)', row.get('Amount', '0')))
            amount_str = amount_str.replace('$', '').replace(',', '').replace('+', '').replace(' ', '')
            if not amount_str or amount_str == 'nan':
                continue
            amount = float(amount_str)

            desc_parts = []
            if pd.notna(row.get('Type')):
                desc_parts.append(str(row['Type']))
            if pd.notna(row.get('From')):
                desc_parts.append(f"From: {row['From']}")
            if pd.notna(row.get('To')):
                desc_parts.append(f"To: {row['To']}")
            if pd.notna(row.get('Note')):
                desc_parts.append(str(row['Note']))

            date_str = str(row.get('Datetime', row.get('Date', '')))

            transactions.append({
                'trans_date': date_str,
                'post_date': date_str,
                'description': ' | '.join(desc_parts) if desc_parts else 'Venmo Transaction',
                'amount': amount,
                'trans_type': 'credit' if amount > 0 else 'debit',
                'cardholder_name': str(row.get('From', '')) if amount > 0 else str(row.get('To', '')),
                'card_last_four': '',
                'payment_method': 'venmo',
            })
        except (ValueError, TypeError):
            continue

    account_info = {
        'institution': 'Venmo',
        'account_type': 'venmo',
        'account_number': 'venmo',
    }
    return transactions, account_info


def parse_venmo_excel(filepath):
    """Parse Venmo data from Excel export."""
    df = pd.read_excel(filepath)
    # Reuse CSV logic since structure is similar
    transactions = []
    for _, row in df.iterrows():
        try:
            amount = 0
            for col in df.columns:
                if 'amount' in col.lower():
                    val = str(row[col]).replace('$', '').replace(',', '').replace('+', '')
                    if val and val != 'nan':
                        amount = float(val)
                        break

            desc = ' | '.join(str(row[c]) for c in df.columns if pd.notna(row[c]) and 'amount' not in c.lower() and 'id' not in c.lower())

            transactions.append({
                'trans_date': str(row.get('Date', row.get('Datetime', ''))),
                'post_date': '',
                'description': desc or 'Venmo Transaction',
                'amount': amount,
                'trans_type': 'credit' if amount > 0 else 'debit',
                'cardholder_name': '',
                'card_last_four': '',
                'payment_method': 'venmo',
            })
        except (ValueError, TypeError):
            continue

    return transactions, {'institution': 'Venmo', 'account_type': 'venmo', 'account_number': 'venmo'}


def parse_venmo_pdf(filepath):
    """Parse Venmo PDF statement."""
    pages = parse_pdf_text(filepath)
    transactions = []

    for page_text in pages:
        lines = page_text.split('\n')
        for line in lines:
            # Venmo PDF patterns: date, name, +/- amount
            match = re.match(
                r'(\d{1,2}/\d{1,2}/\d{2,4})\s+(.+?)\s+([-+]?\$?[\d,]+\.\d{2})',
                line.strip()
            )
            if match:
                amount_str = match.group(3).replace('$', '').replace(',', '').replace('+', '')
                try:
                    amount = float(amount_str)
                except ValueError:
                    continue

                transactions.append({
                    'trans_date': match.group(1),
                    'post_date': match.group(1),
                    'description': f"Venmo: {match.group(2).strip()}",
                    'amount': amount,
                    'trans_type': 'credit' if amount > 0 else 'debit',
                    'cardholder_name': match.group(2).strip(),
                    'card_last_four': '',
                    'payment_method': 'venmo',
                })

    return transactions, {'institution': 'Venmo', 'account_type': 'venmo', 'account_number': 'venmo'}


# --- Excel Parser (generic) ---

def parse_excel_transactions(filepath):
    """Parse transactions from Excel files. Auto-detects column structure."""
    df = pd.read_excel(filepath)
    transactions = []
    account_info = {
        'institution': 'Unknown',
        'account_type': 'bank',
        'account_number': '',
    }

    # Auto-detect column mappings
    col_map = {}
    for col in df.columns:
        col_lower = str(col).lower()
        if 'date' in col_lower and 'post' not in col_lower:
            col_map['trans_date'] = col
        elif 'post' in col_lower and 'date' in col_lower:
            col_map['post_date'] = col
        elif 'desc' in col_lower or 'memo' in col_lower or 'narrative' in col_lower:
            col_map['description'] = col
        elif 'amount' in col_lower or 'total' in col_lower:
            col_map['amount'] = col
        elif 'debit' in col_lower:
            col_map['debit'] = col
        elif 'credit' in col_lower:
            col_map['credit'] = col
        elif 'category' in col_lower or 'type' in col_lower:
            col_map['category'] = col
        elif 'card' in col_lower or 'holder' in col_lower or 'name' in col_lower:
            col_map['cardholder'] = col
        elif 'check' in col_lower and 'num' in col_lower:
            col_map['check_number'] = col

    for _, row in df.iterrows():
        try:
            # Get amount
            if 'amount' in col_map:
                amount_val = row[col_map['amount']]
                if pd.isna(amount_val):
                    continue
                amount_str = str(amount_val).replace('$', '').replace(',', '').replace('(', '-').replace(')', '')
                amount = float(amount_str)
            elif 'debit' in col_map or 'credit' in col_map:
                debit = 0
                credit = 0
                if 'debit' in col_map and pd.notna(row[col_map['debit']]):
                    debit = float(str(row[col_map['debit']]).replace('$', '').replace(',', ''))
                if 'credit' in col_map and pd.notna(row[col_map['credit']]):
                    credit = float(str(row[col_map['credit']]).replace('$', '').replace(',', ''))
                amount = credit - debit if credit else -debit
            else:
                continue

            # Get description
            desc = str(row.get(col_map.get('description', ''), 'Unknown'))
            if desc == 'nan':
                desc = 'Unknown'

            # Get date
            date_val = row.get(col_map.get('trans_date', ''), '')
            if pd.notna(date_val):
                date_str = str(date_val)
            else:
                date_str = ''

            transactions.append({
                'trans_date': date_str,
                'post_date': str(row.get(col_map.get('post_date', ''), '')) if 'post_date' in col_map else date_str,
                'description': desc,
                'amount': amount,
                'trans_type': 'credit' if amount > 0 else 'debit',
                'cardholder_name': str(row.get(col_map.get('cardholder', ''), '')) if 'cardholder' in col_map else '',
                'card_last_four': '',
                'payment_method': '',
            })
        except (ValueError, TypeError):
            continue

    return transactions, account_info


# --- Word Document Parser ---

def parse_word_document(filepath):
    """Parse a Word document for notes/proof - extracts text and any tables."""
    doc = DocxDocument(filepath)
    content = {
        'text': [],
        'tables': [],
    }

    for para in doc.paragraphs:
        if para.text.strip():
            content['text'].append(para.text.strip())

    for table in doc.tables:
        table_data = []
        for row in table.rows:
            row_data = [cell.text.strip() for cell in row.cells]
            table_data.append(row_data)
        content['tables'].append(table_data)

    return content


# --- Master parser dispatcher ---

def parse_document(filepath, doc_type='auto'):
    """
    Parse a document and return transactions + account info.

    doc_type: 'bank_statement', 'credit_card', 'venmo', 'excel', 'word', 'proof', or 'auto'
    """
    ext = os.path.splitext(filepath)[1].lower()
    filename = os.path.basename(filepath)

    if doc_type == 'auto':
        # Auto-detect based on filename and content
        if ext in ('.xlsx', '.xls', '.csv'):
            if 'venmo' in filename.lower():
                doc_type = 'venmo'
            else:
                doc_type = 'excel'
        elif ext == '.docx':
            doc_type = 'word'
        elif ext == '.pdf':
            # Try to detect from content
            try:
                pages = parse_pdf_text(filepath)
                full_text = "\n".join(pages).upper()
                if 'CAPITAL ONE' in full_text or 'SPARK CASH' in full_text:
                    doc_type = 'credit_card'
                elif 'VENMO' in full_text and 'STATEMENT' in full_text:
                    doc_type = 'venmo'
                elif 'BANK OF ST' in full_text or 'COMMERCIAL CHECKING' in full_text:
                    doc_type = 'bank_statement'
                else:
                    doc_type = 'bank_statement'  # default for PDFs
            except Exception:
                doc_type = 'bank_statement'

    if doc_type == 'bank_statement':
        return parse_bank_statement(filepath)
    elif doc_type == 'credit_card':
        return parse_capital_one_statement(filepath)
    elif doc_type == 'venmo':
        return parse_venmo_statement(filepath)
    elif doc_type == 'excel':
        return parse_excel_transactions(filepath)
    elif doc_type in ('word', 'proof'):
        content = parse_word_document(filepath)
        return [], {'content': content, 'doc_type': 'proof'}
    else:
        return [], {}
