"""
Auto-categorization engine for forensic auditing.
Applies rule-based matching to classify transactions.
"""
import re
from database import get_db, get_category_rules


def categorize_transaction(description, amount, trans_type='', payment_method=''):
    """
    Apply categorization rules to a transaction.
    Returns dict with category, subcategory, is_personal, is_business, is_transfer, is_flagged, flag_reason.
    """
    rules = get_category_rules()
    desc_upper = description.upper()
    result = {
        'category': 'Uncategorized',
        'subcategory': None,
        'is_personal': 0,
        'is_business': 0,
        'is_transfer': 0,
        'is_flagged': 0,
        'flag_reason': None,
        'payment_method': payment_method,
    }

    best_match = None
    best_priority = -1

    for rule in rules:
        pattern = rule['pattern'].upper()
        # Convert SQL LIKE pattern to regex-compatible check
        # % = any chars, _ = single char
        if '%' in pattern or '_' in pattern:
            regex_pattern = pattern.replace('%', '.*').replace('_', '.')
            if re.search(regex_pattern, desc_upper):
                if rule['priority'] > best_priority:
                    best_priority = rule['priority']
                    best_match = rule
        elif pattern in desc_upper:
            if rule['priority'] > best_priority:
                best_priority = rule['priority']
                best_match = rule

    if best_match:
        result['category'] = best_match['category']
        result['subcategory'] = best_match['subcategory']
        result['is_personal'] = best_match['is_personal']
        result['is_business'] = best_match['is_business']
        result['is_transfer'] = best_match['is_transfer']

    # Additional heuristic rules

    # Detect transfers
    transfer_keywords = [
        'TRANSFER', 'WIRE', 'CAPITAL ONE', 'VENMO', 'ZELLE', 'CASHAPP',
        'ACH', 'MOBILE PMT'
    ]
    if any(kw in desc_upper for kw in transfer_keywords):
        result['is_transfer'] = 1

    # Detect transfer destination accounts
    acct_match = re.search(r'(?:TO|FROM)\s+(\d{4})', desc_upper)
    if acct_match:
        result['is_transfer'] = 1

    # Detect checks
    check_match = re.search(r'CHECK\s*#?\s*(\d+)', desc_upper)
    if check_match:
        result['payment_method'] = 'check'

    # Detect Venmo payments
    if 'VENMO' in desc_upper:
        result['payment_method'] = 'venmo'
        # Extract recipient name from Venmo
        venmo_name = re.search(r'VENMO[/*\s]+(?:PAYMENT\s+\d+\s+)?(\w+)', desc_upper)
        if venmo_name:
            result['venmo_recipient'] = venmo_name.group(1)

    # Detect POS purchases
    if 'POS PURCHASE' in desc_upper:
        result['payment_method'] = result['payment_method'] or 'debit'

    # Flag suspicious patterns
    flags = []

    # Large round-number transfers (potential structuring)
    if result['is_transfer'] and abs(amount) >= 1000 and abs(amount) % 500 == 0:
        flags.append(f"Round-number transfer: ${abs(amount):,.2f}")

    # Rapid sequence transfers (will be detected at batch level)
    # Large cash withdrawals
    if abs(amount) > 5000 and ('CASH' in desc_upper or 'ATM' in desc_upper):
        flags.append(f"Large cash withdrawal: ${abs(amount):,.2f}")

    # Transfers to unknown accounts
    if 'TRANSFER TO' in desc_upper and abs(amount) > 2000:
        flags.append(f"Large transfer out: ${abs(amount):,.2f}")

    # Capital One payments (money leaving to credit card)
    if 'CAPITAL ONE' in desc_upper and abs(amount) > 1000:
        flags.append(f"Large Capital One payment: ${abs(amount):,.2f}")

    # Venmo payments to specific individuals
    if 'VENMO' in desc_upper and 'JAMES' in desc_upper:
        flags.append("Venmo payment involving JAMES")

    if flags:
        result['is_flagged'] = 1
        result['flag_reason'] = '; '.join(flags)

    return result


def recategorize_all():
    """Re-run categorization on all auto-categorized (not manually edited) transactions."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, description, amount, trans_type, payment_method FROM transactions WHERE manually_edited = 0")
    rows = cursor.fetchall()

    updated = 0
    for row in rows:
        result = categorize_transaction(
            row['description'], row['amount'],
            row['trans_type'], row['payment_method']
        )
        cursor.execute("""
            UPDATE transactions SET
                category = ?, subcategory = ?,
                is_personal = ?, is_business = ?, is_transfer = ?,
                is_flagged = ?, flag_reason = ?,
                payment_method = COALESCE(?, payment_method),
                auto_categorized = 1
            WHERE id = ?
        """, (
            result['category'], result['subcategory'],
            result['is_personal'], result['is_business'], result['is_transfer'],
            result['is_flagged'], result['flag_reason'],
            result['payment_method'],
            row['id']
        ))
        updated += 1

    conn.commit()
    conn.close()
    return updated


def detect_deposit_transfer_patterns():
    """
    Forensic analysis: Detect patterns where deposits are quickly followed by transfers out.
    This identifies potential money diversion.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Get all deposits ordered by date
    cursor.execute("""
        SELECT * FROM transactions
        WHERE (trans_type = 'deposit' OR amount > 0)
        ORDER BY trans_date
    """)
    deposits = [dict(r) for r in cursor.fetchall()]

    # Get all transfers out ordered by date
    cursor.execute("""
        SELECT * FROM transactions
        WHERE is_transfer = 1 AND amount < 0
        ORDER BY trans_date
    """)
    transfers = [dict(r) for r in cursor.fetchall()]

    patterns = []
    for dep in deposits:
        dep_date = dep['trans_date']
        related_transfers = []
        transfer_total = 0

        for xfer in transfers:
            # Within 7 days after deposit
            if xfer['trans_date'] >= dep_date and xfer['trans_date'] <= _add_days(dep_date, 7):
                related_transfers.append(xfer)
                transfer_total += abs(xfer['amount'])

        if related_transfers and transfer_total > 0:
            pct_transferred = (transfer_total / dep['amount'] * 100) if dep['amount'] > 0 else 0
            patterns.append({
                'deposit': dep,
                'transfers': related_transfers,
                'deposit_amount': dep['amount'],
                'transfer_total': transfer_total,
                'pct_transferred': round(pct_transferred, 1),
                'days_span': len(set(t['trans_date'] for t in related_transfers)),
            })

    conn.close()
    return patterns


def _add_days(date_str, days):
    """Simple date addition for YYYY-MM-DD format strings."""
    from datetime import datetime, timedelta
    try:
        dt = datetime.strptime(date_str[:10], '%Y-%m-%d')
        return (dt + timedelta(days=days)).strftime('%Y-%m-%d')
    except (ValueError, TypeError):
        return date_str


def get_cardholder_spending_summary():
    """Get detailed spending breakdown by cardholder."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            cardholder_name,
            category,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as spent,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as received,
            COUNT(*) as transaction_count
        FROM transactions
        WHERE cardholder_name IS NOT NULL AND cardholder_name != ''
        GROUP BY cardholder_name, category
        ORDER BY cardholder_name, spent DESC
    """)
    rows = [dict(r) for r in cursor.fetchall()]

    # Organize by cardholder
    summary = {}
    for row in rows:
        name = row['cardholder_name']
        if name not in summary:
            summary[name] = {'categories': [], 'total_spent': 0, 'total_received': 0, 'total_transactions': 0}
        summary[name]['categories'].append(row)
        summary[name]['total_spent'] += row['spent']
        summary[name]['total_received'] += row['received']
        summary[name]['total_transactions'] += row['transaction_count']

    conn.close()
    return summary
