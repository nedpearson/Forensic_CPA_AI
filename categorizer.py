"""
Auto-categorization engine for forensic auditing.
Applies rule-based matching to classify transactions.
"""
import re
from datetime import datetime, timedelta
from collections import defaultdict
from database import get_db, get_category_rules, build_filter_clause, update_transaction


def categorize_transaction(user_id, description, amount, trans_type='', payment_method='', trans_date=None, account_id=None):
    """
    Apply deterministic categorization rules to a transaction using Phase 9 multi-signal weighted logic.
    Returns dict with category, subcategory, is_personal, is_business, is_transfer, is_flagged, flag_reason.
    """
    from categorization_pipeline import CategorizationPipeline
    result = CategorizationPipeline.process_transaction(user_id, description, amount, trans_type, trans_date, account_id)
    
    # Back-fill legacy fields expected by app.py
    result.setdefault('is_flagged', 0)
    result.setdefault('flag_reason', None)
    result.setdefault('payment_method', payment_method)

    desc_upper = description.upper()

    # Additional heuristic rules (safe to keep on top of rules)

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


def recategorize_all(user_id):
    """Re-run categorization on all auto-categorized (not manually edited) transactions."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, description, amount, trans_date, trans_type, payment_method FROM transactions WHERE user_id = ? AND manually_edited = 0", (user_id,))
    rows = cursor.fetchall()

    updated = 0
    uncategorized = []
    for row in rows:
        result = categorize_transaction(
            user_id,
            row['description'], row['amount'],
            row['trans_type'], row['payment_method']
        )
        
        if result['category'] == 'Uncategorized':
            uncategorized.append({
                'id': row['id'],
                'description': row['description'],
                'amount': row['amount'],
                'trans_date': row['trans_date']
            })
            
        update_args = {
            'category': result['category'],
            'subcategory': result.get('subcategory'),
            'is_personal': result['is_personal'],
            'is_business': result['is_business'],
            'is_transfer': result['is_transfer'],
            'is_flagged': result['is_flagged'],
            'flag_reason': result.get('flag_reason'),
            'categorization_confidence': result.get('categorization_confidence'),
            'categorization_source': result.get('categorization_source'),
            'categorization_status': result.get('categorization_status'),
            'categorization_explanation': result.get('categorization_explanation'),
            'auto_categorized': 1,
            'manually_edited': 0
        }
        if result.get('payment_method'):
            update_args['payment_method'] = result.get('payment_method')
            
        update_transaction(user_id, row['id'], **update_args)
        updated += 1

    conn.close()
    
    if uncategorized:
        run_bulk_ai_categorization(user_id, uncategorized)
        
    return updated


def run_bulk_ai_categorization(user_id, transactions_list):
    """
    Background job to bulk-categorize unrecognized transactions
    using the LLM and auto-learn new rules.
    """
    import threading
    import os
    if not os.environ.get('OPENAI_API_KEY') and not os.environ.get('ANTHROPIC_API_KEY'):
        return

    def _job():
        try:
            from auto_categorizer import AutoCategorizer
            from database import get_categories, update_transaction, add_category_rule, get_db
            
            cats = get_categories(user_id)
            tax_ref = [{'name': c['name']} for c in cats]
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT description, amount, category, is_personal, is_business 
                FROM transactions 
                WHERE user_id = ? AND is_approved = 1 AND category != 'Uncategorized'
                ORDER BY trans_date DESC LIMIT 40
            """, (user_id,))
            few_shot_context = [dict(r) for r in cursor.fetchall()]
            conn.close()
            
            categorizer = AutoCategorizer()
            chunk_size = 50
            
            for i in range(0, len(transactions_list), chunk_size):
                chunk = transactions_list[i:i+chunk_size]
                results = categorizer.categorize_transaction_batch(chunk, tax_ref, few_shot_examples=few_shot_context)
                
                # Update DB
                for r in results:
                    score = r.confidence_score if hasattr(r, 'confidence_score') else 0.5
                    
                    # --- Phase 5 & 10: Low Confidence Internet Lookup Eligibility ---
                    lookup_used = False
                    if score < 0.85 and r.suggested_pattern:
                        # 1. We have low confidence and a clean merchant string
                        from internet_lookup import InternetLookupProvider
                        from database import get_lookup_cache, set_lookup_cache
                        
                        lookup_key = r.suggested_pattern.replace('%', '').strip()
                        cached_result = get_lookup_cache(lookup_key)
                        
                        if cached_result is None:
                            # 2. Reach out to public API safely
                            cached_result = InternetLookupProvider.search_business_entity(lookup_key)
                            set_lookup_cache(lookup_key, cached_result)
                            
                        if cached_result:
                            lookup_used = True
                            # 3. Re-run inference WITH the new internet context
                            # We hack the description to append the lookup snippet so the LLM prompt sees it
                            cloned_txn = {
                                'id': r.txn_id, 
                                'description': next((t['description'] for t in chunk if t['id'] == r.txn_id), '') + f" (WEB CONTEXT: {cached_result[:300]})", 
                                'amount': next((t['amount'] for t in chunk if t['id'] == r.txn_id), 0),
                                'trans_date': next((t['trans_date'] for t in chunk if t['id'] == r.txn_id), '')
                            }
                            
                            second_pass = categorizer.categorize_transaction_batch([cloned_txn], tax_ref, few_shot_examples=few_shot_context)
                            if second_pass:
                                r = second_pass[0]
                                score = r.confidence_score if hasattr(r, 'confidence_score') else 0.5
                                
                    # Phase 10: Precision-Safe Status Applied Bounds
                    if score >= 0.90:
                        status = 'auto_applied'
                    elif score >= 0.65:
                        status = 'suggested'
                    else:
                        status = 'review_required'
                        # Phase 10 Safety Escalation: Wipe out the rule suggestion entirely if the LLM couldn't break 0.30 even after lookup.
                        if score < 0.30:
                            r.suggested_pattern = None
                        
                    explanation = getattr(r, 'reasoning', '')
                    flags = getattr(r, 'explanation_flags', '')
                    if flags:
                        explanation += f" [Flags: {flags}]"
                        
                    update_transaction(
                        user_id, r.txn_id,
                        category=r.category,
                        subcategory=r.subcategory,
                        is_personal=1 if r.is_personal else 0,
                        is_business=1 if r.is_business else 0,
                        is_transfer=1 if r.is_transfer else 0,
                        categorization_confidence=score,
                        categorization_source='internet_lookup' if lookup_used else 'ai_inference',
                        categorization_status=status,
                        categorization_explanation=explanation,
                        manually_edited=0
                    )
                    
                    # Learn new rule
                    if r.suggested_pattern and status == 'auto_applied':
                        add_category_rule(
                            user_id, 
                            r.suggested_pattern, 
                            r.category, 
                            r.subcategory, 
                            1 if r.is_personal else 0, 
                            1 if r.is_business else 0, 
                            1 if r.is_transfer else 0, 
                            40
                        )
        except Exception as e:
            print(f"Background AI Categorization Error: {e}")

    thread = threading.Thread(target=_job)
    thread.daemon = True
    thread.start()


def detect_deposit_transfer_patterns(user_id, filters=None):
    """
    Forensic analysis: Detect patterns where deposits are quickly followed by transfers out.
    This identifies potential money diversion.
    """
    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(user_id, filters)

    # Get all deposits ordered by date
    cursor.execute(f"""
        SELECT * FROM transactions
        {where} AND (trans_type = 'deposit' OR amount > 0)
        ORDER BY trans_date
    """, params)
    deposits = [dict(r) for r in cursor.fetchall()]

    # Get all transfers out ordered by date
    cursor.execute(f"""
        SELECT * FROM transactions
        {where} AND is_transfer = 1 AND amount < 0
        ORDER BY trans_date
    """, params)
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
    try:
        dt = datetime.strptime(date_str[:10], '%Y-%m-%d')
        return (dt + timedelta(days=days)).strftime('%Y-%m-%d')
    except (ValueError, TypeError):
        return date_str


def _days_between(date1, date2):
    """Calculate days between two YYYY-MM-DD date strings."""
    try:
        d1 = datetime.strptime(date1[:10], '%Y-%m-%d')
        d2 = datetime.strptime(date2[:10], '%Y-%m-%d')
        return abs((d2 - d1).days)
    except (ValueError, TypeError):
        return 999


def get_cardholder_spending_summary(user_id, filters=None):
    """Get detailed spending breakdown by cardholder."""
    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(user_id, filters)

    cursor.execute(f"""
        SELECT
            cardholder_name,
            category,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as spent,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as received,
            COUNT(*) as transaction_count
        FROM transactions
        {where} AND cardholder_name IS NOT NULL AND cardholder_name != ''
        GROUP BY cardholder_name, category
        ORDER BY cardholder_name, spent DESC
    """, params)
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


# =============== NEW FORENSIC ANALYSIS FUNCTIONS ===============

def get_recipient_analysis(user_id, filters=None):
    """Analyze money recipients - who gets the money, how much, how often."""
    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(user_id, filters)

    cursor.execute(f"""
        SELECT description, amount, trans_date, cardholder_name, category,
               is_personal, is_business, is_transfer, payment_method
        FROM transactions {where} AND amount < 0
        ORDER BY trans_date
    """, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    recipients = defaultdict(lambda: {
        'total': 0, 'count': 0, 'amounts': [], 'dates': [],
        'categories': set(), 'cardholders': set(), 'methods': set(),
        'first_date': '', 'last_date': '', 'suspicion_score': 0
    })

    all_cardholders = set()

    for row in rows:
        # Extract recipient name from description
        name = _extract_recipient(row['description'])
        if not name:
            continue

        r = recipients[name]
        amt = abs(row['amount'])
        r['total'] += amt
        r['count'] += 1
        r['amounts'].append(amt)
        r['dates'].append(row['trans_date'])
        r['categories'].add(row['category'] or 'Uncategorized')
        if row['cardholder_name']:
            r['cardholders'].add(row['cardholder_name'])
            all_cardholders.add(row['cardholder_name'].upper())
        if row['payment_method']:
            r['methods'].add(row['payment_method'])
        if not r['first_date'] or row['trans_date'] < r['first_date']:
            r['first_date'] = row['trans_date']
        if not r['last_date'] or row['trans_date'] > r['last_date']:
            r['last_date'] = row['trans_date']

    # Calculate suspicion scores and convert sets to lists
    result = []
    grand_total = sum(r['total'] for r in recipients.values())

    for name, r in recipients.items():
        score = 0
        flags = []

        # Round-number pattern (structuring)
        round_count = sum(1 for a in r['amounts'] if a % 500 == 0 and a >= 500)
        if round_count > 0:
            round_pct = round_count / r['count']
            score += int(round_pct * 20)
            if round_pct > 0.5:
                flags.append(f"{round_count}/{r['count']} round-number payments")

        # Same exact amount repeatedly
        from collections import Counter
        amt_counts = Counter(r['amounts'])
        most_common_amt, most_common_cnt = amt_counts.most_common(1)[0]
        if most_common_cnt >= 3:
            score += 15
            flags.append(f"Same amount ${most_common_amt:,.2f} x{most_common_cnt}")

        # Regular intervals
        if len(r['dates']) >= 3:
            intervals = []
            sorted_dates = sorted(r['dates'])
            for i in range(len(sorted_dates) - 1):
                intervals.append(_days_between(sorted_dates[i], sorted_dates[i+1]))
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                if variance < 4 and avg_interval < 35:  # Very regular
                    score += 15
                    flags.append(f"Regular pattern: every ~{avg_interval:.0f} days")

        # Self-dealing: recipient name matches a cardholder
        name_upper = name.upper()
        for ch in all_cardholders:
            if ch in name_upper or name_upper in ch:
                score += 25
                flags.append(f"Name matches cardholder: {ch}")
                break

        # High concentration
        concentration = (r['total'] / grand_total * 100) if grand_total > 0 else 0
        if concentration > 10:
            score += 10
            flags.append(f"Receives {concentration:.1f}% of all outflows")

        # Large first-time payment
        if r['count'] <= 2 and r['total'] > 5000:
            score += 10
            flags.append(f"New recipient with ${r['total']:,.2f}")

        r['suspicion_score'] = min(score, 100)
        r['flags'] = flags
        r['concentration_pct'] = round(concentration, 1)
        r['avg_amount'] = r['total'] / r['count'] if r['count'] > 0 else 0
        r['categories'] = list(r['categories'])
        r['cardholders'] = list(r['cardholders'])
        r['methods'] = list(r['methods'])
        del r['amounts']
        del r['dates']

        result.append({'name': name, **r})

    result.sort(key=lambda x: x['total'], reverse=True)
    return result


def _extract_recipient(description):
    """Extract a meaningful recipient name from a transaction description."""
    desc = description.upper().strip()

    # Venmo: extract recipient name
    venmo_match = re.search(r'VENMO\s*\*?\s*(\w+(?:\s+\w+)?)', desc)
    if venmo_match:
        return 'VENMO - ' + venmo_match.group(1).strip()

    # Internet/ACH transfer: extract destination
    transfer_match = re.search(r'(?:TRANSFER|WIRE)\s+(?:TO|FROM)\s+(\w+)', desc)
    if transfer_match:
        return 'TRANSFER - ' + transfer_match.group(1).strip()

    # POS Purchase: extract merchant
    pos_match = re.search(r'POS\s+PURCHASE\s+(?:NON-PIN|WITH PIN)\s+(.+?)(?:\s+\d{2}/\d{2}|\s*$)', desc)
    if pos_match:
        merchant = pos_match.group(1).strip()
        # Remove location codes and card numbers
        merchant = re.sub(r'\s+\d{5,}\s*', ' ', merchant)
        merchant = re.sub(r'\s+\*{3,5}\d{4}', '', merchant)
        merchant = re.sub(r'\s+[A-Z]{2}\s+\d+$', '', merchant)
        return merchant.strip()[:40]

    # Check: extract payee
    check_match = re.search(r'CHECK\s*#?\s*\d+\s*(.*)', desc)
    if check_match and check_match.group(1):
        return 'CHECK - ' + check_match.group(1).strip()[:30]

    # Bill pay
    bill_match = re.search(r'(.+?)\s*/\s*BILL\s*PAY', desc)
    if bill_match:
        return bill_match.group(1).strip()[:30]

    # Generic: use first meaningful words
    clean = re.sub(r'POS\s+PURCHASE\s+(?:NON-PIN|WITH PIN)\s+', '', desc)
    clean = re.sub(r'\s+\d{5,}', '', clean)
    clean = re.sub(r'\s+[A-Z]{2}\s+\d+$', '', clean)
    words = clean.split()[:4]
    if words:
        return ' '.join(words)[:35]

    return None


def get_deposit_aging(user_id, filters=None):
    """Analyze how quickly deposits are followed by withdrawals/transfers."""
    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(user_id, filters)

    cursor.execute(f"""
        SELECT id, trans_date, description, amount, cardholder_name
        FROM transactions {where} AND amount > 0 ORDER BY trans_date
    """, params)
    deposits = [dict(r) for r in cursor.fetchall()]

    cursor.execute(f"""
        SELECT id, trans_date, description, amount, cardholder_name, is_transfer
        FROM transactions {where} AND amount < 0 ORDER BY trans_date
    """, params)
    withdrawals = [dict(r) for r in cursor.fetchall()]
    conn.close()

    results = []
    for dep in deposits:
        dep_date = dep['trans_date']
        dep_amt = dep['amount']

        # Find withdrawals within 3 days
        fast_out = [w for w in withdrawals
                    if w['trans_date'] >= dep_date
                    and _days_between(dep_date, w['trans_date']) <= 3]
        fast_total = sum(abs(w['amount']) for w in fast_out)

        # Find withdrawals within 7 days
        week_out = [w for w in withdrawals
                    if w['trans_date'] >= dep_date
                    and _days_between(dep_date, w['trans_date']) <= 7]
        week_total = sum(abs(w['amount']) for w in week_out)

        pct_3day = (fast_total / dep_amt * 100) if dep_amt > 0 else 0
        pct_7day = (week_total / dep_amt * 100) if dep_amt > 0 else 0

        risk = 'low'
        if pct_3day > 80:
            risk = 'high'
        elif pct_3day > 50 or pct_7day > 80:
            risk = 'medium'

        results.append({
            'deposit': dep,
            'amount': dep_amt,
            'out_3day': round(fast_total, 2),
            'out_7day': round(week_total, 2),
            'pct_3day': round(pct_3day, 1),
            'pct_7day': round(pct_7day, 1),
            'risk': risk,
            'fast_withdrawals': len(fast_out),
        })

    return results


def get_cardholder_comparison(user_id, filters=None):
    """Side-by-side comparison of all cardholders."""
    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(user_id, filters)

    cursor.execute(f"""
        SELECT
            cardholder_name,
            COUNT(*) as total_transactions,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total_spent,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as total_received,
            COALESCE(SUM(CASE WHEN is_transfer = 1 AND amount < 0 THEN ABS(amount) ELSE 0 END), 0) as transfers_out,
            COALESCE(SUM(CASE WHEN is_flagged = 1 THEN 1 ELSE 0 END), 0) as flagged_count,
            COALESCE(SUM(CASE WHEN is_personal = 1 THEN ABS(amount) ELSE 0 END), 0) as personal_total,
            COALESCE(SUM(CASE WHEN is_business = 1 THEN ABS(amount) ELSE 0 END), 0) as business_total,
            MIN(trans_date) as first_transaction,
            MAX(trans_date) as last_transaction,
            COALESCE(AVG(CASE WHEN amount < 0 THEN ABS(amount) ELSE NULL END), 0) as avg_purchase
        FROM transactions
        {where} AND cardholder_name IS NOT NULL AND cardholder_name != ''
        GROUP BY cardholder_name
        ORDER BY total_spent DESC
    """, params)
    rows = [dict(r) for r in cursor.fetchall()]

    # Get top categories per cardholder
    for row in rows:
        cursor.execute(f"""
            SELECT category, COALESCE(SUM(ABS(amount)), 0) as total, COUNT(*) as cnt
            FROM transactions
            {where} AND cardholder_name = ? AND amount < 0
            GROUP BY category ORDER BY total DESC LIMIT 5
        """, params + [row['cardholder_name']])
        row['top_categories'] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return rows


def get_audit_trail(user_id, limit=200):
    """Get recent audit log entries."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT a.*, t.description as trans_description, t.amount as trans_amount
        FROM audit_log a
        LEFT JOIN transactions t ON a.transaction_id = t.id
        WHERE a.user_id = ?
        ORDER BY a.timestamp DESC
        LIMIT ?
    """, (user_id, limit))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_executive_summary(user_id, filters=None):
    """Generate an executive summary of key forensic findings."""
    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(user_id, filters)

    summary = {'findings': [], 'risk_score': 0, 'total_analyzed': 0}

    # Total transactions
    cursor.execute(f"SELECT COUNT(*) as cnt, MIN(trans_date) as first_date, MAX(trans_date) as last_date FROM transactions {where}", params)
    row = dict(cursor.fetchone())
    summary['total_analyzed'] = row['cnt']
    summary['date_range'] = f"{row['first_date'] or 'N/A'} to {row['last_date'] or 'N/A'}"

    if row['cnt'] == 0:
        conn.close()
        summary['findings'].append({'severity': 'info', 'title': 'No Data', 'detail': 'Upload statements to begin analysis.'})
        return summary

    # Total money flow
    cursor.execute(f"SELECT COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END),0) as total_in, COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END),0) as total_out FROM transactions {where}", params)
    flow = dict(cursor.fetchone())
    summary['total_in'] = flow['total_in']
    summary['total_out'] = flow['total_out']
    summary['net_flow'] = flow['total_in'] - flow['total_out']

    # Finding: Net cash position
    if summary['net_flow'] < -1000:
        summary['findings'].append({
            'severity': 'warning', 'title': 'Net Cash Outflow',
            'detail': f"${abs(summary['net_flow']):,.2f} more went out than came in."
        })
        summary['risk_score'] += 10

    # Finding: Flagged transactions
    cursor.execute(f"SELECT COUNT(*) as cnt, COALESCE(SUM(ABS(amount)),0) as total FROM transactions {where} AND is_flagged = 1", params)
    flagged = dict(cursor.fetchone())
    if flagged['cnt'] > 0:
        summary['findings'].append({
            'severity': 'danger', 'title': f"{flagged['cnt']} Flagged Transactions",
            'detail': f"${flagged['total']:,.2f} in flagged activity detected."
        })
        summary['risk_score'] += min(30, flagged['cnt'] * 3)

    # Finding: Personal spending on business account
    cursor.execute(f"SELECT COUNT(*) as cnt, COALESCE(SUM(ABS(amount)),0) as total FROM transactions {where} AND is_personal = 1", params)
    personal = dict(cursor.fetchone())
    if personal['cnt'] > 0:
        pct = (personal['total'] / flow['total_out'] * 100) if flow['total_out'] > 0 else 0
        summary['findings'].append({
            'severity': 'warning' if pct > 15 else 'info',
            'title': f"Personal Spending: ${personal['total']:,.2f}",
            'detail': f"{personal['cnt']} personal transactions ({pct:.1f}% of outflows)."
        })
        if pct > 15:
            summary['risk_score'] += 10

    # Finding: Transfer concentration
    cursor.execute(f"SELECT COALESCE(SUM(ABS(amount)),0) as total, COUNT(*) as cnt FROM transactions {where} AND is_transfer = 1 AND amount < 0", params)
    transfers = dict(cursor.fetchone())
    if transfers['cnt'] > 0:
        xfer_pct = (transfers['total'] / flow['total_out'] * 100) if flow['total_out'] > 0 else 0
        if xfer_pct > 30:
            summary['findings'].append({
                'severity': 'danger', 'title': f"High Transfer Activity: {xfer_pct:.0f}%",
                'detail': f"${transfers['total']:,.2f} moved via transfers ({transfers['cnt']} transactions)."
            })
            summary['risk_score'] += 15

    # Finding: Rapid deposit drain
    where_d, params_d = build_filter_clause(user_id, filters, 'd')
    cursor.execute(f"""
        SELECT COUNT(*) as cnt FROM (
            SELECT d.id, d.amount as dep_amt,
                COALESCE(SUM(CASE WHEN w.trans_date BETWEEN d.trans_date AND date(d.trans_date, '+3 days')
                    THEN ABS(w.amount) ELSE 0 END), 0) as out_3day
            FROM transactions d
            LEFT JOIN transactions w ON w.amount < 0 AND w.trans_date >= d.trans_date
            {where_d} AND d.amount > 0
            GROUP BY d.id
            HAVING out_3day > dep_amt * 0.8
        )
    """, params_d)
    rapid = cursor.fetchone()['cnt']
    if rapid > 0:
        summary['findings'].append({
            'severity': 'danger', 'title': f"{rapid} Rapid Deposit Drains",
            'detail': f"Deposits with 80%+ withdrawn within 3 days."
        })
        summary['risk_score'] += min(20, rapid * 5)

    # Finding: Round-number transactions
    cursor.execute(f"SELECT COUNT(*) as cnt FROM transactions {where} AND amount < 0 AND ABS(amount) >= 500 AND CAST(ABS(amount) AS INTEGER) % 500 = 0", params)
    round_nums = cursor.fetchone()['cnt']
    if round_nums >= 5:
        summary['findings'].append({
            'severity': 'warning', 'title': f"{round_nums} Round-Number Payments",
            'detail': f"Multiple payments in exact $500 increments - potential structuring."
        })
        summary['risk_score'] += 10

    # Finding: Uncategorized transactions
    cursor.execute(f"SELECT COUNT(*) as cnt, COALESCE(SUM(ABS(amount)),0) as total FROM transactions {where} AND category = 'Uncategorized'", params)
    uncat = dict(cursor.fetchone())
    if uncat['cnt'] > 10:
        summary['findings'].append({
            'severity': 'info', 'title': f"{uncat['cnt']} Uncategorized",
            'detail': f"${uncat['total']:,.2f} in transactions need categorization."
        })

    # Finding: Top recipient concentration
    cursor.execute(f"""
        SELECT description, COALESCE(SUM(ABS(amount)),0) as total, COUNT(*) as cnt
        FROM transactions {where} AND amount < 0
        GROUP BY UPPER(SUBSTR(description, 1, 20))
        ORDER BY total DESC LIMIT 1
    """, params)
    top_recip = cursor.fetchone()
    if top_recip and flow['total_out'] > 0:
        top = dict(top_recip)
        concentration = top['total'] / flow['total_out'] * 100
        if concentration > 20:
            summary['findings'].append({
                'severity': 'warning', 'title': f"Top Recipient: {concentration:.0f}% Concentration",
                'detail': f"Single entity received ${top['total']:,.2f} across {top['cnt']} payments."
            })
            summary['risk_score'] += 10

    summary['risk_score'] = min(100, summary['risk_score'])
    conn.close()
    return summary


def get_money_flow(user_id, filters=None):
    """Track money flow between accounts - where money enters and exits."""
    conn = get_db()
    cursor = conn.cursor()
    where_t, params_t = build_filter_clause(user_id, filters, 't')
    where, params = build_filter_clause(user_id, filters)

    # Get flow by account
    cursor.execute(f"""
        SELECT t.account_id, a.account_name, a.account_type, a.institution,
            COALESCE(SUM(CASE WHEN t.amount > 0 THEN t.amount ELSE 0 END), 0) as inflow,
            COALESCE(SUM(CASE WHEN t.amount < 0 THEN ABS(t.amount) ELSE 0 END), 0) as outflow,
            COUNT(*) as trans_count
        FROM transactions t
        LEFT JOIN accounts a ON t.account_id = a.id
        {where_t}
        GROUP BY t.account_id
        ORDER BY outflow DESC
    """, params_t)
    accounts = [dict(r) for r in cursor.fetchall()]

    # Detect cross-account transfers
    cursor.execute(f"""
        SELECT description, amount, trans_date, cardholder_name, account_id
        FROM transactions
        {where} AND is_transfer = 1
        ORDER BY trans_date
    """, params)
    transfers = [dict(r) for r in cursor.fetchall()]

    # Group transfers to detect flows between accounts
    flows = []
    desc_upper_map = {}
    for t in transfers:
        desc = t['description'].upper()
        # Look for account references in transfer descriptions
        acct_ref = None
        if 'CAPITAL ONE' in desc:
            acct_ref = 'Capital One'
        elif 'VENMO' in desc:
            acct_ref = 'Venmo'
        elif re.search(r'TO\s+\d{4}', desc):
            match = re.search(r'TO\s+(\d{4})', desc)
            acct_ref = f'Account #{match.group(1)}'
        elif re.search(r'FROM\s+\d{4}', desc):
            match = re.search(r'FROM\s+(\d{4})', desc)
            acct_ref = f'Account #{match.group(1)}'

        if acct_ref:
            key = acct_ref
            if key not in desc_upper_map:
                desc_upper_map[key] = {'destination': acct_ref, 'total': 0, 'count': 0, 'dates': []}
            desc_upper_map[key]['total'] += abs(t['amount'])
            desc_upper_map[key]['count'] += 1
            desc_upper_map[key]['dates'].append(t['trans_date'])

    for key, data in desc_upper_map.items():
        data['first_date'] = min(data['dates']) if data['dates'] else ''
        data['last_date'] = max(data['dates']) if data['dates'] else ''
        del data['dates']
        flows.append(data)

    flows.sort(key=lambda x: x['total'], reverse=True)

    # Payment method breakdown
    cursor.execute(f"""
        SELECT payment_method,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total,
            COUNT(*) as cnt
        FROM transactions
        {where} AND payment_method IS NOT NULL AND payment_method != ''
        GROUP BY payment_method
        ORDER BY total DESC
    """, params)
    methods = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return {'accounts': accounts, 'flows': flows, 'methods': methods}


def get_timeline_data(user_id, filters=None):
    """Get transaction data organized for timeline visualization."""
    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(user_id, filters)

    cursor.execute(f"""
        SELECT trans_date,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as day_in,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as day_out,
            COUNT(*) as day_count,
            COALESCE(SUM(CASE WHEN is_flagged = 1 THEN 1 ELSE 0 END), 0) as day_flagged,
            COALESCE(SUM(CASE WHEN is_transfer = 1 AND amount < 0 THEN ABS(amount) ELSE 0 END), 0) as day_transfers,
            GROUP_CONCAT(
                CASE WHEN ABS(amount) > 1000 THEN
                    SUBSTR(description, 1, 30) || ' $' || CAST(ROUND(ABS(amount),2) AS TEXT)
                ELSE NULL END,
                ' | '
            ) as notable
        FROM transactions
        {where}
        GROUP BY trans_date
        ORDER BY trans_date
    """, params)
    days = [dict(r) for r in cursor.fetchall()]

    # Running balance
    running = 0
    for d in days:
        running += d['day_in'] - d['day_out']
        d['running_balance'] = round(running, 2)

    conn.close()
    return days


def get_recurring_transactions(user_id, filters=None):
    """Detect transactions that recur at regular intervals (weekly, biweekly, monthly).
    Flags potential unauthorized recurring payments."""
    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(user_id, filters)

    # Get all outflow transactions grouped by cleaned description
    cursor.execute(f"""
        SELECT id, trans_date, description, amount, cardholder_name, is_personal, is_business, category
        FROM transactions
        {where} AND amount < 0
        ORDER BY description, trans_date
    """, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Group by normalized description (first 20 chars uppercase, stripped of numbers/dates)
    groups = defaultdict(list)
    for r in rows:
        key = re.sub(r'\d{2}/\d{2}', '', r['description'].upper()[:25])
        key = re.sub(r'\s+', ' ', key).strip()
        if len(key) >= 4:
            groups[key].append(r)

    recurring = []
    for key, txns in groups.items():
        if len(txns) < 3:
            continue

        # Sort by date
        txns.sort(key=lambda x: x['trans_date'])

        # Calculate intervals between consecutive transactions
        dates = []
        for t in txns:
            try:
                dates.append(datetime.strptime(t['trans_date'], '%Y-%m-%d'))
            except (ValueError, TypeError):
                pass

        if len(dates) < 3:
            continue

        intervals = [(dates[i+1] - dates[i]).days for i in range(len(dates)-1)]
        avg_interval = sum(intervals) / len(intervals)
        std_dev = (sum((x - avg_interval)**2 for x in intervals) / len(intervals)) ** 0.5

        # Determine if it's recurring (consistent interval with low deviation)
        if std_dev > avg_interval * 0.5:
            continue  # Too irregular

        # Classify the frequency
        if 5 <= avg_interval <= 9:
            frequency = 'Weekly'
        elif 12 <= avg_interval <= 16:
            frequency = 'Biweekly'
        elif 25 <= avg_interval <= 35:
            frequency = 'Monthly'
        elif 55 <= avg_interval <= 65:
            frequency = 'Bimonthly'
        elif 85 <= avg_interval <= 100:
            frequency = 'Quarterly'
        else:
            frequency = f'Every ~{int(avg_interval)} days'

        amounts = [abs(t['amount']) for t in txns]
        avg_amount = sum(amounts) / len(amounts)
        amount_consistent = max(amounts) - min(amounts) < avg_amount * 0.15

        # Risk flags
        flags = []
        if not any(t['is_personal'] or t['is_business'] for t in txns):
            flags.append('Unclassified - not marked personal or business')
        if any(t['category'] == 'Uncategorized' for t in txns):
            flags.append('Uncategorized transactions')
        if amount_consistent and avg_amount > 200:
            flags.append(f'Consistent amount ~${avg_amount:,.2f}')
        cardholders = list(set(t['cardholder_name'] for t in txns if t['cardholder_name']))
        if len(cardholders) > 1:
            flags.append(f'Multiple cardholders: {", ".join(cardholders)}')

        recurring.append({
            'description': txns[0]['description'],
            'normalized': key,
            'frequency': frequency,
            'avg_interval_days': round(avg_interval, 1),
            'std_dev_days': round(std_dev, 1),
            'count': len(txns),
            'avg_amount': round(avg_amount, 2),
            'total_amount': round(sum(amounts), 2),
            'amount_consistent': amount_consistent,
            'first_date': txns[0]['trans_date'],
            'last_date': txns[-1]['trans_date'],
            'cardholders': cardholders,
            'category': txns[0]['category'],
            'flags': flags,
            'transaction_ids': [t['id'] for t in txns],
        })

    # Sort by total amount descending
    recurring.sort(key=lambda x: x['total_amount'], reverse=True)
    return recurring


def suggest_rule_from_edit(user_id, transaction_id):
    """Suggest a categorization rule based on a manually edited transaction."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions WHERE user_id = ? AND id = ?", (user_id, transaction_id))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    t = dict(row)
    desc = t['description'].upper()

    # Extract a pattern from the description
    # Remove numbers, dates, card numbers to find the vendor core
    pattern = re.sub(r'\d{2}/\d{2}\s+\d{2}:\d{2}', '', desc)
    pattern = re.sub(r'\*{3,5}\d{4}', '', pattern)
    pattern = re.sub(r'\s+\d{5,}', '', pattern)
    pattern = re.sub(r'\s+[A-Z]{2}\s*$', '', pattern)
    pattern = re.sub(r'\s+', ' ', pattern).strip()

    # Use first meaningful words as pattern
    words = pattern.split()[:4]
    if len(words) >= 2:
        suggested_pattern = '%' + ' '.join(words[:3]) + '%'
    elif words:
        suggested_pattern = '%' + words[0] + '%'
    else:
        return None

    return {
        'pattern': suggested_pattern,
        'category': t['category'],
        'subcategory': t.get('subcategory'),
        'is_personal': t['is_personal'],
        'is_business': t['is_business'],
        'is_transfer': t['is_transfer'],
        'priority': 50,
        'source_description': t['description'],
    }
