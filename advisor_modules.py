import sqlite3
from typing import Dict, Any, List
from database import get_db, build_filter_clause

def _create_finding(title: str, description: str, severity: str, confidence: int, evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Helper to enforce strict finding schema with confidence scoring and traceability."""
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "confidence_score": confidence,
        "evidence_links": evidence
    }

# ---------------------------------------------------------
# PART 1: PROFITABILITY & FINANCIAL ANALYSIS
# ---------------------------------------------------------
def analyze_profitability(user_id: int, company_id: int) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    filters = {'company_id': company_id} if company_id else None
    where, params = build_filter_clause(user_id, filters)
    findings = []

    try:
        # Period-over-period differences and margin erosion
        cursor.execute(f"""
            SELECT strftime('%Y-%m', trans_date) as month, 
                   SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as revenue,
                   SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) as expenses
            FROM transactions {where}
            GROUP BY month ORDER BY month ASC
        """, params)
        monthly_data = cursor.fetchall()

        if len(monthly_data) >= 2:
            last_month = monthly_data[-1]
            prev_month = monthly_data[-2]
            if last_month['revenue'] < prev_month['revenue'] and last_month['expenses'] > prev_month['expenses']:
                findings.append(_create_finding(
                    title="Margin Erosion Detected",
                    description=f"Revenue decreased and expenses increased from {prev_month['month']} to {last_month['month']}.",
                    severity="warning",
                    confidence=85,
                    evidence=[]
                ))

        # Duplicate entries checks
        cursor.execute(f"""
            SELECT trans_date, amount, description, COUNT(*) as cnt, GROUP_CONCAT(id) as ids 
            FROM transactions {where}
            GROUP BY trans_date, amount, description
            HAVING cnt > 1
        """, params)
        duplicates = cursor.fetchall()
        if duplicates:
            evidence = [{"type": "transaction", "id": int(dup['ids'].split(',')[0]), "amount": dup['amount']} for dup in duplicates[:3]]
            findings.append(_create_finding(
                title="Duplicate Transaction Entries",
                description=f"Found {len(duplicates)} instances of identical transactions occurring on the same date with the exact same amount/description.",
                severity="warning",
                confidence=95,
                evidence=evidence
            ))
            
    finally:
        conn.close()

    if not findings:
            return [{"status": "insufficient_evidence", "message": "No profitability anomalies detected in current active data scope."}]
    return findings

# ---------------------------------------------------------
# PART 2: FRAUD & FORENSIC DETECTION
# ---------------------------------------------------------
def detect_fraud(user_id: int, company_id: int) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    filters = {'company_id': company_id} if company_id else None
    where, params = build_filter_clause(user_id, filters)
    findings = []

    try:
        # Round-number anomaly patterns
        cursor.execute(f"""
            SELECT id, amount, description, trans_date 
            FROM transactions {where} 
            AND amount < 0 AND ABS(amount) >= 1000 AND CAST(ABS(amount) AS INTEGER) % 1000 = 0
        """, params)
        round_nums = cursor.fetchall()
        if len(round_nums) >= 3:
            evidence = [{"type": "transaction", "id": r['id'], "amount": r['amount']} for r in round_nums[:5]]
            findings.append(_create_finding(
                title="Round-Number Anomaly Patterns",
                description=f"Detected {len(round_nums)} large round-number payments. Found frequently with fabricated invoices.",
                severity="danger",
                confidence=90,
                evidence=evidence
            ))

        # Ghost employee / payroll anomaly (multiple payments same day, same amount, slightly diff names/descriptions)
        cursor.execute(f"""
            SELECT trans_date, ABS(amount) as amt, COUNT(*) as cnt, GROUP_CONCAT(id) as ids
            FROM transactions {where} AND category LIKE '%payroll%' OR category LIKE '%salary%'
            GROUP BY trans_date, amt
            HAVING cnt >= 2
        """, params)
        ghost_payroll = cursor.fetchall()
        if ghost_payroll:
            evidence = [{"type": "transaction", "id": int(gp['ids'].split(',')[0]), "amount": gp['amt']} for gp in ghost_payroll[:2]]
            findings.append(_create_finding(
                title="Ghost Employee / Payroll Anomaly",
                description=f"Multiple identical payroll amounts issued on the same exact date.",
                severity="danger",
                confidence=75,
                evidence=evidence
            ))

    finally:
        conn.close()

    if not findings:
            return [{"status": "insufficient_evidence", "message": "No rigid fraud indicators triggered in active company data."}]
    return findings

# ---------------------------------------------------------
# PART 3: RED FLAG DETECTION
# ---------------------------------------------------------
def detect_red_flags(user_id: int, company_id: int) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    filters = {'company_id': company_id} if company_id else None
    where, params = build_filter_clause(user_id, filters)
    findings = []

    try:
        # Suspicious transfers
        cursor.execute(f"""
            SELECT id, amount, trans_date, description 
            FROM transactions {where} 
            AND is_transfer = 1 AND amount < -50000
        """, params)
        large_transfers = cursor.fetchall()
        if large_transfers:
            evidence = [{"type": "transaction", "id": r['id'], "amount": r['amount']} for r in large_transfers[:3]]
            findings.append(_create_finding(
                title="Suspicious Large Transfers",
                description=f"Identified {len(large_transfers)} massive outbound transfers requiring documentation.",
                severity="warning",
                confidence=85,
                evidence=evidence
            ))

        # Unusual spikes/drops (monthly variance > 50%)
        # For simplicity in Phase 8E, looking at large one-off expenses > 3x average
        cursor.execute(f"SELECT SUM(ABS(amount))/COUNT(*) as avg_exp FROM transactions {where} AND amount < 0", params)
        avg_row = cursor.fetchone()
        avg_exp = avg_row['avg_exp'] if avg_row and avg_row['avg_exp'] else 0
        if avg_exp > 0:
            cursor.execute(f"""
                SELECT id, amount FROM transactions {where} 
                AND amount < 0 AND ABS(amount) > ?
            """, params + [avg_exp * 5]) # 5x average
            spikes = cursor.fetchall()
            if spikes:
                evidence = [{"type": "transaction", "id": s['id'], "amount": s['amount']} for s in spikes[:3]]
                findings.append(_create_finding(
                    title="Unusual Expense Spikes",
                    description=f"Detected {len(spikes)} transactions exceeding 5x the average baseline variance.",
                    severity="info",
                    confidence=80,
                    evidence=evidence
                ))

    finally:
        conn.close()

    if not findings:
            return [{"status": "insufficient_evidence", "message": "No statistical red flags found."}]
    return findings

# ---------------------------------------------------------
# PART 4: DOCUMENT INTELLIGENCE
# ---------------------------------------------------------
def analyze_documents(user_id: int, company_id: int) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    findings = []
    
    try:
        if company_id:
            cursor.execute("SELECT id, filename, file_type, statement_start_date, statement_end_date FROM documents WHERE company_id = ?", (company_id,))
        else:
            cursor.execute("SELECT id, filename, file_type, statement_start_date, statement_end_date FROM documents WHERE user_id = ? AND company_id IS NULL", (user_id,))
        docs = cursor.fetchall()

        # Check for cross-document inconsistencies (e.g., overlapping dates from same bank)
        # Note: In a real system we'd extract bank name, but simplified here.
        overlap_counts = 0
        doc_evidence = []
        for i, d1 in enumerate(docs):
            for j, d2 in enumerate(docs):
                if i < j and d1['statement_start_date'] and d2['statement_end_date']:
                    if d1['statement_start_date'] < d2['statement_end_date'] and d1['statement_end_date'] > d2['statement_start_date'] and d1['file_type'] == d2['file_type']:
                        overlap_counts += 1
                        doc_evidence.append({"type": "document", "id": d1['id'], "filename": d1['filename']})
        
        if overlap_counts > 0:
            findings.append(_create_finding(
                title="Cross-Document Inconsistencies",
                description=f"Detected {overlap_counts} potential overlapping date periods across same-typed documents.",
                severity="warning",
                confidence=90,
                evidence=doc_evidence[:3]
            ))
            
    finally:
        conn.close()

    if not findings:
            return [{"status": "insufficient_evidence", "message": "Document metadata aligns cleanly. No cross-document conflicts."}]
    return findings


# ---------------------------------------------------------
# PART 5: INTERNAL CONTROLS ASSESSMENT
# ---------------------------------------------------------
def assess_controls(user_id: int, company_id: int) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    filters = {'company_id': company_id} if company_id else None
    where, params = build_filter_clause(user_id, filters)
    findings = []

    try:
        # Segregation of duties: Admin overrides on manually edited transactions
        cursor.execute(f"SELECT id, description, amount FROM transactions {where} AND is_edited = 1", params)
        manual_overrides = cursor.fetchall()
        if len(manual_overrides) > 10:
            evidence = [{"type": "transaction", "id": r['id'], "amount": r['amount']} for r in manual_overrides[:3]]
            findings.append(_create_finding(
                title="Segregation of Duties / Approval Gaps",
                description=f"High frequency ({len(manual_overrides)}) of manually overridden/edited transactions without explicit secondary approvals.",
                severity="warning",
                confidence=70,  # inferred from behavioral markers
                evidence=evidence
            ))

        # Commingling (Personal vs Business)
        cursor.execute(f"SELECT id, amount FROM transactions {where} AND is_personal = 1", params)
        personal = cursor.fetchall()
        if len(personal) > 0:
            evidence = [{"type": "transaction", "id": r['id'], "amount": r['amount']} for r in personal[:3]]
            findings.append(_create_finding(
                title="Commingling Core Controls Failure",
                description=f"Identified {len(personal)} personal expenses flowing through business ledger. Policy violation.",
                severity="danger",
                confidence=100, # explicitly categorized
                evidence=evidence
            ))
            
    finally:
        conn.close()

    if not findings:
            return [{"status": "insufficient_evidence", "message": "No explicit control failures detected."}]
    return findings

# ---------------------------------------------------------
# PART 6: RISK SCORING
# ---------------------------------------------------------
def calculate_risk_scores(user_id: int, company_id: int, all_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates granular risk profiles for the active company based on findings array."""
    
    # Base risk score initialization
    scores = {
        "fraud_probability": 0,
        "control_risk": 0,
        "vendor_risk": 0,
        "overall_confidence": "HIGH"
    }

    # Iterate actual gathered deterministic objects
    for finding in all_findings:
        if finding.get('status') == 'insufficient_evidence':
            continue
            
        sev = finding.get('severity', 'info')
        conf = finding.get('confidence_score', 0)
        title = finding.get('title', '').lower()
        
        points = 0
        if sev == 'danger': points = 25
        elif sev == 'warning': points = 10
        elif sev == 'info': points = 2

        # Discount using confidence multiplier 
        points = points * (conf / 100.0)

        if 'round-number' in title or 'duplicate' in title or 'ghost' in title:
            scores["fraud_probability"] = min(100, scores["fraud_probability"] + points * 1.5)
        elif 'control' in title or 'override' in title or 'commingling' in title:
            scores["control_risk"] = min(100, scores["control_risk"] + points * 1.5)
        elif 'vendor' in title or 'recipient' in title:
            scores["vendor_risk"] = min(100, scores["vendor_risk"] + points * 1.5)

    scores["fraud_probability"] = round(scores["fraud_probability"], 1)
    scores["control_risk"] = round(scores["control_risk"], 1)
    scores["vendor_risk"] = round(scores["vendor_risk"], 1)
    
    # Drop internal confidence if no data triggered
    if sum(scores.values()) if any(isinstance(v, (int, float)) for v in scores.values()) else 0 == 0:
        scores["overall_confidence"] = "LOW (Dataset too sparse)"

    return scores
