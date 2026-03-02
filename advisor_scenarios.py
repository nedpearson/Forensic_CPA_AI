import sqlite3
from typing import Dict, Any, List
from database import get_db, build_filter_clause

def _create_scenario(title: str, explanation: str, before_val: float, after_val: float, diff_val: float, type_label: str, evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "title": f"[SIMULATION] {title}",
        "explanation": explanation,
        "before_impact": before_val,
        "after_impact": after_val,
        "net_difference": diff_val,
        "impact_type": type_label,
        "evidence_links": evidence
    }

def run_scenarios(user_id: int, company_id: int, all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Executes entirely deterministic, GAAP-compliant simulation limits against the live data.
    """
    conn = get_db()
    cursor = conn.cursor()
    filters = {'company_id': company_id} if company_id else None
    where, params = build_filter_clause(user_id, filters)
    scenarios = []

    try:
        # 1. Profit Impact of Correcting Commingled Funds
        cursor.execute(f"SELECT SUM(ABS(amount)) as total_personal, COUNT(*) as cnt, GROUP_CONCAT(id) as ids FROM transactions {where} AND is_personal = 1", params)
        personal = cursor.fetchone()
        
        cursor.execute(f"SELECT COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END),0) as total_in, COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END),0) as total_out FROM transactions {where}", params)
        flow = cursor.fetchone()
        
        baseline_profit = flow['total_in'] - flow['total_out'] if flow else 0
        
        if personal and personal['cnt'] > 0:
            personal_amt = personal['total_personal'] or 0
            adjusted_profit = baseline_profit + personal_amt
            evidence = [{"type": "transaction", "id": int(i)} for i in personal['ids'].split(',')[:5]]
            
            scenarios.append(_create_scenario(
                title="Profit Impact of Correcting Misclassified Personal Expenses",
                explanation="Simulates the effect on net business profit/cash flow if all flagged personal expenses were properly eliminated from the corporate expense ledger, restoring expected margins.",
                before_val=baseline_profit,
                after_val=adjusted_profit,
                diff_val=personal_amt,
                type_label="Net Profit Improvement",
                evidence=evidence
            ))

        # 2. Vendor Elimination Scenario (Highest single vendor removal)
        # Note: In phase 8E, recipients were processed. We can do a simple top-payee strip.
        cursor.execute(f"""
            SELECT description, SUM(ABS(amount)) as total_paid, COUNT(*) as cnt, GROUP_CONCAT(id) as ids 
            FROM transactions {where} AND amount < 0 AND is_transfer = 0 
            GROUP BY description ORDER BY total_paid DESC LIMIT 1
        """, params)
        top_vendor = cursor.fetchone()
        if top_vendor and top_vendor['cnt'] >= 3:
            ven_amt = top_vendor['total_paid'] or 0
            adjusted_cashflow = baseline_profit + ven_amt
            evidence = [{"type": "transaction", "id": int(i)} for i in top_vendor['ids'].split(',')[:3]]
            
            scenarios.append(_create_scenario(
                title=f"Vendor Elimination: {top_vendor['description']}",
                explanation="Simulates cash flow restoration if the largest single vendor contract was eliminated or discovered to be fraudulent.",
                before_val=baseline_profit,
                after_val=adjusted_cashflow,
                diff_val=ven_amt,
                type_label="Cash Flow Improvement",
                evidence=evidence
            ))

        # 3. Revenue Timing / Check Tampering Reversal (Fraud findings)
        fraud_flags = [f for f in all_findings if f.get('severity') == 'danger' and 'Anomaly' in f.get('title', '')]
        if fraud_flags:
            stolen_amt = 0
            ev_pool = []
            for f in fraud_flags:
                for ev in f.get('evidence_links', []):
                    stolen_amt += abs(ev.get('amount', 0))
                    ev_pool.append(ev)
            
            if stolen_amt > 0:
                adjusted_profit = baseline_profit + stolen_amt
                scenarios.append(_create_scenario(
                    title="Fraud Remediation & Recovery Simulation",
                    explanation="Simulates the structural restoration of the balance sheet if all deterministically detected anomalies and round-number frauds were successfully recovered via legal action.",
                    before_val=baseline_profit,
                    after_val=adjusted_profit,
                    diff_val=stolen_amt,
                    type_label="Asset Recovery",
                    evidence=ev_pool[:5]
                ))

    finally:
        conn.close()

    if not scenarios:
        return [{"status": "insufficient_evidence", "message": "No actionable scenario simulations triggered by the active dataset."}]

    return scenarios
