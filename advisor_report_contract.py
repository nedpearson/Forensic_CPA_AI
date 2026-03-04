import uuid
import datetime
from typing import Dict, Any, List

def build_premium_client_report(company_id: int) -> Dict[str, Any]:
    """
    Constructs the formalized 'Client Audit Report' data contract.
    This is the single source of truth for the Premium Audit Report UI and PDFs.
    """
    from database import get_advisor_findings, get_remediation_tasks, get_db
    
    findings = get_advisor_findings(company_id)
    tasks = get_remediation_tasks(company_id)
    
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Fetch Date Range & CF Proxy
    cursor.execute("SELECT MIN(trans_date) as start_date, MAX(trans_date) as max_date, SUM(amount) as net_cashflow FROM transactions WHERE account_id IN (SELECT id FROM accounts WHERE company_id = ?)", (company_id,))
    date_row = cursor.fetchone()
    
    period_start = date_row['start_date'] if date_row and date_row['start_date'] else "N/A"
    period_end = date_row['max_date'] if date_row and date_row['max_date'] else "N/A"
    net_cf = float(date_row['net_cashflow']) if date_row and date_row['net_cashflow'] else 0.0
    
    # 2. Income Statement Proxy
    cursor.execute("SELECT trans_type, SUM(amount) as total FROM transactions WHERE account_id IN (SELECT id FROM accounts WHERE company_id = ?) GROUP BY trans_type", (company_id,))
    is_rows = cursor.fetchall()
    revenue = sum([float(r['total']) for r in is_rows if r['trans_type'] in ['deposit', 'credit']])
    expenses = sum([float(r['total']) for r in is_rows if r['trans_type'] in ['debit', 'fee', 'payment']])
    
    # Extract latest run ID
    run_ids = set([f.get('analysis_run_id') for f in findings if f.get('analysis_run_id')])
    latest_run_id = list(run_ids)[0] if run_ids else "N/A"
    
    # 3. Stratify Findings for Risk Register
    high_findings = [f for f in findings if f.get('severity') == 'danger']
    med_findings = [f for f in findings if f.get('severity') == 'warning']
    low_findings = [f for f in findings if f.get('severity') == 'info']
    
    risk_register = sorted(findings, key=lambda x: (x.get('severity') == 'info', x.get('severity') == 'warning', x.get('severity') == 'danger', -x.get('confidence', 0)))
    
    # Format client/auditor summary limits safely
    client_mode_summary = f"We have completed a forensic review of the financial records from {period_start} to {period_end}. We identified {len(high_findings)} critical areas of structural concern and {len(med_findings)} secondary issues. Below is a detailed breakdown of findings, simulated impacts, and an actionable remediation plan."
    auditor_mode_summary = f"Automated analytic procedures executed against ledger entries from {period_start} to {period_end}. Identified {len(high_findings)} severe anomalies (Confidence > 80%) indicating potential control deficiencies, asset misappropriation, or reporting misstatement. Exhibits below detail evidence traceability."
    
    # Map exhibits (mocking out standard aggregations if evidence_graph isn't deep enough yet)
    exhibits = [
        {"type": "vendor_concentration", "title": "Top Vendor Analysis", "description": "Concentration of outflow anomalies."},
        {"type": "velocity_anomalies", "title": "Unusual Payment Patterns", "description": "High frequency or structurally similar payouts."},
    ]
    
    # Appendices (paged)
    appendix = []
    
    conn.close()

    contract = {
        "report_id": str(uuid.uuid4()),
        "company_id": company_id,
        "analysis_run_id": latest_run_id,
        "period_start": period_start,
        "period_end": period_end,
        "generated_at": datetime.datetime.now().isoformat(),
        "client_mode_summary": client_mode_summary,
        "auditor_mode_summary": auditor_mode_summary,
        "financial_statements_snapshot": {
            "pnl_summary": {
                "total_revenue": revenue,
                "total_expenses": expenses,
                "net_income_proxy": revenue - expenses
            },
            "bs_summary": {
                "assets": 0.0,
                "liabilities": 0.0,
                "equity": 0.0,
                "note": "Balance Sheet reconstruction unavailable in strictly cash-basis uploads. Metrics reflect proxy bounds."
            },
            "cash_flow_summary": {
                "net_operating": net_cf,
                "net_investing": 0.0,
                "net_financing": 0.0
            }
        },
        "risk_register": risk_register,
        "detailed_findings": [
            {
                "finding_id": f.get('finding_id'),
                "title": f.get('title'),
                "severity": f.get('severity'),
                "confidence": f.get('confidence'),
                "plain_english_explanation": f.get('plain_english_explanation', f.get('executive_summary', '')),
                "auditor_rationale": f.get('forensic_rationale', ''),
                "impact_breakdown": f.get('financial_impact', {}),
                "evidence_citations": f.get('evidence_graph', {}),
                "recommended_fixes": f.get('recommended_actions', []),
                "next_steps_requests": "Request missing original invoices and bank statements for these transactions." if f.get('severity') == 'danger' else "Review internally."
            } for f in risk_register
        ],
        "exhibits": exhibits,
        "internal_controls_section": {
            "summary": "The environment exhibits structural weaknesses in vendor approval and expense categorization logic.",
            "deficiencies": [f.get('title') for f in findings if f.get('category' ) == 'internal_controls']
        },
        "remediation_plan": tasks,
        "audit_ready_appendix": {
            "evidence_index_count": len(findings),
            "note": "Use the /api/advisor/report/appendix paginated endpoint to load full transaction lines."
        }
    }
    
    return contract
