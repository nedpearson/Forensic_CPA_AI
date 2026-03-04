import json
from typing import Dict, Any, List
from database import get_advisor_findings

def generate_advisor_report(company_id: int, mode: str = 'client') -> Dict[str, Any]:
    """
    Generates a deterministic narrative report from persisted advisor_findings.
    Mode can be 'client' (plain english) or 'auditor' (technical rationales).
    """
    
    # 1. Fetch raw findings directly from DB to guarantee it matches the UI
    raw_findings = get_advisor_findings(company_id)
    
    if not raw_findings:
        return {
            "status": "empty",
            "message": "No findings exist in the database for this company yet. Please run the Advisor analysis."
        }
        
    # Group findings by category
    sections = {}
    for f in raw_findings:
        cat = f.get('category', 'unknown')
        if cat not in sections:
            sections[cat] = []
        sections[cat].append(f)
        
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT MIN(trans_date) as start_date, MAX(trans_date) as max_date FROM transactions WHERE account_id IN (SELECT id FROM accounts WHERE company_id = ?)", (company_id,))
    row = cursor.fetchone()
    conn.close()
    
    date_range = "N/A"
    if row and row['start_date'] and row['max_date']:
        date_range = f"{row['start_date']} to {row['max_date']}"

    # Extract Analysis Run ID (they should all share it implicitly per company refresh)
    analysis_run_ids = set()
    for f in raw_findings:
        if f.get('analysis_run_id'):
            analysis_run_ids.add(f.get('analysis_run_id'))
    
    # Build report sections
    report = {
        "status": "ready",
        "company_id": company_id,
        "mode": mode,
        "analysis_run_id": list(analysis_run_ids)[0] if analysis_run_ids else "N/A",
        "date_range": date_range,
        "executive_summary": _build_executive_summary(raw_findings, mode),
        "detailed_findings": _build_detailed_findings(sections, mode),
        "appendix": _build_appendix(raw_findings)
    }
    
    return report

def _build_executive_summary(findings: List[Dict[str, Any]], mode: str) -> str:
    high_sev = [f for f in findings if f.get('severity') == 'danger']
    med_sev = [f for f in findings if f.get('severity') == 'warning']
    
    if mode == 'client':
        lines = [
            f"**Executive Summary**",
            f"Our AI analysis has reviewed the recent financial activity and identified {len(high_sev)} critical areas requiring immediate attention, along with {len(med_sev)} items to monitor.",
        ]
        if high_sev:
            lines.append("The most concerning issues involve:")
            for f in high_sev[:3]:
                lines.append(f"- **{f['title']}**: {f.get('executive_summary', '')}")
                
        lines.append("\n**Financial Impact Summary**")
        lines.append("Estimates are calculated based on explicit transactions matching pattern criteria. Assumes all flagged transactions represent actual exposure unless otherwise verified by client documents.")

        lines.append("\nPlease review the detailed findings below for explanations and recommended next steps.")
        return "\n\n".join(lines)
    else:
        # Auditor Mode
        lines = [
            f"**Forensic Audit Summary**",
            f"Automated analytic procedures identified {len(high_sev)} high-risk anomalies and {len(med_sev)} medium-risk flags.",
            "Systematic review of the internal control environment and transaction ledgers indicates the following primary risk vectors:"
        ]
        if high_sev:
            for f in high_sev[:3]:
                lines.append(f"- **{f['title']}** (Confidence: {f.get('confidence', 0)}%): {f.get('forensic_rationale', '')}")
                
        lines.append("\n**Financial Impact Summary (Auditor)**")
        lines.append("Quantitative materiality thresholds applied where data permits. Underlying assumptions depend on strict exact-match reconciliation against provided banking and bookkeeping statements.")
        
        return "\n\n".join(lines)


def _build_detailed_findings(sections: Dict[str, List[Dict]], mode: str) -> List[Dict[str, Any]]:
    formatted_sections = []
    
    for category, items in sections.items():
        if not items: continue
        
        section_name = category.replace('_', ' ').title()
        
        narratives = []
        for i, f in enumerate(items):
            # Generate the [EVID-xxx] string for inline citations
            ev_graph = f.get('evidence_graph', [])
            ev_str = ", ".join([f"[EVID-{e['type']}-{e['id']}]" for e in ev_graph if 'id' in e])
            
            p = []
            if mode == 'client':
                p.append(f"### {i+1}. {f['title']}")
                p.append(f"**What we found:** {f.get('plain_english_explanation', 'No generic explanation provided.')}")
                p.append(f"**Why it matters:** {f.get('executive_summary', 'This item could indicate an area of misclassification or potential risk.')}")
                
                if ev_str:
                    p.append(f"**Evidence:** This finding is based on {len(ev_graph)} specific items in your records ({ev_str}).")
                else:
                    p.append(f"**Evidence:** No direct node evidence attached, derived from aggregate metadata.")
                
                impact = f.get('financial_impact')
                if impact:
                    p.append(f"**Financial impact:** Based on available data, the impact is noted. (Method: {impact.get('method', 'transaction aggregation')} | Est: {impact.get('amount', 'N/A')})")
                else:
                    p.append(f"**Financial impact:** Unknown precise financial value.")
                    
                if f.get('recommended_actions'):
                    p.append(f"**How to fix:** " + " ".join(f['recommended_actions']))
                else:
                    p.append(f"**How to fix:** Review the referenced records and update your system.")
                
                p.append(f"**Next questions / missing documents:** Please review the attached evidence. If any supporting documentation is missing, please upload it to the workspace.")
            else:
                p.append(f"### {i+1}. {f['title']} (Sev: {f.get('severity', 'none').upper()})")
                p.append(f"**Forensic Rationale:** {f.get('forensic_rationale', 'N/A')}")
                p.append(f"**Implications (Why it matters):** {f.get('executive_summary', 'N/A')}")
                
                if ev_str:
                    p.append(f"**Traceability (Evidence):** Nodes {ev_str}")
                else:
                    p.append(f"**Traceability (Evidence):** Aggregate level alert.")

                impact = f.get('financial_impact')
                if impact:
                    p.append(f"**Financial impact:** Quantitative Est: {impact.get('amount', 'N/A')} (Method: {impact.get('method', 'N/A')})")
                
                if f.get('recommended_actions'):
                    p.append(f"**Control Recommendations (How to fix):** " + " ".join(f['recommended_actions']))
                
                p.append(f"**Audit Next Steps (Next questions / missing documents):** Verify all identified transactions against direct bank statements and request original receipts for unmatched items.")
            
            narratives.append("\n\n".join(p))
            
        formatted_sections.append({
            "category": section_name,
            "content": "\n\n---\n\n".join(narratives)
        })
        
    return formatted_sections

def _build_appendix(findings: List[Dict[str, Any]]) -> str:
    # Gather a unique list of all evidence items cited and dump them 
    evidence_index = {}
    for f in findings:
        for e in f.get('evidence_graph', []):
            if 'id' in e and 'type' in e:
                key = f"{e['type']}-{e['id']}"
                if key not in evidence_index:
                    title = f.get('title', 'Unknown Finding')
                    evidence_index[key] = f"Type: {e['type'].upper()} | ID: {e['id']} | Cited In: {title}"
                    
    lines = ["**Audit Trail Appendix**\n"]
    if not evidence_index:
        lines.append("No specific evidence records were directly cited in this run.")
    else:
        for k, info in evidence_index.items():
            lines.append(f"- `[EVID-{k}]` : {info}")
            
    return "\n".join(lines)
