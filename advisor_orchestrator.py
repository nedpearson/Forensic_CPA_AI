from typing import Dict, Any, List
from advisor_modules import analyze_profitability, detect_fraud, detect_red_flags, analyze_documents, assess_controls, calculate_risk_scores
from advisor_scenarios import run_scenarios

def run_advisor_orchestration(aggregated_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Orchestration layer that prepares, validates, classifies, and routes aggregated 
    company-scoped data into deterministic Advisor UI structures.
    """
    user_id = aggregated_payload.get("user_id")
    company_id = aggregated_payload.get("company_id")

    # Combine localized payload anomalies with deep-database modules
    raw_fraud = _detect_fraud_exceptions(aggregated_payload) + detect_fraud(user_id, company_id)
    raw_key = analyze_profitability(user_id, company_id) + _extract_key_findings(aggregated_payload)
    raw_red = detect_red_flags(user_id, company_id)
    raw_doc = _evaluate_document_intelligence(aggregated_payload) + analyze_documents(user_id, company_id)
    raw_ctrl = _assess_internal_controls(aggregated_payload) + assess_controls(user_id, company_id)

    # Flatten findings for Risk Scoring BEFORE validation drops any items to keep global context
    all_findings = raw_fraud + raw_key + raw_red + raw_doc + raw_ctrl
    
    # Self-validation layer explicitly wrapping findings
    fraud_flags = _validate_findings(raw_fraud, company_id, "fraud_red_flags")
    key_finds = _validate_findings(raw_key, company_id, "key_findings")
    red_flags = _validate_findings(raw_red, company_id, "fraud_red_flags")
    doc_intel = _validate_findings(raw_doc, company_id, "document_intelligence")
    controls = _validate_findings(raw_ctrl, company_id, "internal_controls")
    validated_scenarios = _validate_findings(run_scenarios(user_id, company_id, all_findings), company_id, "scenario_simulator")

    results = {
        "company_id": company_id,
        "executive_summary": _construct_executive_summary(aggregated_payload),
        "fraud_red_flags": _enforce_minimum_findings(fraud_flags + red_flags, "Fraud & Red Flags"),
        "key_findings": _enforce_minimum_findings(key_finds, "Key Findings"),
        "document_intelligence": _enforce_minimum_findings(doc_intel, "Document Intelligence"),
        "internal_controls": _enforce_minimum_findings(controls, "Internal Controls"),
        "risk_scoring": calculate_risk_scores(user_id, company_id, all_findings),
        "scenario_simulator": _enforce_minimum_findings(validated_scenarios, "Scenario Simulator"),
        "audit_ready_appendix": _compile_audit_appendix(aggregated_payload)
    }
    
    return results

def _validate_findings(findings: List[Dict[str, Any]], expected_company_id: int, category: str = None) -> List[Dict[str, Any]]:
    import hashlib
    """Final Self-Validation Step: Assures schema correctness and traceability."""
    valid = []
    for f in findings:
        if f.get('status') == 'insufficient_evidence':
            continue
            
        # 1. Schema Validation (Must be structured correctly)
        if 'title' not in f or 'severity' not in f or 'confidence_score' not in f:
            continue
            
        # 2. Traceability Validation (Must contain an evidence array)
        if 'evidence_links' not in f:
            continue
            
        # 3. Security/Isolation (Reject cross-company data if embedded directly in finding)
        if expected_company_id and f.get('company_id') and f.get('company_id') != expected_company_id:
            continue

        if category:
            h = hashlib.sha256(f"{expected_company_id}_{category}_{f['title']}".encode()).hexdigest()
            f['finding_id'] = h
            f['company_id'] = expected_company_id
            f['category'] = category
            
            # Enforce the new DB schema defaults
            desc = f.get('description', '')
            if 'executive_summary' not in f:
                f['executive_summary'] = desc.split('.')[0] + "." if desc else ""
            if 'plain_english_explanation' not in f:
                f['plain_english_explanation'] = desc
            if 'forensic_rationale' not in f:
                f['forensic_rationale'] = f"Algorithmic match for {category} heuristics based on deterministic inputs."
            if 'financial_impact' not in f:
                f['financial_impact'] = {}
            if 'recommended_actions' not in f:
                f['recommended_actions'] = []
            if 'drilldown_queries' not in f:
                f['drilldown_queries'] = {}
            if 'evidence_graph' not in f:
                f['evidence_graph'] = f.get('evidence_links', [])
            if 'confidence' not in f:
                f['confidence'] = f.get('confidence_score', 0)

        valid.append(f)
        
    return valid

def _enforce_minimum_findings(findings: List[Dict[str, Any]], section_name: str) -> List[Dict[str, Any]]:
    """Ensures empty lists are cleanly replaced by a single placeholder object for the UI."""
    if not findings:
        return [{"status": "insufficient_evidence", "message": f"No anomalous or statistically significant findings met the confidence threshold for {section_name}."}]
    return findings

def _create_finding(title: str, description: str, severity: str, confidence: int, evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Helper to enforce strict finding schema with confidence scoring and traceability."""
    return {
        "title": title,
        "description": description,
        "severity": severity,  # info, warning, danger, success
        "confidence_score": confidence, # 0-100
        "evidence_links": evidence
    }

def _construct_executive_summary(payload: Dict[str, Any]) -> Dict[str, Any]:
    analytics = payload.get("analytics", {})
    exec_sum = analytics.get("executive_summary", {})
    
    if not exec_sum or not exec_sum.get("total_analyzed"):
        return {
            "status": "insufficient_evidence",
            "message": "Not enough transaction data to compute an executive summary."
        }
    
    return {
        "status": "success",
        "data": exec_sum
    }

def _detect_fraud_exceptions(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. Flagged Transactions Analysis
    flagged = payload.get("flagged_transactions", [])
    if flagged:
        # Traceability: attach exact transaction IDs
        evidence = [{"type": "transaction", "id": t["transaction_id"], "amount": t["amount"]} for t in flagged[:5]]
        
        findings.append(_create_finding(
            title="Flagged Anomalies Detected",
            description=f"Detected {len(flagged)} explicitly flagged transactions requiring review.",
            severity="danger",
            confidence=95,
            evidence=evidence
        ))
    
    # 2. Deposit Aging Rapid Drain
    aging = payload.get("analytics", {}).get("deposit_aging", [])
    rapid_drains = [d for d in aging if d.get('pct_3day', 0) >= 80]
    if rapid_drains:
        evidence = [{"type": "transaction", "id": d["deposit"]["id"], "amount": d["amount"]} for d in rapid_drains[:3]]
        findings.append(_create_finding(
            title="Rapid Deposit Drain",
            description=f"Found {len(rapid_drains)} deposits where >80% of funds were withdrawn within 3 days.",
            severity="danger",
            confidence=85,
            evidence=evidence
        ))
        
    if not findings:
        return [{"status": "insufficient_evidence", "message": "No deterministic fraud markers or flagged patterns detected in the current data scope."}]
        
    return findings

def _extract_key_findings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. Recipient Concentration
    recipients = payload.get("analytics", {}).get("recipient_analysis", [])
    if recipients:
        top_recipients = recipients[:3]
        evidence = [{"type": "entity", "name": r["name"], "total_amount": r["total"]} for r in top_recipients]
        
        findings.append(_create_finding(
            title="Concentrated Spending Destinations",
            description=f"The top {len(top_recipients)} payees account for a significant portion of outflows.",
            severity="info",
            confidence=90,
            evidence=evidence
        ))
        
    if not findings:
        return [{"status": "insufficient_evidence", "message": "No statistically significant spending concentrations or timeline spikes detected."}]
        
    return findings

def _evaluate_document_intelligence(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    documents = payload.get("documents", [])
    
    if not documents:
        return [{"status": "insufficient_evidence", "message": "No documents uploaded. Unable to perform OCR and extraction intelligence."}]
        
    bank_statements = [d for d in documents if d.get("file_type") == "bank"]
    if bank_statements:
        evidence = [{"type": "document", "id": d["document_id"], "filename": d["filename"]} for d in bank_statements]
        findings.append(_create_finding(
            title="Bank Statement Verification",
            description=f"Verified {len(bank_statements)} bank statements parsed via deterministic OCR mappings.",
            severity="success",
            confidence=100,
            evidence=evidence
        ))
        
    return findings

def _assess_internal_controls(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    
    # Check for commingling of funds
    flagged = payload.get("flagged_transactions", [])
    personal_in_biz = [t for t in flagged if t.get("is_personal") == 1]
    
    if len(personal_in_biz) > 5:
        evidence = [{"type": "transaction", "id": t["transaction_id"], "amount": t["amount"]} for t in personal_in_biz[:5]]
        findings.append(_create_finding(
            title="Commingling of Funds",
            description=f"High frequency ({len(personal_in_biz)}) of personal expenses identified in business ledgers, indicating poor internal entity boundary controls.",
            severity="warning",
            confidence=80,
            evidence=evidence
        ))
        
    if not findings:
        return [{"status": "insufficient_evidence", "message": "Current activity volume lacks sufficient indicators to assess internal control failures."}]
        
    return findings

def _compile_audit_appendix(payload: Dict[str, Any]) -> Dict[str, Any]:
    # Gathers every deterministic ID for the final traceability payload.
    return {
        "status": "ready",
        "traced_documents": [d["document_id"] for d in payload.get("documents", [])],
        "flagged_anchors": [t["transaction_id"] for t in payload.get("flagged_transactions", [])],
        "active_accounts": [a["account_id"] for a in payload.get("accounts", [])]
    }
