import json
from typing import Dict, Any, List, Optional
from database import get_db

def run_simulation(
    company_id: int, 
    scenario_type: str, 
    parameters: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Executes a financial simulation based on underlying transactions.
    Guardrails: No books are modified (read-only queries).
    """
    
    # Base guardrails
    if scenario_type not in ['reclassification', 'timing', 'add_back', 'controls_remediation']:
        return {"status": "error", "message": "Invalid scenario type. Must be GAAP-compliant simulation."}
        
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Calculate baseline metrics first
        cursor.execute("SELECT COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as total_in, COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total_out FROM transactions WHERE company_id = ?", (company_id,))
        base_flow = cursor.fetchone()
        baseline_revenue = base_flow['total_in'] if base_flow else 0.0
        baseline_expenses = base_flow['total_out'] if base_flow else 0.0
        baseline_profit = baseline_revenue - baseline_expenses
        
        # Dispatch to specific scenario logic
        if scenario_type == 'reclassification':
            return _simulate_reclassification(cursor, company_id, baseline_profit, parameters)
        elif scenario_type == 'timing':
            return _simulate_timing(cursor, company_id, baseline_revenue, baseline_profit, parameters)
        elif scenario_type == 'add_back':
            return _simulate_add_back(cursor, company_id, baseline_profit, parameters)
        elif scenario_type == 'controls_remediation':
            return _simulate_controls_remediation(cursor, company_id, baseline_profit, parameters)
            
    finally:
        conn.close()

def _simulate_reclassification(cursor, company_id: int, baseline_profit: float, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulates recategorizing expenses (e.g., from an operational expense to owner draw).
    Owner draws do not hit the P&L, thus increasing Net Profit.
    """
    target_category = params.get('target_category', '')
    if not target_category:
        return {"status": "error", "message": "Target category is required for reclassification."}
        
    # Find transactions matching the criteria
    query = "SELECT id, trans_date, description, amount, category FROM transactions WHERE company_id = ? AND category = ?"
    q_params = [company_id, target_category]
    
    if params.get('vendor_match'):
        query += " AND description LIKE ?"
        q_params.append(f"%{params['vendor_match']}%")
        
    cursor.execute(query, q_params)
    affected_rows = cursor.fetchall()
    
    if not affected_rows:
        return {"status": "insufficient_evidence", "message": "No transactions match the proposed reclassification criteria."}
        
    total_reclass_amount = sum(abs(row['amount']) for row in affected_rows if row['amount'] < 0)
    
    adjusted_profit = baseline_profit + total_reclass_amount
    
    evidence_links = [{"type": "transaction", "id": row['id'], "description": row['description'], "amount": row['amount']} for row in affected_rows]
    
    return {
        "status": "success",
        "scenario": "Reclassification",
        "baseline_profit": baseline_profit,
        "adjusted_profit": adjusted_profit,
        "delta": total_reclass_amount,
        "assumptions": f"Assumes {len(affected_rows)} transactions categorized as '{target_category}' are reclassified to a non-P&L equity account.",
        "confidence": 85, # Deterministic math, but depends on user judgment
        "affected_count": len(affected_rows),
        "evidence_links": evidence_links
    }

def _simulate_timing(cursor, company_id: int, baseline_revenue: float, baseline_profit: float, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulates deferring revenue recognition (e.g., matching GAAP requirements for prepaid contracts).
    """
    deferral_percentage = float(params.get('deferral_percentage', 0))
    if not (0 < deferral_percentage <= 100):
         return {"status": "error", "message": "Invalid deferral percentage."}
         
    # Find large deposits that might be prepaid contracts
    threshold = float(params.get('threshold', 5000))
    query = "SELECT id, trans_date, description, amount FROM transactions WHERE company_id = ? AND amount > ?"
    cursor.execute(query, (company_id, threshold))
    affected_rows = cursor.fetchall()
    
    if not affected_rows:
        return {"status": "insufficient_evidence", "message": f"No large deposits over ${threshold} found for matching."}
        
    total_eligible = sum(row['amount'] for row in affected_rows)
    deferred_amount = total_eligible * (deferral_percentage / 100.0)
    
    adjusted_profit = baseline_profit - deferred_amount
    
    evidence_links = [{"type": "transaction", "id": row['id'], "description": row['description'], "amount": row['amount']} for row in affected_rows]
    
    return {
        "status": "success",
        "scenario": "Revenue Timing Deferral",
        "baseline_profit": baseline_profit,
        "adjusted_profit": adjusted_profit,
        "delta": -deferred_amount,
        "assumptions": f"Deferred {deferral_percentage}% of {len(affected_rows)} major deposits (over ${threshold}) to a future period liability account.",
        "confidence": 75,
        "affected_count": len(affected_rows),
        "evidence_links": evidence_links
    }

def _simulate_add_back(cursor, company_id: int, baseline_profit: float, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    EBITDA Normalization: Adds back one-time expenses or discretionary owner spending.
    """
    # Simply sum all transactions marked 'is_personal = 1' or matching a specific query
    query = "SELECT id, trans_date, description, amount FROM transactions WHERE company_id = ? AND is_personal = 1"
    cursor.execute(query, (company_id,))
    affected_rows = cursor.fetchall()
    
    if not affected_rows:
        return {"status": "insufficient_evidence", "message": "No transactions are currently flagged as personal/discretionary for add-backs."}
        
    total_add_back = sum(abs(row['amount']) for row in affected_rows if row['amount'] < 0)
    
    adjusted_profit = baseline_profit + total_add_back
    evidence_links = [{"type": "transaction", "id": row['id'], "description": row['description'], "amount": row['amount']} for row in affected_rows]
    
    return {
        "status": "success",
        "scenario": "EBITDA Normalization / Add-backs",
        "baseline_profit": baseline_profit,
        "adjusted_profit": adjusted_profit,
        "delta": total_add_back,
        "assumptions": f"Added back {len(affected_rows)} highly discretionary or personal expenses to normalize operational cash flow.",
        "confidence": 95,
        "affected_count": len(affected_rows),
        "evidence_links": evidence_links
    }

def _simulate_controls_remediation(cursor, company_id: int, baseline_profit: float, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remediation impact estimates: simulates cash savings if duplicate payments or flagged transactions were prevented.
    """
    query = "SELECT id, trans_date, description, amount FROM transactions WHERE company_id = ? AND is_flagged = 1"
    cursor.execute(query, (company_id,))
    affected_rows = cursor.fetchall()
    
    if not affected_rows:
        return {"status": "insufficient_evidence", "message": "No flagged transactions found to simulate remediation against."}
        
    total_savings = sum(abs(row['amount']) for row in affected_rows if row['amount'] < 0)
    
    adjusted_profit = baseline_profit + total_savings
    evidence_links = [{"type": "transaction", "id": row['id'], "description": row['description'], "amount": row['amount']} for row in affected_rows]
    
    return {
        "status": "success",
        "scenario": "Control Remediation Savings",
        "baseline_profit": baseline_profit,
        "adjusted_profit": adjusted_profit,
        "delta": total_savings,
        "assumptions": f"Simulates {len(affected_rows)} historical flagged/duplicate payments being completely blocked by preventative internal controls.",
        "confidence": 90,
        "affected_count": len(affected_rows),
        "evidence_links": evidence_links
    }
