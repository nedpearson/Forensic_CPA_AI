from typing import Dict, Any
from database import get_db

def _calc_financials(txns: list) -> Dict[str, Any]:
    revenue = 0.0
    cogs = 0.0
    opex = 0.0
    other_income = 0.0
    debt_service = 0.0
    ar = 0.0
    ap = 0.0
    current_assets = 0.0
    current_liabilities = 0.0

    for t in txns:
        amt = float(t['amount'] or 0.0)
        cat = str(t['category'] or '').lower()
        desc = str(t['description'] or '').lower()
        
        # P&L matching
        if amt > 0:
            if 'unearned' in cat or 'liability' in cat or 'loan' in cat:
                current_liabilities += amt
            elif 'revenue' in cat or 'sales' in cat or 'deposit' in cat or 'income' in cat:
                revenue += amt
            elif 'receivable' in cat or 'ar' == cat or 'a/r' in cat:
                ar += amt
            else:
                other_income += amt
                
        elif amt < 0:
            abs_amt = abs(amt)
            if 'cogs' in cat or 'cost of goods' in cat or 'inventory' in cat or ('vendor' in desc and 'inventory' in cat):
                cogs += abs_amt
            elif 'loan' in cat or 'debt' in cat or 'interest' in cat:
                debt_service += abs_amt
                current_liabilities += abs_amt # Adds to total debt
            elif 'payable' in cat or 'ap' == cat or 'a/p' in cat:
                ap += abs_amt
                current_liabilities += abs_amt # Accounts payable
            elif 'capitalization' in cat or 'fixed asset' in cat:
                current_assets += abs_amt # Move out of P&L into Assets
            elif 'owner draw' in cat or 'equity' in cat:
                pass # Doesn't touch P&L or liabilities, just equity reduction (handled implicitly by cash drop)
            else:
                opex += abs_amt

    # Assets & Liabilities bounds
    # Cash proxy = all deposits - all withdrawals, minus non-cash adjustments (which we tracked via variables)
    net_cash_flow = sum([float(t['amount'] or 0.0) for t in txns])
    current_assets += net_cash_flow
    current_assets += ar
    
    gross_profit = revenue - cogs
    operating_income = gross_profit - opex
    net_income = operating_income + other_income - debt_service
    
    # Ratios
    gross_margin = (gross_profit / revenue * 100) if revenue > 0 else 0.0
    operating_margin = (operating_income / revenue * 100) if revenue > 0 else 0.0
    current_ratio = (current_assets / current_liabilities) if current_liabilities > 0 else 999.0
    dscr = (operating_income / debt_service) if debt_service > 0 else 999.0
    
    ar_days = (ar / revenue * 365) if revenue > 0 else 0.0
    ap_days = (ap / cogs * 365) if cogs > 0 else 0.0

    return {
        "pnl": {
            "revenue": round(revenue, 2),
            "cogs": round(cogs, 2),
            "gross_profit": round(gross_profit, 2),
            "operating_expenses": round(opex, 2),
            "operating_income": round(operating_income, 2),
            "net_income": round(net_income, 2)
        },
        "balance_sheet": {
            "assets": round(current_assets, 2),
            "liabilities": round(current_liabilities, 2),
            "equity": round(current_assets - current_liabilities, 2),
            "ar_proxy": round(ar, 2),
            "ap_proxy": round(ap, 2)
        },
        "ratios": {
            "gross_margin": round(gross_margin, 2),
            "operating_margin": round(operating_margin, 2),
            "current_ratio": round(current_ratio, 2),
            "dscr": round(dscr, 2),
            "ar_days": round(ar_days, 1),
            "ap_days": round(ap_days, 1)
        }
    }

def run_simulation(
    company_id: int, 
    scenario_type: str, 
    parameters: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Executes a financial simulation based on underlying transactions.
    Guardrails: No books are modified (read-only queries).
    Includes Statement Impact Computation (P&L, BS, Ratios)
    """
    if scenario_type not in ['reclassification', 'timing', 'add_back', 'controls_remediation', 'capitalization']:
        return {"status": "error", "message": "Invalid scenario type. Must be GAAP-compliant simulation."}
        
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Fetch all baseline transactions
        cursor.execute("SELECT id, trans_date, description, amount, category, is_flagged, is_personal FROM transactions WHERE company_id = ?", (company_id,))
        baseline_txns = [dict(r) for r in cursor.fetchall()]
        
        # Dispatch to specific scenario logic
        if scenario_type == 'reclassification':
            adjusted_txns, affected, reasoning = _simulate_reclassification(baseline_txns, parameters)
        elif scenario_type == 'timing':
            adjusted_txns, affected, reasoning = _simulate_timing(baseline_txns, parameters)
        elif scenario_type == 'add_back':
            adjusted_txns, affected, reasoning = _simulate_add_back(baseline_txns, parameters)
        elif scenario_type == 'controls_remediation':
            adjusted_txns, affected, reasoning = _simulate_controls_remediation(baseline_txns, parameters)
        elif scenario_type == 'capitalization':
            adjusted_txns, affected, reasoning = _simulate_capitalization(baseline_txns, parameters)
        else:
            return {"status": "error", "message": "Unhandled scenario type"}
            
        if affected == 0:
            return {"status": "insufficient_evidence", "message": "No transactions matched the criteria for this specific simulation. Try adjusting filters or threshold."}
            
        baseline_financials = _calc_financials(baseline_txns)
        adjusted_financials = _calc_financials(adjusted_txns)
        
        # Calculate Delta in Net Income
        delta = adjusted_financials['pnl']['net_income'] - baseline_financials['pnl']['net_income']
        
        return {
            "status": "success",
            "scenario": scenario_type.replace('_', ' ').title(),
            "baseline": baseline_financials,
            "adjusted": adjusted_financials,
            "delta": round(delta, 2),
            "assumptions": reasoning['assumptions'],
            "confidence": reasoning['confidence'],
            "affected_count": affected,
            "evidence_links": reasoning['evidence_links'],
            "gaap_notes": reasoning.get('gaap_notes', "Simulated for internal analytic purposes only.")
        }
    except Exception as e:
        import traceback
        return {"status": "error", "message": f"Engine failed: {e}", "trace": traceback.format_exc()}
    finally:
        conn.close()

def _simulate_reclassification(txns, params):
    target_category = params.get('target_category', '').lower()
    new_category = params.get('new_category', 'Owner Draw').lower()
    vendor_match = params.get('vendor_match', '').lower()
    
    adjusted = []
    affected_nodes = []
    
    for t in txns:
        t_copy = dict(t)
        match = True
        
        if target_category and target_category not in str(t['category']).lower():
            match = False
        if vendor_match and vendor_match not in str(t['description']).lower():
            match = False
            
        if match and t['amount'] < 0:
            t_copy['category'] = new_category
            affected_nodes.append({"type": "transaction", "id": t['id'], "description": t['description'], "amount": t['amount']})
            
        adjusted.append(t_copy)
        
    reasoning = {
        "assumptions": f"Reclassified {len(affected_nodes)} transactions matching criteria from OPEX to '{new_category.title()}'.",
        "confidence": 85,
        "evidence_links": affected_nodes,
        "gaap_notes": "Entity-level reclassification simulation."
    }
    return adjusted, len(affected_nodes), reasoning

def _simulate_timing(txns, params):
    threshold = float(params.get('threshold', 5000))
    deferral_percentage = float(params.get('deferral_percentage', 50)) / 100.0
    
    adjusted = []
    affected_nodes = []
    
    for t in txns:
        if t['amount'] > threshold and 'deposit' in str(t['category']).lower():
            t_copy = dict(t)
            # Reduce recognized revenue
            t_copy['amount'] = t['amount'] * (1 - deferral_percentage)
            
            # Create the unearned offset (Liability). The cash didn't physically leave the bank, but NI dropped.
            # To preserve cash proxy: dummy liability transaction that offsets the revenue drop for cash calculations
            dummy = dict(t)
            dummy['amount'] = t['amount'] * deferral_percentage
            dummy['category'] = 'Unearned Revenue / Loan'
            
            affected_nodes.append({"type": "transaction", "id": t['id'], "description": t['description'], "amount": t['amount']})
            adjusted.append(t_copy)
            adjusted.append(dummy)
        else:
            adjusted.append(dict(t))
            
    reasoning = {
        "assumptions": f"Deferred {deferral_percentage*100}% of {len(affected_nodes)} material deposits (over ${threshold}) to a future liability account (Unearned Revenue).",
        "confidence": 75,
        "evidence_links": affected_nodes,
        "gaap_notes": "ASC 606 Revenue Recognition timing constraint."
    }
    return adjusted, len(affected_nodes), reasoning

def _simulate_add_back(txns, params):
    adjusted = []
    affected_nodes = []
    
    for t in txns:
        t_copy = dict(t)
        if t.get('is_personal') == 1 and t['amount'] < 0:
            # Change from expense to equity draw
            t_copy['category'] = 'Owner Draw'
            affected_nodes.append({"type": "transaction", "id": t['id'], "description": t['description'], "amount": t['amount']})
        adjusted.append(t_copy)
        
    reasoning = {
        "assumptions": f"Removed {len(affected_nodes)} detected personal/discretionary expenses to normalize operating cash flow into an EBITDA proxy.",
        "confidence": 95,
        "evidence_links": affected_nodes,
        "gaap_notes": "Non-GAAP EBITDA normalization framework."
    }
    return adjusted, len(affected_nodes), reasoning

def _simulate_controls_remediation(txns, params):
    adjusted = []
    affected_nodes = []
    
    for t in txns:
        if t.get('is_flagged') == 1 and t['amount'] < 0:
            # Prevented -> transaction didn't occur.
            affected_nodes.append({"type": "transaction", "id": t['id'], "description": t['description'], "amount": t['amount']})
            continue 
        adjusted.append(dict(t))
        
    reasoning = {
        "assumptions": f"Simulates 100% prevention of {len(affected_nodes)} flagged anomalous outflows via strictly internal routing controls.",
        "confidence": 90,
        "evidence_links": affected_nodes,
        "gaap_notes": "Internal Audit forward-looking remediation impact."
    }
    return adjusted, len(affected_nodes), reasoning

def _simulate_capitalization(txns, params):
    threshold = float(params.get('threshold', 2500))
    adjusted = []
    affected_nodes = []
    
    for t in txns:
        t_copy = dict(t)
        cat_lower = str(t['category']).lower()
        if t['amount'] < -threshold and t.get('is_personal') != 1 and 'loan' not in cat_lower and 'fixed asset' not in cat_lower and 'capital' not in cat_lower:
            t_copy['category'] = 'Fixed Asset Capitalization'
            affected_nodes.append({"type": "transaction", "id": t['id'], "description": t['description'], "amount": t['amount']})
        adjusted.append(t_copy)
        
    reasoning = {
        "assumptions": f"Capitalized {len(affected_nodes)} material expenses over ${threshold}, stripping the immediate hit from the P&L and moving it to the Balance Sheet proxy.",
        "confidence": 70,
        "evidence_links": affected_nodes,
        "gaap_notes": "ASC 360 Property, Plant & Equipment initial recognition simulation. Ignores fractional first-year depreciation."
    }
    return adjusted, len(affected_nodes), reasoning
