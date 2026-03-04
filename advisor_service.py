import json
from database import get_db, build_filter_clause
from categorizer import get_executive_summary, get_deposit_aging, get_recipient_analysis
from typing import Dict, Any

def get_advisor_aggregation_payload(user_id: int, company_id: int) -> Dict[str, Any]:
    """
    Safely aggregates all domain-scoped active company records
    to form the deterministic payload for the LLM Advisor.
    """
    # Enforce company scoping using the built-in deterministic query builder
    filters = {'company_id': company_id} if company_id else None
    
    conn = get_db()
    cursor = conn.cursor()
    
    payload = {
        "company_id": company_id,
        "user_id": user_id,
        "metadata": {},
        "documents": [],
        "accounts": [],
        "flagged_transactions": [],
        "analytics": {}
    }
    
    try:
        # 1. Gather active company metadata
        if company_id:
            cursor.execute("SELECT name, created_at FROM companies WHERE id = ?", (company_id,))
            cat_row = cursor.fetchone()
            if cat_row:
                payload['metadata']['company_name'] = cat_row['name']
                payload['metadata']['created_at'] = cat_row['created_at']

        # 2. Gather Document Metadata (Deterministic Context)
        if company_id:
            cursor.execute("SELECT id as document_id, filename, file_type, statement_start_date, statement_end_date, upload_date FROM documents WHERE company_id = ?", (company_id,))
        else:
            cursor.execute("SELECT id as document_id, filename, file_type, statement_start_date, statement_end_date, upload_date FROM documents WHERE user_id = ? AND company_id IS NULL", (user_id,))
        payload['documents'] = [dict(row) for row in cursor.fetchall()]

        # 3. Gather Account Structures
        if company_id:
            cursor.execute("SELECT id as account_id, account_name as name, account_type as type, institution FROM accounts WHERE company_id = ?", (company_id,))
        else:
            cursor.execute("SELECT id as account_id, account_name as name, account_type as type, institution FROM accounts WHERE user_id = ? AND company_id IS NULL", (user_id,))
        payload['accounts'] = [dict(row) for row in cursor.fetchall()]

        # 4. Gather Flagged / Critical Transactions (Limited to 200 for token safety)
        where, params = build_filter_clause(user_id, filters)
        cursor.execute(f"""
            SELECT id as transaction_id, trans_date, description, amount, trans_type, 
                   category, is_flagged, flag_reason, is_personal, is_transfer 
            FROM transactions 
            {where} AND is_flagged = 1 
            ORDER BY trans_date DESC LIMIT 200
        """, params)
        payload['flagged_transactions'] = [dict(row) for row in cursor.fetchall()]

        # 5. Integrate Deterministic Analytics (using existing secure aggregators)
        payload['analytics']['executive_summary'] = get_executive_summary(user_id, filters=filters)
        payload['analytics']['deposit_aging'] = get_deposit_aging(user_id, filters=filters)
        payload['analytics']['recipient_analysis'] = get_recipient_analysis(user_id, filters=filters)

    finally:
        conn.close()

    return payload
