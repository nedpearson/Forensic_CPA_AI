import os
os.environ['TESTING'] = 'true'
import json

import database
from auto_categorizer import AutoCategorizer, TransactionCategory, TransactionCategorizationBatch

class MockProvider:
    def generate_structured_output(self, prompt, schema):
        # We check the prompt to see if we're doing the single-item fallback (WEB CONTEXT)
        # or the initial bulk pass.
        if "WEB CONTEXT" in prompt:
            results = [
                TransactionCategory(
                    txn_id=2,
                    reasoning="ACH WEB is a payment gateway. Looks like software.",
                    category="Software",
                    subcategory=None,
                    is_personal=False,
                    is_business=True,
                    is_transfer=False,
                    suggested_pattern="%ACH WEB%",
                    confidence_score=0.90,
                    explanation_flags=""
                )
            ]
        else:
            results = [
                TransactionCategory(
                    txn_id=1,
                    reasoning="Looks like a fast food restaurant based on prior history.",
                    category="Dining Output",
                    subcategory=None,
                    is_personal=True,
                    is_business=False,
                    is_transfer=False,
                    suggested_pattern="%MCDONALDS%",
                    confidence_score=0.95,
                    explanation_flags=""
                ),
                TransactionCategory(
                    txn_id=2,
                    reasoning="Generic ACH string, highly variable, unknown vendor.",
                    category="Software",
                    subcategory=None,
                    is_personal=False,
                    is_business=True,
                    is_transfer=False,
                    suggested_pattern="%ACH WEB%",
                    confidence_score=0.45,
                    explanation_flags="Generic ACH, unknown vendor"
                )
            ]
        batch = TransactionCategorizationBatch(results=results)
        return batch

def setup_db():
    db_path = 'test_inference.db'
    if os.path.exists(db_path):
        os.remove(db_path)
    # Override the statically evaluated DB_PATH
    database.DB_PATH = db_path
    
    database.init_db()

    conn = database.get_db()
    cursor = conn.cursor()
    # Insert user
    cursor.execute("INSERT INTO users (email, password_hash) VALUES ('test_ai@example.com', 'has')")
    user_id = cursor.lastrowid
    
    # Insert Categories
    cursor.execute("INSERT INTO categories (user_id, name) VALUES (?, 'Dining Output')", (user_id,))
    cursor.execute("INSERT INTO categories (user_id, name) VALUES (?, 'Software')", (user_id,))
    
    conn.commit()
    conn.close()
    
    # Insert Transactions
    t1, _ = database.add_transaction(user_id=user_id, doc_id=None, account_id=None, trans_date="2023-10-01", post_date="2023-10-01", description="MCDONALDS", amount=-10.0, trans_type="debit", category="Uncategorized")
    t2, _ = database.add_transaction(user_id=user_id, doc_id=None, account_id=None, trans_date="2023-10-01", post_date="2023-10-01", description="ACH WEB ABCDEF", amount=-200.0, trans_type="debit", category="Uncategorized")
    
    # Insert an approved transaction to serve as few-shot
    database.add_transaction(user_id=user_id, doc_id=None, account_id=None, trans_date="2023-09-01", post_date="2023-09-01", description="MCDONALDS 1234", amount=-12.0, trans_type="debit", category="Dining Output", is_approved=1)
    
    return user_id, t1, t2

def run_test():
    uid, t1, t2 = setup_db()
    
    # Run bulk job manually using mock
    from categorizer import run_bulk_ai_categorization
    import threading
    
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions WHERE user_id = ? AND category = 'Uncategorized'", (uid,))
    uncat = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
        # Inject Mock Provider logic
    import auto_categorizer
    original_get = auto_categorizer.get_llm_provider
    try:
        auto_categorizer.get_llm_provider = lambda: MockProvider()
        
        # Override the job to run synchronously for test
        from database import get_categories, update_transaction, add_category_rule, get_db
        
        cats = get_categories(uid)
        tax_ref = [{'name': c['name']} for c in cats]
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT description, amount, category, is_personal, is_business FROM transactions WHERE user_id = ? AND is_approved = 1 AND category != 'Uncategorized' ORDER BY trans_date DESC LIMIT 40", (uid,))
        few_shot_context = [dict(r) for r in cursor.fetchall()]
        conn.close()
        
        categorizer = AutoCategorizer()
        results = categorizer.categorize_transaction_batch(uncat, tax_ref, few_shot_examples=few_shot_context)
        
        for r in results:
            score = r.confidence_score if hasattr(r, 'confidence_score') else 0.5
            
            # --- Phase 5: Internet Lookup Fallback Trigger ---
            lookup_used = False
            if score < 0.85 and r.suggested_pattern:
                # 1. We have low confidence and a clean merchant string
                from internet_lookup import InternetLookupProvider
                from database import get_lookup_cache, set_lookup_cache
                
                lookup_key = r.suggested_pattern.replace('%', '').strip()
                cached_result = get_lookup_cache(lookup_key)
                
                if cached_result is None:
                    # 2. Reach out to public API safely
                    # We inject a mock snippet here to avoid spamming actual Wikipedia in unit tests
                    if "ACH WEB" in lookup_key:
                        cached_result = "ACH WEB is a generic payment gateway."
                    else:
                        cached_result = InternetLookupProvider.search_business_entity(lookup_key)
                        
                    set_lookup_cache(lookup_key, cached_result)
                    
                if cached_result:
                    lookup_used = True
                    # 3. Re-run inference WITH the new internet context
                    cloned_txn = {
                        'id': r.txn_id, 
                        'description': next((t['description'] for t in uncat if t['id'] == r.txn_id), '') + f" (WEB CONTEXT: {cached_result[:300]})", 
                        'amount': next((t['amount'] for t in uncat if t['id'] == r.txn_id), 0),
                        'trans_date': next((t['trans_date'] for t in uncat if t['id'] == r.txn_id), '')
                    }
                    
                    second_pass = categorizer.categorize_transaction_batch([cloned_txn], tax_ref, few_shot_examples=few_shot_context)
                    if second_pass:
                        r = second_pass[0]
                        score = r.confidence_score if hasattr(r, 'confidence_score') else 0.5
            
            if score >= 0.85:
                status = 'auto_applied'
            elif score >= 0.5:
                status = 'suggested'
            else:
                status = 'review_required'
            
            explanation = getattr(r, 'reasoning', '')
            flags = getattr(r, 'explanation_flags', '')
            if flags:
                explanation += f" [Flags: {flags}]"
                
            update_transaction(
                uid, r.txn_id,
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

            if r.suggested_pattern and status == 'auto_applied':
                add_category_rule(
                    uid,
                    r.suggested_pattern,
                    r.category,
                    r.subcategory,
                    1 if r.is_personal else 0,
                    1 if r.is_business else 0,
                    1 if r.is_transfer else 0,
                    40
                )

        # Check DB State
        conn = database.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM transactions WHERE id = ?", (t1,))
        r1 = cursor.fetchone()
        
        cursor.execute("SELECT * FROM transactions WHERE id = ?", (t2,))
        r2 = cursor.fetchone()
        
        cursor.execute("SELECT * FROM category_rules WHERE user_id = ?", (uid,))
        rules = cursor.fetchall()
        
        conn.close()
        
        assert dict(r1)['category'] == 'Dining Output'
        assert dict(r1)['categorization_status'] == 'auto_applied'
        assert dict(r1)['categorization_source'] == 'ai_inference'
        assert dict(r1)['manually_edited'] == 0
        
        assert dict(r2)['category'] == 'Software'
        assert dict(r2)['categorization_status'] == 'auto_applied'
        assert dict(r2)['categorization_source'] == 'internet_lookup'
        assert dict(r2)['manually_edited'] == 0
        
        print(f"Rules created: {len(rules)}")
        
        print("OK All LLM Inference pipeline and persistence checks passed!")
    finally:
        auto_categorizer.get_llm_provider = original_get

if __name__ == '__main__':
    run_test()
