from database import get_db, get_category_rules
from merchant_normalizer import MerchantNormalizer
import re

class CategorizationPipeline:
    
    @staticmethod
    def process_transaction(user_id: int, raw_desc: str, amount: float, trans_type: str = 'debit') -> dict:
        """
        The definitive 5-tier orchestration pipeline for categorizing a transaction.
        Executes rules in strict precedence order.
        """
        result = {
            'category': 'Uncategorized',
            'subcategory': None,
            'is_personal': 0,
            'is_business': 0,
            'is_transfer': 0,
            'merchant_id': None,
            'categorization_source': 'system_default',
            'categorization_confidence': 0.0,
            'categorization_status': 'suggested',
            'categorization_explanation': 'No rules matched.'
        }
        
        cleaned_desc = MerchantNormalizer.clean_raw_string(raw_desc)
        
        # ---------------------------------------------------------
        # Precedence 1: Explicit User Override (Handled by DB Layer/Updates, not during ingestion)
        # Note: If predicting for an existing row mapped manually, we skip. 
        # But this function is usually called on NEW transactions or bulk-recat.
        # ---------------------------------------------------------
        
        # ---------------------------------------------------------
        # Precedence 2: User Learned Alias Mapping (Rank 1 for auto-cat)
        # ---------------------------------------------------------
        conn = get_db()
        cursor = conn.cursor()
        
        # Fetch the canonical merchant and its default category if it has an alias
        merchant_dict = MerchantNormalizer.resolve_merchant(user_id, raw_desc)
        merchant_id = merchant_dict['id'] if merchant_dict else None
        
        if merchant_dict and merchant_dict.get('default_category_id'):
            # We found a mapped merchant alias! Look up the category details
            cursor.execute("SELECT name FROM categories WHERE id = ?", (merchant_dict['default_category_id'],))
            cat_row = cursor.fetchone()
            if cat_row:
                result.update({
                    'category': cat_row['name'],
                    'merchant_id': merchant_dict['id'],
                    'is_personal': merchant_dict.get('is_personal', 0),
                    'is_business': merchant_dict.get('is_business', 0),
                    'is_transfer': merchant_dict.get('is_transfer', 0),
                    'categorization_source': 'learned_rule',
                    'categorization_confidence': 1.0,
                    'categorization_status': 'auto_applied',
                    'categorization_explanation': f"Matched specific learned alias for {merchant_dict.get('canonical_name', raw_desc)}"
                })
                conn.close()
                return result

        # ---------------------------------------------------------
        # Precedence 3: Deterministic Regex/Keyword Rules
        # ---------------------------------------------------------
        # We fetch rules ordered by priority DESC.
        try:
            rules = get_category_rules(user_id)
        except Exception:
            # Safe fallback if get_category_rules doesn't exist yet
            cursor.execute("SELECT * FROM category_rules WHERE user_id = ? ORDER BY priority DESC", (user_id,))
            rules = [dict(r) for r in cursor.fetchall()]

        conn.close()
        
        for rule in rules:
            pattern = rule['pattern']
            # Convert SQL LIKE pattern (%) to Regex (.*) if necessary
            if pattern.startswith('%') and pattern.endswith('%'):
                regex_pattern = re.escape(pattern.strip('%'))
                match = re.search(regex_pattern, raw_desc.upper())
            elif '%' in pattern:
                regex_pattern = '^' + re.escape(pattern).replace('\\%', '.*') + '$'
                match = re.match(regex_pattern, raw_desc.upper())
            else:
                regex_pattern = '^' + re.escape(pattern) + '$'
                match = re.match(regex_pattern, raw_desc.upper())
                
            if match:
                result.update({
                    'category': rule['category'],
                    'subcategory': rule.get('subcategory'),
                    'is_personal': rule.get('is_personal', 0),
                    'is_business': rule.get('is_business', 0),
                    'is_transfer': rule.get('is_transfer', 0),
                    'merchant_id': merchant_id, # Can be null if alias not found above
                    'categorization_source': 'deterministic_rule',
                    'categorization_confidence': 1.0,
                    'categorization_status': 'auto_applied',
                    'categorization_explanation': f"Matched hard rule: {pattern}"
                })
                return result

        # ---------------------------------------------------------
        # Precedence 4 & 5: AI Inference / Web Fallback
        # Note: In Phase 3, we stop here and return Uncategorized.
        # The background Bulk AI job will catch this transaction later.
        # ---------------------------------------------------------
        
        # If we got here, but had a merchant without a category, just map the merchant
        if merchant_id:
            result['merchant_id'] = merchant_id
            
        return result
