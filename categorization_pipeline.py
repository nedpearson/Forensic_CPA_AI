from database import get_db, get_category_rules
from merchant_normalizer import MerchantNormalizer
import re
from collections import defaultdict

class CategorizationPipeline:
    
    @staticmethod
    def process_transaction(user_id: int, raw_desc: str, amount: float, trans_type: str = 'debit', trans_date: str = None, account_id: int = None, cache: dict = None) -> dict:
        """
        Phase 9: Multi-Signal Weighted Categorization Pipeline.
        Evaluates explicit rules, learned aliases, and historical quantitative signals to form a confidence score.
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
            'categorization_status': 'review_required',
            'categorization_explanation': 'No rules matched.'
        }
        
        cleaned_desc = MerchantNormalizer.clean_raw_string(raw_desc)
        candidates = defaultdict(lambda: {
            'score': 0.0, 
            'signals': [], 
            'subcategory': None,
            'is_personal': 0, 
            'is_business': 0, 
            'is_transfer': 0, 
            'merchant_id': None,
            'source': 'weighted_inference'
        })
        
        conn = get_db()
        cursor = conn.cursor()
        
        # --- Signal 1: Merchant Identity & Alias (Weight: 0.8) ---
        merchant_dict = MerchantNormalizer.resolve_merchant(user_id, raw_desc, cache=cache)
        merchant_id = merchant_dict['id'] if merchant_dict else None
        
        if merchant_dict and merchant_dict.get('default_category_id'):
            cat_name = None
            if cache is not None and 'categories' in cache:
                cat_name = cache['categories'].get(merchant_dict['default_category_id'])
            else:
                cursor.execute("SELECT name FROM categories WHERE id = ?", (merchant_dict['default_category_id'],))
                cat_row = cursor.fetchone()
                if cat_row:
                    cat_name = cat_row['name']
                    
            if cat_name:
                candidates[cat_name]['score'] += 0.8
                candidates[cat_name]['signals'].append("Matched learned merchant identity (+0.8)")
                candidates[cat_name]['merchant_id'] = merchant_id
                candidates[cat_name]['is_personal'] = merchant_dict.get('is_personal', 0)
                candidates[cat_name]['is_business'] = merchant_dict.get('is_business', 0)
                candidates[cat_name]['is_transfer'] = merchant_dict.get('is_transfer', 0)
                candidates[cat_name]['source'] = 'learned_rule'

        # --- Phase 11: Merchant Contextual Overrides ---
        if merchant_id and account_id:
            # Look up account type context
            acct_type = None
            if cache is not None and 'account_type' in cache:
                acct_type = cache['account_type']
            else:
                cursor.execute("SELECT account_type FROM accounts WHERE id = ?", (account_id,))
                acct_row = cursor.fetchone()
                if acct_row:
                    acct_type = acct_row['account_type']
                    
            if acct_type:
                # Check for an active Context Rule
                context_rule = None
                if cache is not None and 'context_rules' in cache:
                    context_rule = cache['context_rules'].get((merchant_id, acct_type))
                else:
                    cursor.execute("""
                        SELECT mcr.mapped_category_id, mcr.priority, c.name as category_name
                        FROM merchant_context_rules mcr
                        JOIN categories c ON mcr.mapped_category_id = c.id
                        WHERE mcr.user_id = ? AND mcr.merchant_id = ? 
                              AND mcr.context_type = 'account_type' AND mcr.context_value = ?
                        ORDER BY mcr.priority DESC LIMIT 1
                    """, (user_id, merchant_id, acct_type))
                    context_rule = cursor.fetchone()
                    
                if context_rule:
                    ctx_cat = context_rule['category_name']
                    base_bonus = context_rule['priority'] / 100.0
                    
                    if ctx_cat not in candidates:
                        candidates[ctx_cat] = {
                            'score': 0.0, 
                            'signals': [], 
                            'source': 'context_rule', 
                            'merchant_id': merchant_id,
                            'subcategory': None,
                            'is_personal': 0,
                            'is_business': 0,
                            'is_transfer': 0
                        }
                    
                    # Phase 11 Guard: In order for Context to override a learned Base Mapping safely, 
                    # we grant a definitive priority boost so it wins ties or strongly nudges history.
                    effective_bonus = base_bonus + 0.30
                    
                    candidates[ctx_cat]['score'] += effective_bonus
                    candidates[ctx_cat]['signals'].append(f"Context match ({acct_type}) override (+{effective_bonus:.2f})")
                    candidates[ctx_cat]['source'] = 'context_rule'
                    candidates[ctx_cat]['merchant_id'] = merchant_id

        # --- Signal 2: Deterministic Rules (Weight: priority / 100) ---
        if cache is not None and 'rules' in cache:
            rules = cache['rules']
        else:
            try:
                rules = get_category_rules(user_id)
            except Exception:
                cursor.execute("SELECT * FROM category_rules WHERE user_id = ? ORDER BY priority DESC", (user_id,))
                rules = [dict(r) for r in cursor.fetchall()]

        for rule in rules:
            pattern = rule['pattern']
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
                cat_name = rule['category']
                priority = rule.get('priority', 50)
                
                # Absolute Explicit Overrides short-circuit the weighted pipeline
                if priority >= 100:
                    conn.close()
                    result.update({
                        'category': cat_name,
                        'subcategory': rule.get('subcategory'),
                        'is_personal': rule.get('is_personal', 0),
                        'is_business': rule.get('is_business', 0),
                        'is_transfer': rule.get('is_transfer', 0),
                        'merchant_id': merchant_id,
                        'categorization_source': 'deterministic_rule',
                        'categorization_confidence': 1.0,
                        'categorization_status': 'auto_applied',
                        'categorization_explanation': f"Absolute rule match: {pattern}"
                    })
                    return result
                
                weight = priority / 100.0
                candidates[cat_name]['score'] += weight
                candidates[cat_name]['signals'].append(f"Matched rule priority {priority} (+{weight:.2f})")
                candidates[cat_name]['subcategory'] = rule.get('subcategory')
                candidates[cat_name]['is_personal'] = rule.get('is_personal', 0)
                candidates[cat_name]['is_business'] = rule.get('is_business', 0)
                candidates[cat_name]['is_transfer'] = rule.get('is_transfer', 0)
                candidates[cat_name]['source'] = 'deterministic_rule'
                candidates[cat_name]['rule_priority'] = priority
                candidates[cat_name]['rule_hit_count'] = rule.get('hit_count', 1)

        # --- Signal 3: Historical Amounts & Frequency (Weight: +0.1 to +0.3) ---
        tx_count = 0
        
        hist_rows = []
        if merchant_id or cleaned_desc:
            if cache is not None and 'history_merchant' in cache:
                if merchant_id and merchant_id in cache['history_merchant']:
                    hist_rows = cache['history_merchant'][merchant_id]
            else:
                if cleaned_desc:
                    cursor.execute("""
                        SELECT category, AVG(amount) as avg_amt, COUNT(*) as tx_count 
                        FROM transactions 
                        WHERE user_id = ? AND is_approved = 1 AND category != 'Uncategorized' 
                        AND (merchant_id = ? OR UPPER(description) LIKE ?)
                        GROUP BY category
                    """, (user_id, merchant_id, f"%{cleaned_desc}%"))
                else:
                    cursor.execute("""
                        SELECT category, AVG(amount) as avg_amt, COUNT(*) as tx_count 
                        FROM transactions 
                        WHERE user_id = ? AND is_approved = 1 AND category != 'Uncategorized' 
                        AND merchant_id = ?
                        GROUP BY category
                    """, (user_id, merchant_id))
                hist_rows = cursor.fetchall()
            
            for row in hist_rows:
                cat_name = row['category']
                avg_amt = row['avg_amt']
                tx_count += row['tx_count'] # Accumulate total history
                cat_count = row['tx_count']
                
                # Increment base likelihood for historical matches
                if cat_count > 0:
                    candidates[cat_name]['score'] += 0.1
                    candidates[cat_name]['signals'].append(f"Historical category frequency x{cat_count} (+0.1)")
                    
                # High-signal bonus if amount matches typical historical range (within 20% or $5)
                if amount and avg_amt is not None:
                    allowed_variance = max(5.0, abs(avg_amt) * 0.20)
                    if abs(amount - avg_amt) <= allowed_variance:
                        candidates[cat_name]['score'] += 0.2
                        candidates[cat_name]['signals'].append(f"Historical amount match ~${avg_amt:.2f} (+0.2)")
                    elif abs(amount - avg_amt) > max(50.0, abs(avg_amt) * 2.0):
                        candidates[cat_name]['score'] -= 0.3
                        candidates[cat_name]['signals'].append(f"Amount highly deviates from avg ${avg_amt:.2f} (-0.3)")

        # --- Evaluate Weighted Signals & Handle Conflicts ---
        if candidates:
            best_cat = max(candidates.keys(), key=lambda k: candidates[k]['score'])
            best_data = candidates[best_cat]
            conf = min(1.0, best_data['score'])
            
            # Phase 12/13: Safe Autopilot Gating
            is_safe_autopilot = (best_data['source'] == 'deterministic_rule' and 
                                 best_data.get('rule_priority', 0) >= 80 and 
                                 best_data.get('rule_hit_count', 1) >= 3)
                                 
            if is_safe_autopilot:
                conf = max(conf, 0.90)
                best_data['signals'].append("Safe Autopilot Gating: Strong learned pattern bypasses review")
            
            # Phase 10: Precision-Safe Penalties
            # 1. Sparse History Penalty
            if tx_count < 3 and not is_safe_autopilot:
                conf -= 0.15
                best_data['signals'].append("Sparse history penalty (-0.15)")
                
            # 2. Ambiguous Merchant Penalty
            ambiguous_prefixes = ['SQ *', 'TST*', 'PAYPAL *', 'UBER *', 'AMZN MKTP ']
            is_ambiguous = any(raw_desc.upper().startswith(p) for p in ambiguous_prefixes) or len(cleaned_desc) < 5
            if is_ambiguous and not best_data['merchant_id']:
                conf -= 0.2
                best_data['signals'].append("Ambiguous text without exact alias map (-0.2)")
                
            # 3. Broad Rule Capping
            if conf >= 0.90 and tx_count < 3 and best_data['source'] == 'deterministic_rule' and not best_data['merchant_id'] and not is_safe_autopilot:
                conf = 0.89  # Hard cap broad rules from reaching auto-apply without evidence
                best_data['signals'].append("Capped broad rule to 0.89 without history")

            # 4. Decayed or Weak Rule Capping
            if conf >= 0.90 and best_data['source'] == 'deterministic_rule' and not is_safe_autopilot:
                conf = 0.89
                best_data['signals'].append("Capped weak/decayed rule to 0.89 to prevent unsafe auto-apply")

            conf = max(0.0, conf) # Floor at 0.0
            explanation = "; ".join(best_data['signals'])
            
            # Conflict Check: Were any other categories heavily scored?
            conflicts = [c for c in candidates if c != best_cat and candidates[c]['score'] >= 0.4]
            if conflicts:
                conf -= 0.3 # Slash confidence safely
                conf = max(0.0, conf)
                explanation += f" | NOTE: Conflicting evidence found for {', '.join(conflicts)}."
                
            # Phase 10: Refined Calibration Status Bounds
            status = 'auto_applied' if conf >= 0.90 else ('suggested' if conf >= 0.65 else 'review_required')
            
            result.update({
                'category': best_cat,
                'subcategory': best_data['subcategory'],
                'is_personal': best_data['is_personal'],
                'is_business': best_data['is_business'],
                'is_transfer': best_data['is_transfer'],
                'merchant_id': best_data['merchant_id'] or merchant_id,
                'categorization_source': best_data['source'],
                'categorization_confidence': round(conf, 2),
                'categorization_status': status,
                'categorization_explanation': explanation
            })
        else:
            if merchant_id:
                result['merchant_id'] = merchant_id
                
        conn.close()
        return result
