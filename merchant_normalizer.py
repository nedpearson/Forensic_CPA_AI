import re
from database import get_db

class MerchantNormalizer:
    
    @staticmethod
    def clean_raw_string(raw_desc: str) -> str:
        """
        Strips common bank noise (dates, store hex codes, "POS PURCHASE", etc.)
        from a raw transaction description to yield a clean, matchable string.
        """
        if not raw_desc:
            return ""
            
        desc = raw_desc.upper().strip()
        
        # 1. Remove POS/Card prefixes
        desc = re.sub(r'^POS\s+PURCHASE\s+(?:(?:NON-PIN|WITH PIN)\s+)?', '', desc)
        desc = re.sub(r'^RECURRING\s+PAYMENT\s+AUTHORIZED\s+ON\s+\d{2}/\d{2}\s+', '', desc)
        desc = re.sub(r'^PURCHASE\s+AUTHORIZED\s+ON\s+\d{2}/\d{2}\s+', '', desc)
        desc = re.sub(r'^CARD\s+\d{4}\s+', '', desc)
        
        # 2. Remove trailing dates or location IDs (e.g., 12/31, #1234)
        desc = re.sub(r'\s+\d{2}/\d{2}$', '', desc)
        desc = re.sub(r'\s+#\d{3,}$', '', desc)
        
        # 3. Strip long alphanumeric hex codes or phone numbers commonly left by gateways
        # e.g. TST* WILLIES 800-555-1234 -> TST* WILLIES
        desc = re.sub(r'\s+\d{3}-\d{3}-\d{4}.*$', '', desc)
        desc = re.sub(r'\s+[A-Z0-9]{8,}.*$', '', desc) # Long hashed IDs
        
        # 4. Strip excessive numbers trailing the string 
        desc = re.sub(r'\s+\d{4,}\s*$', '', desc)
        
        # 5. Clean up leading TST* or SQ * from POS terminals if we want pure names
        # Actually, often users want to keep "SQ *" or "TST *" as it's part of the raw pattern matching,
        # but let's standardize spacing.
        desc = re.sub(r'^TST\s*\*\s*', 'TST* ', desc)
        desc = re.sub(r'^SQ\s*\*\s*', 'SQ* ', desc)
        desc = re.sub(r'^SP\s*\*\s*', 'SP* ', desc)
        
        return desc.strip()[:60] # Cap length

    @staticmethod
    def resolve_merchant(user_id: int, raw_desc: str) -> tuple[int, str, int] | tuple[None, None, None]:
        """
        Looks up a raw transaction description in the `merchant_aliases` table.
        Returns (merchant_id, canonical_name, default_category_id) if found, else None.
        """
        if not raw_desc:
            return None, None, None
            
        cleaned = MerchantNormalizer.clean_raw_string(raw_desc)
        
        conn = get_db()
        cursor = conn.cursor()
        
        # We check for exact alias match on the cleaned string first
        cursor.execute('''
            SELECT m.id, m.canonical_name, m.default_category_id, m.is_personal, m.is_business, m.is_transfer
            FROM merchant_aliases a
            JOIN merchants m ON a.merchant_id = m.id
            WHERE a.user_id = ? AND a.raw_pattern = ?
        ''', (user_id, cleaned))
        
        row = cursor.fetchone()
        
        if not row:
            # Fallback: check if the canonical name itself matches exactly
            cursor.execute('''
                SELECT id, canonical_name, default_category_id, is_personal, is_business, is_transfer
                FROM merchants 
                WHERE user_id = ? AND canonical_name = ?
            ''', (user_id, cleaned))
            row = cursor.fetchone()
            
        conn.close()
        
        if row:
            return dict(row)
            
        return None

    @staticmethod
    def learn_merchant_alias(user_id: int, raw_desc: str, canonical_name: str, category_id: int = None, is_transfer=0, is_personal=0, is_business=0):
        """
        Creates or updates a merchant identity and links the raw string as an alias.
        """
        if not raw_desc or not canonical_name:
            return None
            
        cleaned_alias = MerchantNormalizer.clean_raw_string(raw_desc)
        canonical_name = canonical_name.upper().strip()
        
        conn = get_db()
        cursor = conn.cursor()
        
        # 1. Ensure Merchant Exists
        cursor.execute("SELECT id FROM merchants WHERE user_id = ? AND canonical_name = ?", (user_id, canonical_name))
        m_row = cursor.fetchone()
        
        if m_row:
            merchant_id = m_row['id']
            # Optionally update defaults if explicitly provided
            if category_id is not None:
                cursor.execute("""
                    UPDATE merchants 
                    SET default_category_id = ?, is_transfer = ?, is_personal = ?, is_business = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (category_id, is_transfer, is_personal, is_business, merchant_id))
        else:
            cursor.execute("""
                INSERT INTO merchants (user_id, canonical_name, default_category_id, is_transfer, is_personal, is_business)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, canonical_name, category_id, is_transfer, is_personal, is_business))
            merchant_id = cursor.lastrowid
            
        # 2. Add Alias if not exists
        cursor.execute("SELECT id FROM merchant_aliases WHERE user_id = ? AND merchant_id = ? AND raw_pattern = ?", 
                      (user_id, merchant_id, cleaned_alias))
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO merchant_aliases (user_id, merchant_id, raw_pattern)
                VALUES (?, ?, ?)
            """, (user_id, merchant_id, cleaned_alias))
            
        conn.commit()
        conn.close()
        
        return merchant_id
