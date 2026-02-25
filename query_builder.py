import sqlite3

class QueryBuilder:
    """
    Translates a FilterSchema (dict) into a parameterized SQL WHERE clause.
    """
    def __init__(self, filters=None):
        self.filters = filters or {}
        self.conditions = []
        self.params = []
        self._build()

    def _build(self):
        f = self.filters

        # 1. View Mode (Personal vs Business)
        view_mode = f.get('view_mode', 'all')
        if view_mode == 'personal':
            self.conditions.append("is_personal = 1")
        elif view_mode == 'business':
            self.conditions.append("is_business = 1")

        # 2. Date Ranges
        date_from = f.get('date_from')
        date_to = f.get('date_to')
        if date_from:
            self.conditions.append("trans_date >= ?")
            self.params.append(date_from)
        if date_to:
            self.conditions.append("trans_date <= ?")
            self.params.append(date_to)

        # 3. Exact Matches
        for field in ['category', 'cardholder_name', 'trans_type', 'account_id', 'payment_method']:
            # Front-end uses 'cardholder' instead of 'cardholder_name'
            lookup_key = 'cardholder' if field == 'cardholder_name' else field
            val = f.get(lookup_key)
            if val:
                self.conditions.append(f"{field} = ?")
                self.params.append(val)

        # 4. Text Search
        search = f.get('search')
        if search:
            self.conditions.append("(description LIKE ? OR user_notes LIKE ?)")
            term = f"%{search}%"
            self.params.extend([term, term])

        # 5. Amounts
        min_amt = f.get('min_amount')
        if min_amt:
            try:
                self.conditions.append("ABS(amount) >= ?")
                self.params.append(float(min_amt))
            except ValueError:
                pass
                
        max_amt = f.get('max_amount')
        if max_amt:
            try:
                self.conditions.append("ABS(amount) <= ?")
                self.params.append(float(max_amt))
            except ValueError:
                pass

        # 6. Flags
        for flag in ['is_flagged', 'is_transfer', 'is_personal', 'is_business']:
            val = f.get(flag)
            if val == '1' or val is True or val == 1:
                self.conditions.append(f"{flag} = 1")

    def get_where_clause(self):
        if not self.conditions:
            return "1=1", tuple()
        return " AND ".join(self.conditions), tuple(self.params)

    def get_faceted_counts(self, conn):
        """Returns distributions over various categorical fields."""
        where, params = self.get_where_clause()
        
        def _get_counts(field):
            cursor = conn.execute(f'''
                SELECT {field} as label, SUM(ABS(amount)) as total_amount, COUNT(*) as count 
                FROM transactions 
                WHERE {where} AND {field} IS NOT NULL
                GROUP BY {field} 
                ORDER BY total_amount DESC LIMIT 20
            ''', params)
            return [dict(r) for r in cursor.fetchall()]
            
        return {
            'categories': _get_counts('category'),
            'cardholders': _get_counts('cardholder_name'),
            'types': _get_counts('trans_type'),
            'payment_methods': _get_counts('payment_method')
        }
        
    def get_time_series(self, conn, interval='month'):
        """Returns time series distribution of spend vs income."""
        where, params = self.get_where_clause()
        
        date_format = '%Y-%m' if interval == 'month' else '%Y-%m-%d'
        
        cursor = conn.execute(f'''
            SELECT 
                strftime('{date_format}', trans_date) as period,
                SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as deposits,
                SUM(CASE WHEN amount < 0 AND is_transfer = 0 THEN ABS(amount) ELSE 0 END) as expenses,
                SUM(CASE WHEN amount < 0 AND is_transfer = 1 THEN ABS(amount) ELSE 0 END) as transfers_out
            FROM transactions
            WHERE {where} 
            GROUP BY period
            ORDER BY period ASC
        ''', params)
        return [dict(r) for r in cursor.fetchall()]
        
    def get_top_entities(self, conn, limit=10):
        """Returns entities with highest aggregate throughput."""
        where, params = self.get_where_clause()
        
        cursor = conn.execute(f'''
            SELECT description as entity, SUM(ABS(amount)) as total_amount, COUNT(*) as tx_count
            FROM transactions
            WHERE {where}
            GROUP BY description
            ORDER BY total_amount DESC
            LIMIT ?
        ''', list(params) + [limit])
        return [dict(r) for r in cursor.fetchall()]
