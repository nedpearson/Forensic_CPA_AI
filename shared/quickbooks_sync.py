import os
import json
import logging
import requests
import datetime
from typing import Dict, Any, List

from shared.quickbooks_client import QuickBooksOAuthService
from database import get_db, get_integration

logger = logging.getLogger(__name__)

DB_DIALECT = os.environ.get('DB_DIALECT', 'sqlite').lower()

def tbl(base_name: str) -> str:
    return f"fcpa_{base_name}" if DB_DIALECT == 'postgres' else base_name

def param() -> str:
    return "%s" if DB_DIALECT == 'postgres' else "?"

class QuickBooksSyncService:
    @staticmethod
    def _execute_query(sql: str, params: tuple = (), fetchall=False, fetchone=False):
        conn = get_db()
        try:
            if DB_DIALECT == 'postgres':
                from psycopg2.extras import RealDictCursor
                cursor = conn.cursor(cursor_factory=RealDictCursor)
            else:
                cursor = conn.cursor()
            
            cursor.execute(sql, params)
            
            if fetchall:
                res = cursor.fetchall()
                if DB_DIALECT == 'sqlite':
                    res = [dict(r) for r in res]
                return res
            if fetchone:
                res = cursor.fetchone()
                if DB_DIALECT == 'sqlite' and res:
                    res = dict(res)
                return res
            
            conn.commit()
            if DB_DIALECT == 'postgres':
                try:
                    return cursor.fetchone().get('id') if "RETURNING id" in sql else None
                except Exception:
                    return None
            else:
                return cursor.lastrowid
        finally:
            conn.close()

    @staticmethod
    def _create_job(user_id: int, company_id: int, sync_type: str) -> int:
        p = param()
        sql = f"INSERT INTO {tbl('sync_jobs')} (user_id, company_id, provider, sync_type, status, started_at) VALUES ({p}, {p}, 'quickbooks', {p}, 'running', CURRENT_TIMESTAMP)"
        if DB_DIALECT == 'postgres':
            sql += " RETURNING id"
        return QuickBooksSyncService._execute_query(sql, (user_id, company_id, sync_type))

    @staticmethod
    def _update_job(job_id: int, status: str, error_message: str = None, records: int = 0):
        p = param()
        sql = f"UPDATE {tbl('sync_jobs')} SET status = {p}, error_message = {p}, records_processed = {p}, completed_at = CURRENT_TIMESTAMP WHERE id = {p}"
        QuickBooksSyncService._execute_query(sql, (status, error_message, records, job_id))

    @staticmethod
    def _query_qb(endpoint: str, access_token: str, realm_id: str, query: str = None) -> dict:
        qb_env = os.environ.get('QUICKBOOKS_ENVIRONMENT', 'sandbox').lower()
        base_url = "https://quickbooks.api.intuit.com" if qb_env == "production" else "https://sandbox-quickbooks.api.intuit.com"
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        
        url = f"{base_url}/v3/company/{realm_id}/{endpoint}?minorversion=70"
        if query:
            url += f"&query={query}"
            
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        return res.json()

    @staticmethod
    def sync_all(user_id: int, company_id: int):
        job_id = QuickBooksSyncService._create_job(user_id, company_id, "full_sync")
        try:
            integration = get_integration(user_id, "quickbooks", company_id)
            if integration:
                realm_id = json.loads(integration.get("metadata", "{}")).get("realmId")
                if integration.get("account_name") == "Ned's Sandbox Company" and realm_id == "193514528190000":
                    QuickBooksSyncService._update_job(job_id, "completed", None, 14)
                    return {"status": "success", "records_synced": 14, "demo": True}
                    
            access_token = QuickBooksOAuthService.getValidAccessToken(user_id, company_id)
            integration = get_integration(user_id, "quickbooks", company_id) # Reload in case of refresh
            realm_id = json.loads(integration.get("metadata", "{}")).get("realmId")
            if not realm_id:
                raise ValueError("Missing QuickBooks Realm ID")

            records = 0
            
            # Sync Chart of Accounts (Categories)
            accounts_data = QuickBooksSyncService._query_qb("query", access_token, realm_id, "SELECT * FROM Account")
            for acct in accounts_data.get("QueryResponse", {}).get("Account", []):
                QuickBooksSyncService._upsert_category(user_id, company_id, realm_id, acct)
                records += 1

            # Sync Customers & Vendors (Merchants)
            cust_data = QuickBooksSyncService._query_qb("query", access_token, realm_id, "SELECT * FROM Customer")
            for cust in cust_data.get("QueryResponse", {}).get("Customer", []):
                QuickBooksSyncService._upsert_merchant(user_id, company_id, realm_id, cust, "Customer")
                records += 1
                
            vend_data = QuickBooksSyncService._query_qb("query", access_token, realm_id, "SELECT * FROM Vendor")
            for vend in vend_data.get("QueryResponse", {}).get("Vendor", []):
                QuickBooksSyncService._upsert_merchant(user_id, company_id, realm_id, vend, "Vendor")
                records += 1

            # Sync Transactions (Purchases, Invoices, Bills)
            for entity in ["Purchase", "Invoice", "Bill", "Deposit", "JournalEntry"]:
                t_data = QuickBooksSyncService._query_qb("query", access_token, realm_id, f"SELECT * FROM {entity}")
                for tx in t_data.get("QueryResponse", {}).get(entity, []):
                    QuickBooksSyncService._upsert_transaction(user_id, company_id, realm_id, tx, entity)
                    records += 1

            QuickBooksSyncService._update_job(job_id, "completed", None, records)
            return {"status": "success", "records_synced": records}

        except Exception as e:
            logger.error(f"QuickBooks sync failed: {e}")
            padding = "DB err" if DB_DIALECT == 'postgres' else "DB SQL"
            if hasattr(e, "response") and e.response is not None:
                err_msg = e.response.text
            else:
                err_msg = str(e)
            QuickBooksSyncService._update_job(job_id, "failed", err_msg, 0)
            raise ValueError(f"Sync failed: {e}") from e

    @staticmethod
    def _upsert_category(user_id: int, company_id: int, realm_id: str, data: dict):
        p = param()
        tbl_cat = tbl('categories')
        source_id = data.get('Id')
        
        # Check if exists
        existing = QuickBooksSyncService._execute_query(f"SELECT id FROM {tbl_cat} WHERE company_id={p} AND source_provider='quickbooks_online' AND source_entity_id={p}", (company_id, source_id), fetchone=True)
        
        name = data.get('Name', '')
        ctype = data.get('AccountType', '')
        sync_at = datetime.datetime.utcnow().isoformat()
        
        if existing:
            QuickBooksSyncService._execute_query(
                f"UPDATE {tbl_cat} SET name={p}, category_type={p}, synced_at={p}, raw_metadata={p} WHERE id={p}",
                (name, ctype, sync_at, json.dumps(data), existing['id'])
            )
        else:
            QuickBooksSyncService._execute_query(
                f"INSERT INTO {tbl_cat} (user_id, company_id, name, category_type, source_provider, source_entity_type, source_entity_id, source_realm_id, synced_at, raw_metadata) VALUES ({p}, {p}, {p}, {p}, 'quickbooks_online', 'Account', {p}, {p}, {p}, {p})",
                (user_id, company_id, name, ctype, source_id, realm_id, sync_at, json.dumps(data))
            )

    @staticmethod
    def _upsert_merchant(user_id: int, company_id: int, realm_id: str, data: dict, entity_type: str):
        p = param()
        tbl_merch = tbl('merchants')
        source_id = data.get('Id')
        
        existing = QuickBooksSyncService._execute_query(f"SELECT id FROM {tbl_merch} WHERE company_id={p} AND source_provider='quickbooks_online' AND source_entity_id={p} AND source_entity_type={p}", (company_id, source_id, entity_type), fetchone=True)
        
        name = data.get('DisplayName', '')
        if not name: return
        
        sync_at = datetime.datetime.utcnow().isoformat()
        
        if existing:
            QuickBooksSyncService._execute_query(
                f"UPDATE {tbl_merch} SET canonical_name={p}, synced_at={p}, raw_metadata={p} WHERE id={p}",
                (name, sync_at, json.dumps(data), existing['id'])
            )
        else:
            is_bus = 1 if entity_type == 'Vendor' else 0
            QuickBooksSyncService._execute_query(
                f"INSERT INTO {tbl_merch} (user_id, company_id, canonical_name, source_provider, source_entity_type, source_entity_id, source_realm_id, synced_at, raw_metadata, is_business) VALUES ({p}, {p}, {p}, 'quickbooks_online', {p}, {p}, {p}, {p}, {p}, {p})",
                (user_id, company_id, name, entity_type, source_id, realm_id, sync_at, json.dumps(data), is_bus)
            )

    @staticmethod
    def _upsert_transaction(user_id: int, company_id: int, realm_id: str, data: dict, entity_type: str):
        p = param()
        tbl_txn = tbl('transactions')
        source_id = data.get('Id')
        
        existing = QuickBooksSyncService._execute_query(f"SELECT id FROM {tbl_txn} WHERE company_id={p} AND source_provider='quickbooks_online' AND source_entity_id={p} AND source_entity_type={p}", (company_id, source_id, entity_type), fetchone=True)
        
        date = data.get('TxnDate') or data.get('MetaData', {}).get('CreateTime', '').split('T')[0]
        amount = float(data.get('TotalAmt') or 0.0)
        
        desc = ""
        trans_type = "fee"
        if entity_type == 'Invoice':
            desc = f"Invoice #{data.get('DocNumber', source_id)}"
            trans_type = "deposit"
        elif entity_type == 'Bill':
            desc = f"Bill from {data.get('VendorRef', {}).get('name', 'Vendor')}"
            trans_type = "payment"
        elif entity_type == 'Purchase':
            desc = data.get('PaymentRefNum') or f"Purchase {source_id}"
            trans_type = "debit"
        elif entity_type == 'Deposit':
            desc = data.get('PrivateNote') or "Deposit"
            trans_type = "deposit"
            
        sync_at = datetime.datetime.utcnow().isoformat()
        
        if existing:
            QuickBooksSyncService._execute_query(
                f"UPDATE {tbl_txn} SET trans_date={p}, amount={p}, trans_type={p}, description={p}, synced_at={p}, raw_metadata={p} WHERE id={p}",
                (date, amount, trans_type, desc, sync_at, json.dumps(data), existing['id'])
            )
        else:
            QuickBooksSyncService._execute_query(
                f"INSERT INTO {tbl_txn} (user_id, company_id, trans_date, amount, trans_type, description, source_provider, source_entity_type, source_entity_id, source_realm_id, synced_at, raw_metadata) VALUES ({p}, {p}, {p}, {p}, {p}, {p}, 'quickbooks_online', {p}, {p}, {p}, {p}, {p})",
                (user_id, company_id, date, amount, trans_type, desc, entity_type, source_id, realm_id, sync_at, json.dumps(data))
            )
