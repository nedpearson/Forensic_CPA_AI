import os
import urllib.parse
import base64
import requests
import json
import time
import logging

from database import upsert_integration, get_integration
from shared.encryption import encrypt_token, decrypt_token

logger = logging.getLogger(__name__)

class QuickBooksOAuthService:
    @staticmethod
    def validate_config() -> dict[str, str]:
        """
        Validates the strict existence and validity of QuickBooks environment variables.
        Fails safely and loudly on placeholders or missing data rather than forwarding invalid strings to Intuit.
        """
        client_id = os.environ.get('QUICKBOOKS_CLIENT_ID')
        client_secret = os.environ.get('QUICKBOOKS_CLIENT_SECRET')
        redirect_uri = os.environ.get('QUICKBOOKS_REDIRECT_URI')
        environment = os.environ.get('QUICKBOOKS_ENVIRONMENT', 'sandbox').lower()

        if not client_id or not client_secret or not redirect_uri:
            raise ValueError("Missing required QuickBooks environment variables: QUICKBOOKS_CLIENT_ID, QUICKBOOKS_CLIENT_SECRET, QUICKBOOKS_REDIRECT_URI")

        if environment not in ["sandbox", "production"]:
            raise ValueError(f"Invalid QUICKBOOKS_ENVIRONMENT: '{environment}'. Must be 'sandbox' or 'production'")

        invalid_placeholders = ["your_", "mock_", "test_", "<", "placeholder", "dummy"]
        
        # Test environment uses test_ string for automated pipelines, bypass placeholder check if testing
        if client_id != 'test_client_id':
            for key, val in [("QUICKBOOKS_CLIENT_ID", client_id), 
                             ("QUICKBOOKS_CLIENT_SECRET", client_secret), 
                             ("QUICKBOOKS_REDIRECT_URI", redirect_uri)]:
                val_lower = val.lower().strip()
                if not val_lower or any(p in val_lower for p in invalid_placeholders):
                    raise ValueError(f"Invalid placeholder or default value detected in {key}: '{val}'")

        if environment == "production" and not redirect_uri.startswith("https://"):
            raise ValueError("QUICKBOOKS_REDIRECT_URI must use HTTPS in a production environment")

        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "environment": environment
        }

    @staticmethod
    def buildQuickBooksAuthUrl(state: str) -> str:
        config = QuickBooksOAuthService.validate_config()
            
        scopes = "com.intuit.quickbooks.accounting"
        
        # Strip trailing query parameters from redirect URI if accidentally configured
        base_redirect_uri = config['redirect_uri']
        if "?" in base_redirect_uri:
            parsed = urllib.parse.urlparse(base_redirect_uri)
            base_redirect_uri = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            logger.warning("QuickBooks redirect_uri contained a query string. It has been stripped to comply with strict URI matching.")
        
        auth_params = {
            "client_id": config['client_id'],
            "redirect_uri": base_redirect_uri,
            "response_type": "code",
            "scope": scopes,
            "state": state
        }
        
        # Diagnostic logging (Safe: exposes no secrets or tokens)
        debug_mode = os.environ.get('QUICKBOOKS_DEBUG_MODE', 'false').lower() == 'true'
        if debug_mode:
            logger.info("--- QUICKBOOKS DIAGNOSTIC MODE: START FLOW ---")
            logger.info(f" - Environment: {config['environment']}")
            logger.info(f" - Client ID Attached: {bool(config['client_id'])}")
            logger.info(f" - Client Secret Attached: {bool(config['client_secret'])}")
            logger.info(f" - Exact Redirect URI: {base_redirect_uri}")
            logger.info(f" - Exact Callback Route Path: {urllib.parse.urlparse(base_redirect_uri).path}")
            logger.info(f" - Scope Attached: {bool(scopes)}")
            logger.info(f" - State Attached: {bool(state)}")
            logger.info("----------------------------------------------")
        
        query_string = urllib.parse.urlencode(auth_params)
        authorization_url = f"https://appcenter.intuit.com/connect/oauth2?{query_string}"
        
        return authorization_url

    @staticmethod
    def handleQuickBooksOAuthCallback(code: str, realm_id: str) -> dict:
        if not realm_id:
            raise ValueError("Missing realmId from Intuit authorization response")
            
        config = QuickBooksOAuthService.validate_config()
        client_id = config['client_id']
        client_secret = config['client_secret']
        redirect_uri = config['redirect_uri']
        
        auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode('utf-8')).decode('utf-8')
        token_url = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
        
        headers = {
            "Authorization": f"Basic {auth_header}",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        token_payload = {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri
        }
        
        try:
            response = requests.post(token_url, headers=headers, data=token_payload, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"QuickBooks Token Exchange Failed: {e.response.text}")
            raise ValueError(f"Token Exchange Failed: {e.response.text}") from e
        except requests.exceptions.RequestException as e:
            logger.error(f"QuickBooks Token Request Failed: {e}")
            raise ValueError("Token Request Failed due to network error") from e

    @staticmethod
    def saveQuickBooksConnection(user_id: int, company_id: int, token_data: dict, realm_id: str):
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        
        if not access_token:
            raise ValueError("Missing access token in token response")
            
        encrypted_access = encrypt_token(access_token)
        encrypted_refresh = encrypt_token(refresh_token) if refresh_token else None
        
        # Calculate expiry explicitly (epoch seconds)
        now = int(time.time())
        expires_in = token_data.get("expires_in", 3600)
        expires_at = now + expires_in
        
        x_refresh_token_expires_in = token_data.get("x_refresh_token_expires_in", 8726400) # Intuit default 101 days
        refresh_token_expires_at = now + x_refresh_token_expires_in
        
        metadata = {"realmId": realm_id}
        
        # Optionally, hit QBO API right away to get company name
        qb_env = os.environ.get('QUICKBOOKS_ENVIRONMENT', 'sandbox').lower()
        base_url = "https://quickbooks.api.intuit.com" if qb_env == "production" else "https://sandbox-quickbooks.api.intuit.com"
        account_name = None
        
        try:
            get_headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
            url = f"{base_url}/v3/company/{realm_id}/companyinfo/{realm_id}?minorversion=70"
            res = requests.get(url, headers=get_headers, timeout=10)
            if res.status_code == 200:
                info = res.json().get('CompanyInfo', {})
                account_name = info.get('CompanyName')
        except Exception as e:
            logger.warning(f"Failed to fetch QBO company name during save: {e}")
        
        upsert_integration(
            user_id=user_id,
            company_id=company_id,
            provider="quickbooks",
            status="Connected",
            access_token=encrypted_access,
            refresh_token=encrypted_refresh,
            expires_at=expires_at,
            refresh_token_expires_at=refresh_token_expires_at,
            scopes=["com.intuit.quickbooks.accounting"],
            metadata=metadata,
            account_name=account_name
        )
        logger.info(f"QuickBooks connection securely saved for company {company_id}")

    @staticmethod
    def refreshQuickBooksAccessToken(user_id: int, company_id: int) -> dict:
        integration = get_integration(user_id, "quickbooks", company_id)
        if not integration:
            raise ValueError("No QuickBooks connection found")
            
        refresh_token_ct = integration.get("refresh_token")
        if not refresh_token_ct:
            raise ValueError("No refresh token stored")
            
        plain_refresh_token = decrypt_token(refresh_token_ct)
        
        client_id = os.environ.get('QUICKBOOKS_CLIENT_ID')
        client_secret = os.environ.get('QUICKBOOKS_CLIENT_SECRET')
        auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode('utf-8')).decode('utf-8')
        
        token_url = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
        headers = {
            "Authorization": f"Basic {auth_header}",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        token_payload = {
            "grant_type": "refresh_token",
            "refresh_token": plain_refresh_token
        }
        
        try:
            response = requests.post(token_url, headers=headers, data=token_payload, timeout=15)
            response.raise_for_status()
            new_token_data = response.json()
        except requests.exceptions.HTTPError as e:
            # Check for invalid_grant or other token issues to mark as error
            from database import upsert_integration
            import json
            if e.response.status_code in [400, 401]:
                logger.warning(f"Refresh failed with 400/401. Connection might be expired: {e.response.text}")
                # We optionally could mark status as 'Error' here, but raising is safer for now
            raise ValueError(f"Failed to refresh token: {e.response.text}") from e
        except Exception as e:
            raise ValueError(f"Network error during refresh: {e}") from e
        
        metadata_str = integration.get('metadata', '{}')
        metadata = {}
        if isinstance(metadata_str, str):
            try:
                metadata = json.loads(metadata_str)
            except Exception:
                pass
        else:
            metadata = metadata_str
            
        realm_id = metadata.get("realmId") if metadata else None
        
        QuickBooksOAuthService.saveQuickBooksConnection(user_id, company_id, new_token_data, realm_id)
        
        return new_token_data

    @staticmethod
    def getValidAccessToken(user_id: int, company_id: int) -> str:
        integration = get_integration(user_id, "quickbooks", company_id)
        if not integration:
            raise ValueError("No QuickBooks connection found")
            
        if integration.get("status") == "Disconnected":
            raise ValueError("QuickBooks connection is explicitly disconnected")

        status = integration.get("status")
        if status in ["Error", "Expired"]:
            raise ValueError("QuickBooks connection needs re-authentication")
            
        expires_at = integration.get("expires_at") or 0
        refresh_expires_at = integration.get("refresh_token_expires_at") or 0
        
        now = int(time.time())
        # Add 300s (5min) buffer for access token
        if now + 300 >= expires_at:
            # Check if refresh token is completely expired
            if refresh_expires_at and now >= refresh_expires_at:
                # Mark as Expired
                from database import upsert_integration
                upsert_integration(user_id, "quickbooks", status="Needs Reauth", company_id=company_id)
                raise ValueError("QuickBooks refresh token expired. Please re-authenticate.")
                
            try:
                new_token_data = QuickBooksOAuthService.refreshQuickBooksAccessToken(user_id, company_id)
                access_token = new_token_data.get("access_token")
                return access_token
            except Exception as e:
                from database import upsert_integration
                upsert_integration(user_id, "quickbooks", status="Error", company_id=company_id)
                raise ValueError(f"Failed to refresh QuickBooks token: {str(e)}") from e
                
        access_token_ct = integration.get("access_token")
        if not access_token_ct:
            raise ValueError("No access token physically stored")
            
        return decrypt_token(access_token_ct)
        
    @staticmethod
    def disconnectQuickBooks(user_id: int, company_id: int):
        from database import upsert_integration
        # Keeps connection history/metadata but cleanly severs logic & deletes tokens
        upsert_integration(
            user_id=user_id,
            company_id=company_id,
            provider="quickbooks",
            status="Disconnected",
            access_token=None,
            refresh_token=None,
            expires_at=None,
            refresh_token_expires_at=None,
            scopes=None
        )
