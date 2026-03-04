import urllib.request
import urllib.parse
import json

class InternetLookupProvider:
    """
    A purely standard-library public lookup provider.
    Currently connects to Wikipedia's open opensearch/extract API.
    """
    
    @staticmethod
    def search_business_entity(normalized_merchant_name: str) -> str:
        """
        Attempts to find a summary paragraph of the specified business entity.
        Returns the raw descriptive text if found, else an empty string.
        """
        if not normalized_merchant_name:
            return ""
            
        try:
            # 1. Use Opensearch to securely resolve the exact Wikipedia page title
            search_query = urllib.parse.quote(normalized_merchant_name)
            url = f"https://en.wikipedia.org/w/api.php?action=opensearch&search={search_query}&limit=1&namespace=0&format=json"
            
            req = urllib.request.Request(url, headers={'User-Agent': 'ForensicCPA-AI/1.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                search_data = json.loads(response.read().decode())
                
            # Opensearch format: [ "query", ["Titles"], ["Descriptions"], ["URLs"] ]
            if len(search_data) > 1 and search_data[1]:
                exact_title = search_data[1][0]
                
                # 2. Extract the actual full summary text for the resolved title
                title_query = urllib.parse.quote(exact_title)
                extract_url = f"https://en.wikipedia.org/w/api.php?action=query&prop=extracts&exintro=true&explaintext=true&titles={title_query}&format=json"
                
                req2 = urllib.request.Request(extract_url, headers={'User-Agent': 'ForensicCPA-AI/1.0'})
                with urllib.request.urlopen(req2, timeout=5) as response2:
                    extract_data = json.loads(response2.read().decode())
                    
                pages = extract_data.get('query', {}).get('pages', {})
                for page_id, page_info in pages.items():
                    if 'extract' in page_info:
                        return page_info['extract'].strip()
                        
            return ""
        except Exception as e:
            print(f"Internet Lookup Provider Error: {e}")
            return ""
