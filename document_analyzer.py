import os
import json
from abc import ABC, abstractmethod
from azure.core.credentials import AzureKeyCredential
from azure.ai.documentintelligence import DocumentIntelligenceClient
from azure.ai.documentintelligence.models import AnalyzeDocumentRequest

class DocumentAnalyzer(ABC):
    """Abstract Base Class for Document Analyzers."""
    
    @abstractmethod
    def analyze_document(self, file_path: str) -> dict:
        """
        Analyzes a document and returns the structured data.
        :param file_path: Absolute path to the file.
        :return: Dictionary containing extracted layout and fields.
        """
        pass

class AzureDocumentIntelligenceAdapter(DocumentAnalyzer):
    """Adapter for Microsoft Azure AI Document Intelligence."""
    
    def __init__(self):
        self.endpoint = os.getenv("AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT")
        self.key = os.getenv("AZURE_DOCUMENT_INTELLIGENCE_KEY")
        
        if not self.endpoint or not self.key:
            raise ValueError("Missing Azure Document Intelligence credentials in environment variables.")
            
        self.client = DocumentIntelligenceClient(
            endpoint=self.endpoint, 
            credential=AzureKeyCredential(self.key)
        )
        
    def analyze_document(self, file_path: str) -> dict:
        """
        Submits the document to Azure for 'prebuilt-document' (or receipt/invoice) extraction.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        with open(file_path, "rb") as f:
            poller = self.client.begin_analyze_document(
                "prebuilt-document", 
                AnalyzeDocumentRequest(bytes_source=f.read())
            )
            
        result = poller.result()
        return result.as_dict()
