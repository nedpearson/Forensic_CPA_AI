from typing import List, Optional
from pydantic import BaseModel, Field
from llm_provider import LLMProvider, get_llm_provider

# --- Structured Output Pydantic Schemas ---

class RiskCategory(BaseModel):
    category_name: str = Field(description="The canonical name of the risk category assigned.")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0.")
    justification: str = Field(description="Brief explanation of why this risk was identified based on the text.")

class Entity(BaseModel):
    name: str = Field(description="Raw name found in the document.")
    type: str = Field(description="Type of entity: 'person', 'organization', 'account', 'transaction_type'.")
    canonical_name: str = Field(description="Normalized or standardized name resolving aliases/typos.")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0.")

class CategorizationOutput(BaseModel):
    risk_categories: List[RiskCategory] = Field(description="Identified risk markers and severity mappings.")
    entities: List[Entity] = Field(description="Standardized list of actors, banks, or organizations.")
    topics: List[str] = Field(description="Array of string topics acting as high-level labels.")
    summary: str = Field(description="Comprehensive summary. MUST include inline citations like [Page 2] when referencing specific evidence.")
    key_findings: List[str] = Field(description="Bullet points of the most critical operational intelligence found.")

# --- Core Business Logic ---

class AutoCategorizer:
    
    def __init__(self, provider: Optional[LLMProvider] = None):
        """
        Initializes the categorizer with a specific LLM routing.
        Allows dependency injection for testing.
        """
        self.provider = provider or get_llm_provider()
        
    def run_categorization(self, extraction_text: str, taxonomy: List[dict] = None) -> dict:
        """
        Takes raw OCR/Document Analysis output, shapes a forensic prompt, 
        and extracts strictly typed entities and risks.
        """
        taxonomy = taxonomy or []
        
        # Build taxonomy context string
        tax_lines = []
        for t in taxonomy:
            t_type = t.get('category_type', 'unknown').upper()
            t_name = t.get('name', '')
            t_desc = t.get('description', '')
            t_sev = t.get('severity', 'low')
            tax_lines.append(f"[{t_type}] {t_name} (Severity: {t_sev}) - {t_desc}")
            
        taxonomy_context = "\n".join(tax_lines) if tax_lines else "No specific taxonomy provided; use forensic accounting best practices."
        
        prompt = f"""
You are a Principal Financial Auditor AI analyzing Extracted Document Text.

### OBJECTIVE
Your job is to read the attached document text and categorize it based strictly on standard forensic 
accounting principles or the provided taxonomy. You must extract:
1. Forensic Risks 
2. Relevant Entities (resolve 'J. Doe' and 'Jon Doe' to a canonical name)
3. Topics 
4. A high-level Summary referencing evidential pages.
5. Key Findings

### TAXONOMY CONFIGURATION
{taxonomy_context}

### INSTRUCTIONS
- Map document findings to the taxonomy risks where applicable.
- Ensure your summary explicitly uses [Page X] or [Line Y] formatting when citing claims that appear in the raw text.

### RAW DOCUMENT EXTRACTION TEXT
{extraction_text}
"""
        
        return self.provider.generate_structured_output(prompt, CategorizationOutput)
