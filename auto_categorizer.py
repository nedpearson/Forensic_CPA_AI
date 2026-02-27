from typing import List, Optional, Dict
from pydantic import BaseModel, Field
from llm_provider import LLMProvider, get_llm_provider
import json

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

class TransactionCategory(BaseModel):
    txn_id: int = Field(description="The ID of the transaction.")
    reasoning: str = Field(description="Chain-of-thought: Step-by-step logic detailing why this specific category applies based on the merchant, amount, or prior examples.")
    category: str = Field(description="The assigned category matching the exact taxonomy value.")
    subcategory: Optional[str] = Field(description="The assigned subcategory, if applicable.")
    is_personal: bool = Field(description="True if this appears to be personal spending.")
    is_business: bool = Field(description="True if this appears to be business spending.")
    is_transfer: bool = Field(description="True if this is a transfer between accounts or payment of a credit card.")
    suggested_pattern: str = Field(description="A SQL LIKE pattern (e.g. '%STARBUCKS%') that could be saved as a rule to catch similar transactions in the future.")
    confidence_score: float = Field(description="Confidence score between 0.0 and 1.0 that this decision is correct.")
    explanation_flags: str = Field(description="Comma-separated tags explaining why confidence might be low (e.g. 'Unknown vendor', 'Ambiguous amount', 'No matching taxonomy'). Leave blank if high confidence.")

class TransactionCategorizationBatch(BaseModel):
    results: List[TransactionCategory] = Field(description="Categorization results for the provided batch.")

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

    def categorize_transaction_batch(self, transactions: List[dict], taxonomy: List[dict] = None, few_shot_examples: List[dict] = None) -> List[TransactionCategory]:
        """
        Bulk categorizes an array of unrecognized transactions using the LLM 
        with Few-Shot Learning and Chain of Thought logic.
        """
        if not transactions:
            return []
            
        taxonomy = taxonomy or []
        tax_str = ", ".join([t.get('name', '') for t in taxonomy])
        
        # Serialize the batch
        batch_text = ""
        for t in transactions:
            batch_text += f"ID:{t['id']} | DESC:{t['description']} | AMOUNT:{t['amount']} | POSTDATE:{t['trans_date']}\n"
            
        # Serialize Few-Shot
        few_shot_context = ""
        if few_shot_examples:
            few_shot_context = "### PRIOR APPROVED TRANSACTIONS (USE AS PRECEDENT)\n"
            for t in few_shot_examples:
                few_shot_context += f"- DESC: {t['description']} | AMOUNT: {t['amount']} -> CATEGORY: {t['category']} (Business: {t['is_business']}, Personal: {t['is_personal']})\n"
            
        prompt = f"""
You are an expert AI Forensic Bookkeeper. Categorize the following batch of bank transactions.

### AVAILABLE TAXONOMY CATEGORIES
{tax_str if tax_str else "Standard accounting categories (e.g. Business - Supplies, Personal - Dining, Transfer)"}

{few_shot_context}

### INSTRUCTIONS
1. Analyze the transaction using Chain-of-Thought. Write down your `reasoning` explicitly: does it look like a known vendor? Is it a transfer? Does it resemble prior approved examples?
2. Pick the single most accurate Category.
3. Provide a `confidence_score` (0.0 to 1.0). Be highly confident (>0.85) ONLY if the merchant is extremely well-known, matches prior examples exactly, or is obvious (like a bank transfer).
4. Provide `explanation_flags` if confidence < 0.85 (e.g., 'Unknown local vendor', 'Generic ACH name').

### TRANSACTIONS TO CATEGORIZE
{batch_text}
"""
        try:
            output = self.provider.generate_structured_output(prompt, TransactionCategorizationBatch)
            return output.results
        except Exception as e:
            print(f"AI Batch Categorization Failed: {e}")
            return []
