from abc import ABC, abstractmethod
from typing import Dict, Any, Type
import os
import json
from pydantic import BaseModel
from openai import OpenAI

class LLMProvider(ABC):
    """Abstract interface for LLM extraction routing."""
    
    @abstractmethod
    def generate_structured_output(self, prompt: str, schema_model: Type[BaseModel]) -> Dict[str, Any]:
        """
        Submits a prompt enforcing a strict JSON schema representation.
        :param prompt: Formatted operational task/context string.
        :param schema_model: Pydantic typed model defining the expected JSON structure.
        """
        pass

class OpenAIProvider(LLMProvider):
    """OpenAI Adapter using latest native JSON schema function binding (Beta syntax)."""
    
    def __init__(self):
        self.api_key = os.getenv("LLM_API_KEY", os.getenv("OPENAI_API_KEY"))
        self.model = os.getenv("LLM_MODEL", "gpt-4o")
        if not self.api_key:
            raise ValueError("OpenAI Provider requires LLM_API_KEY or OPENAI_API_KEY environment variable.")
        self.client = OpenAI(api_key=self.api_key)

    def generate_structured_output(self, prompt: str, schema_model: Type[BaseModel]) -> Dict[str, Any]:
        """Execute a synchronous parse forcing `response_format` strictly against Pydantic schema."""
        completion = self.client.beta.chat.completions.parse(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a forensic data categorization AI. Always return precise, strictly formatted JSON matching the exact schema."},
                {"role": "user", "content": prompt}
            ],
            response_format=schema_model,
        )
        
        # Pydantic structured response payload
        return completion.choices[0].message.parsed.model_dump()

def get_llm_provider() -> LLMProvider:
    """Factory to route to the correct provider based on env."""
    provider_name = os.getenv("LLM_PROVIDER", "openai").lower()
    if provider_name == "openai":
        return OpenAIProvider()
    
    # Fallback to generic unhandled path
    raise NotImplementedError(f"LLM Provider '{provider_name}' is not supported.")
