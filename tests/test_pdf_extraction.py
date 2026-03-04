import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from parsers import parse_document, parse_pdf_text

class TestPDFExtraction(unittest.TestCase):
    
    @patch('parsers.parse_pdf_text')
    @patch('openai.OpenAI')
    def test_parse_bank_statement_with_llm(self, mock_openai, mock_parse_pdf_text):
        # 1. Setup Fixture
        # Using the known uploaded PDF path for the test
        pdf_path = os.path.join(PROJECT_ROOT, 'uploads', 'EStatement_0109_D_20241217_000000_000.pdf')
        
        # Mock OCR / Text extraction
        mock_parse_pdf_text.return_value = [
            "ACCOUNT INFORMATION",
            "Current Balance: -290.00",
            "Overdraft Fee: 5.00"
        ]
        
        # Mock LLM strict JSON schema response
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        
        mock_response = MagicMock()
        mock_parsed_data = MagicMock()
        
        # Simulated strict normalized schema
        mock_parsed_data.account_info.model_dump.return_value = {
            'institution': 'Bank of St. Francisville',
            'account_type': 'bank',
            'account_number': '130109',
            'statement_start': '2024-12-01',
            'statement_end': '2024-12-17'
        }
        
        # Mocking the transactions list directly evaluating to a non-empty array of objects
        mock_tx = MagicMock()
        mock_tx.date = '2024-12-17'
        mock_tx.description = 'Overdraft Fee'
        mock_tx.amount = -5.00
        mock_tx.type = 'debit'
        mock_tx.balance = -290.00
        
        mock_parsed_data.transactions = [mock_tx]
        
        mock_response.choices = [MagicMock(message=MagicMock(parsed=mock_parsed_data))]
        mock_client.beta.chat.completions.parse.return_value = mock_response
        
        # 2. Execute
        transactions, account_info = parse_document(pdf_path, 'bank_statement')
        
        # 3. Assert count > 0 and schema is normalized
        self.assertGreater(len(transactions), 0, "Parsed count must be > 0")
        
        tx = transactions[0]
        self.assertEqual(tx['trans_date'], '2024-12-17')
        self.assertEqual(tx['description'], 'Overdraft Fee')
        self.assertEqual(tx['amount'], -5.00)
        self.assertEqual(tx['trans_type'], 'debit')
        
        print(f"Fixture parsing successful. Parsed {len(transactions)} transaction(s).")
        print(f"Schema output: {tx}")

if __name__ == '__main__':
    unittest.main()
