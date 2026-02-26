import os
from cryptography.fernet import Fernet
import base64

def get_cipher():
    """
    Returns a configured Fernet cipher based on the OAUTH_ENCRYPTION_KEY env var.
    Must be a 32-byte url-safe base64-encoded string.
    """
    key = os.environ.get('OAUTH_ENCRYPTION_KEY')
    if not key:
        raise ValueError("OAUTH_ENCRYPTION_KEY environment variable is missing or empty. Please set it in .env.")
    
    try:
        return Fernet(key.encode('utf-8'))
    except Exception as e:
        raise ValueError(f"Invalid OAUTH_ENCRYPTION_KEY format. Must be a 32-byte url-safe base64-encoded string: {e}")

def encrypt_token(plain_text: str) -> str:
    """Encrypts a plaintext string into a safe cipher text for storage."""
    if not plain_text:
        return None
    cipher = get_cipher()
    return cipher.encrypt(plain_text.encode('utf-8')).decode('utf-8')

def decrypt_token(cipher_text: str) -> str:
    """Decrypts a strong ciphertext back into a plaintext token string."""
    if not cipher_text:
        return None
    cipher = get_cipher()
    return cipher.decrypt(cipher_text.encode('utf-8')).decode('utf-8')
