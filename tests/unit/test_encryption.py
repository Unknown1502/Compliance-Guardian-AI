"""Tests for encryption utilities."""

import pytest
from src.utils.encryption import (
    encrypt_data, decrypt_data, mask_pii, hash_data, 
    EncryptionManager, _encryption_manager
)


class TestEncryption:
    """Test encryption functions."""
    
    def test_encrypt_decrypt_string(self):
        """Test basic string encryption and decryption."""
        # Use the global encryption manager to ensure same key
        original = "sensitive data"
        
        # Get the global manager's key
        manager = _encryption_manager
        key = manager._symmetric_key
        
        # Encrypt and decrypt with the same key
        encrypted = encrypt_data(original, key=key)
        
        assert encrypted != original
        assert isinstance(encrypted, str)
        
        decrypted = decrypt_data(encrypted, key=key)
        assert decrypted == original
    
    def test_hash_data(self):
        """Test data hashing."""
        data = "test data"
        hash1 = hash_data(data)
        hash2 = hash_data(data)
        
        assert hash1 == hash2
        assert len(hash1) > 0
    
    def test_mask_pii_email(self):
        """Test PII masking for email addresses."""
        text = "Contact: john.doe@example.com"
        masked = mask_pii(text)
        
        assert "john.doe@example.com" not in masked
        assert masked.count("*") > 5
    
    def test_mask_pii_phone(self):
        """Test PII masking for phone numbers."""
        text = "Call: 555-123-4567"
        masked = mask_pii(text)
        
        assert "555-123" not in masked
        assert "4567" in masked  # Last 4 digits should be visible
    
    def test_mask_pii_ssn(self):
        """Test PII masking for SSN."""
        text = "SSN: 123-45-6789"
        masked = mask_pii(text)
        
        assert "123-45" not in masked
        assert "***-**-" in masked
