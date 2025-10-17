"""Encryption utilities for Compliance Guardian AI."""

import base64
import hashlib
import hmac
import os
import secrets
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .config import get_config
from .logger import get_logger

logger = get_logger(__name__)


class EncryptionError(Exception):
    """Custom exception for encryption-related errors."""
    pass


class EncryptionManager:
    """
    Centralized encryption management for Compliance Guardian AI.
    
    Provides:
    - Symmetric encryption for data at rest
    - Asymmetric encryption for secure communication
    - Key derivation and management
    - Secure hashing and HMAC
    - PII tokenization
    """
    
    def __init__(self):
        self.config = get_config()
        self._symmetric_key: Optional[bytes] = None
        self._fernet: Optional[Fernet] = None
        self._load_or_generate_key()
    
    def _load_or_generate_key(self) -> None:
        """Load existing encryption key or generate a new one."""
        try:
            # Try to load from config first
            key_from_config = self.config.security.encryption_key
            
            if key_from_config:
                # Decode base64 key from config
                try:
                    self._symmetric_key = base64.b64decode(key_from_config.encode())
                    if len(self._symmetric_key) != 32:  # AES-256 requires 32 bytes
                        raise ValueError("Invalid key length")
                except Exception as e:
                    logger.warning(f"Invalid encryption key in config: {e}")
                    self._symmetric_key = None
            
            # Generate new key if none exists or invalid
            if not self._symmetric_key:
                self._symmetric_key = Fernet.generate_key()
                logger.info("Generated new encryption key")
                
                # In production, this should be stored securely (AWS Secrets Manager, etc.)
                if self.config.is_development():
                    encoded_key = base64.b64encode(self._symmetric_key).decode()
                    logger.debug(f"New encryption key (save this securely): {encoded_key}")
            
            # Initialize Fernet instance
            self._fernet = Fernet(self._symmetric_key)
            
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            raise EncryptionError(f"Encryption initialization failed: {e}")
    
    def get_key_fingerprint(self) -> str:
        """Get a fingerprint of the current encryption key."""
        if not self._symmetric_key:
            return "no-key"
        
        return hashlib.sha256(self._symmetric_key).hexdigest()[:16]


def encrypt_data(
    data: Union[str, bytes], 
    key: Optional[bytes] = None,
    algorithm: str = "fernet"
) -> str:
    """
    Encrypt data using symmetric encryption.
    
    Args:
        data: Data to encrypt (string or bytes)
        key: Optional encryption key (uses default if None)
        algorithm: Encryption algorithm (fernet, aes256)
        
    Returns:
        Base64-encoded encrypted data
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        # Convert string to bytes if necessary
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        if algorithm == "fernet":
            # Use Fernet (recommended for most use cases)
            if key:
                fernet = Fernet(key)
            else:
                # Use global encryption manager
                manager = EncryptionManager()
                fernet = manager._fernet
            
            encrypted = fernet.encrypt(data_bytes)
            return base64.b64encode(encrypted).decode('utf-8')
        
        elif algorithm == "aes256":
            # Use AES-256-GCM
            if not key:
                key = secrets.token_bytes(32)  # Generate random key
            
            # Generate random IV
            iv = secrets.token_bytes(12)  # 12 bytes for GCM
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            
            # Encrypt data
            ciphertext = encryptor.update(data_bytes) + encryptor.finalize()
            
            # Combine IV, tag, and ciphertext
            encrypted_data = iv + encryptor.tag + ciphertext
            
            return base64.b64encode(encrypted_data).decode('utf-8')
        
        else:
            raise EncryptionError(f"Unsupported encryption algorithm: {algorithm}")
            
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise EncryptionError(f"Encryption failed: {e}")


def decrypt_data(
    encrypted_data: str, 
    key: Optional[bytes] = None,
    algorithm: str = "fernet"
) -> str:
    """
    Decrypt data using symmetric encryption.
    
    Args:
        encrypted_data: Base64-encoded encrypted data
        key: Optional decryption key (uses default if None)
        algorithm: Decryption algorithm (fernet, aes256)
        
    Returns:
        Decrypted data as string
        
    Raises:
        EncryptionError: If decryption fails
    """
    try:
        # Decode base64
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        
        if algorithm == "fernet":
            # Use Fernet
            if key:
                fernet = Fernet(key)
            else:
                # Use global encryption manager
                manager = EncryptionManager()
                fernet = manager._fernet
            
            decrypted = fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        
        elif algorithm == "aes256":
            # Use AES-256-GCM
            if not key:
                raise EncryptionError("Key required for AES decryption")
            
            # Extract IV (12 bytes), tag (16 bytes), and ciphertext
            iv = encrypted_bytes[:12]
            tag = encrypted_bytes[12:28]
            ciphertext = encrypted_bytes[28:]
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            
            # Decrypt data
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted.decode('utf-8')
        
        else:
            raise EncryptionError(f"Unsupported decryption algorithm: {algorithm}")
            
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise EncryptionError(f"Decryption failed: {e}")


def hash_data(
    data: Union[str, bytes], 
    algorithm: str = "sha256",
    salt: Optional[bytes] = None
) -> str:
    """
    Hash data using specified algorithm.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm (sha256, sha512, blake2b)
        salt: Optional salt for hashing
        
    Returns:
        Hexadecimal hash string
        
    Raises:
        EncryptionError: If hashing fails
    """
    try:
        # Convert string to bytes if necessary
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        # Add salt if provided
        if salt:
            data_bytes = salt + data_bytes
        
        if algorithm == "sha256":
            hash_obj = hashlib.sha256(data_bytes)
        elif algorithm == "sha512":
            hash_obj = hashlib.sha512(data_bytes)
        elif algorithm == "blake2b":
            hash_obj = hashlib.blake2b(data_bytes)
        else:
            raise EncryptionError(f"Unsupported hash algorithm: {algorithm}")
        
        return hash_obj.hexdigest()
        
    except Exception as e:
        logger.error(f"Hashing failed: {e}")
        raise EncryptionError(f"Hashing failed: {e}")


def generate_salt(length: int = 32) -> bytes:
    """Generate a random salt for hashing."""
    return secrets.token_bytes(length)


def derive_key_from_password(
    password: str,
    salt: Optional[bytes] = None,
    algorithm: str = "pbkdf2",
    key_length: int = 32
) -> Tuple[bytes, bytes]:
    """
    Derive encryption key from password.
    
    Args:
        password: Password to derive key from
        salt: Optional salt (generated if None)
        algorithm: Key derivation algorithm (pbkdf2, scrypt)
        key_length: Desired key length in bytes
        
    Returns:
        Tuple of (derived_key, salt)
        
    Raises:
        EncryptionError: If key derivation fails
    """
    try:
        if not salt:
            salt = generate_salt()
        
        password_bytes = password.encode('utf-8')
        
        if algorithm == "pbkdf2":
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                iterations=100000  # OWASP recommended minimum
            )
        elif algorithm == "scrypt":
            kdf = Scrypt(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                n=2**14,  # CPU/memory cost parameter
                r=8,      # Block size parameter
                p=1       # Parallelization parameter
            )
        else:
            raise EncryptionError(f"Unsupported KDF algorithm: {algorithm}")
        
        derived_key = kdf.derive(password_bytes)
        return derived_key, salt
        
    except Exception as e:
        logger.error(f"Key derivation failed: {e}")
        raise EncryptionError(f"Key derivation failed: {e}")


def generate_rsa_key_pair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """
    Generate RSA public/private key pair.
    
    Args:
        key_size: RSA key size in bits
        
    Returns:
        Tuple of (private_key_pem, public_key_pem)
        
    Raises:
        EncryptionError: If key generation fails
    """
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
        
    except Exception as e:
        logger.error(f"RSA key generation failed: {e}")
        raise EncryptionError(f"RSA key generation failed: {e}")


def encrypt_with_rsa(data: Union[str, bytes], public_key_pem: bytes) -> str:
    """
    Encrypt data with RSA public key.
    
    Args:
        data: Data to encrypt
        public_key_pem: RSA public key in PEM format
        
    Returns:
        Base64-encoded encrypted data
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        # Convert string to bytes if necessary
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        # Load public key
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        # Encrypt data
        encrypted = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted).decode('utf-8')
        
    except Exception as e:
        logger.error(f"RSA encryption failed: {e}")
        raise EncryptionError(f"RSA encryption failed: {e}")


def decrypt_with_rsa(encrypted_data: str, private_key_pem: bytes) -> str:
    """
    Decrypt data with RSA private key.
    
    Args:
        encrypted_data: Base64-encoded encrypted data
        private_key_pem: RSA private key in PEM format
        
    Returns:
        Decrypted data as string
        
    Raises:
        EncryptionError: If decryption fails
    """
    try:
        # Decode base64
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )
        
        # Decrypt data
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted.decode('utf-8')
        
    except Exception as e:
        logger.error(f"RSA decryption failed: {e}")
        raise EncryptionError(f"RSA decryption failed: {e}")


def generate_hmac(
    data: Union[str, bytes], 
    key: Union[str, bytes],
    algorithm: str = "sha256"
) -> str:
    """
    Generate HMAC for data integrity verification.
    
    Args:
        data: Data to generate HMAC for
        key: HMAC key
        algorithm: Hash algorithm for HMAC
        
    Returns:
        Hexadecimal HMAC string
        
    Raises:
        EncryptionError: If HMAC generation fails
    """
    try:
        # Convert to bytes if necessary
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        if isinstance(key, str):
            key_bytes = key.encode('utf-8')
        else:
            key_bytes = key
        
        if algorithm == "sha256":
            mac = hmac.new(key_bytes, data_bytes, hashlib.sha256)
        elif algorithm == "sha512":
            mac = hmac.new(key_bytes, data_bytes, hashlib.sha512)
        else:
            raise EncryptionError(f"Unsupported HMAC algorithm: {algorithm}")
        
        return mac.hexdigest()
        
    except Exception as e:
        logger.error(f"HMAC generation failed: {e}")
        raise EncryptionError(f"HMAC generation failed: {e}")


def verify_hmac(
    data: Union[str, bytes],
    key: Union[str, bytes],
    expected_hmac: str,
    algorithm: str = "sha256"
) -> bool:
    """
    Verify HMAC for data integrity.
    
    Args:
        data: Original data
        key: HMAC key
        expected_hmac: Expected HMAC value
        algorithm: Hash algorithm used
        
    Returns:
        True if HMAC is valid
        
    Raises:
        EncryptionError: If HMAC verification fails
    """
    try:
        actual_hmac = generate_hmac(data, key, algorithm)
        return hmac.compare_digest(actual_hmac, expected_hmac)
        
    except Exception as e:
        logger.error(f"HMAC verification failed: {e}")
        raise EncryptionError(f"HMAC verification failed: {e}")


def tokenize_pii(pii_value: str, token_length: int = 16) -> Tuple[str, str]:
    """
    Tokenize PII data for safe storage.
    
    Args:
        pii_value: PII value to tokenize
        token_length: Length of generated token
        
    Returns:
        Tuple of (token, encrypted_value)
        
    Raises:
        EncryptionError: If tokenization fails
    """
    try:
        # Generate random token
        token = secrets.token_hex(token_length)
        
        # Encrypt the original value
        encrypted_value = encrypt_data(pii_value)
        
        logger.info(f"PII tokenized successfully", extra={
            "token_length": len(token),
            "original_length": len(pii_value)
        })
        
        return token, encrypted_value
        
    except Exception as e:
        logger.error(f"PII tokenization failed: {e}")
        raise EncryptionError(f"PII tokenization failed: {e}")


def detokenize_pii(encrypted_value: str) -> str:
    """
    Detokenize PII data.
    
    Args:
        encrypted_value: Encrypted PII value
        
    Returns:
        Original PII value
        
    Raises:
        EncryptionError: If detokenization fails
    """
    try:
        return decrypt_data(encrypted_value)
        
    except Exception as e:
        logger.error(f"PII detokenization failed: {e}")
        raise EncryptionError(f"PII detokenization failed: {e}")


def secure_random_string(length: int = 32, include_special: bool = False) -> str:
    """
    Generate cryptographically secure random string.
    
    Args:
        length: Length of the string
        include_special: Include special characters
        
    Returns:
        Random string
    """
    if include_special:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    else:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def encrypt_file(file_path: str, output_path: Optional[str] = None) -> str:
    """
    Encrypt a file using symmetric encryption.
    
    Args:
        file_path: Path to file to encrypt
        output_path: Output path for encrypted file
        
    Returns:
        Path to encrypted file
        
    Raises:
        EncryptionError: If file encryption fails
    """
    try:
        if not output_path:
            output_path = file_path + ".encrypted"
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = encrypt_data(file_data)
        
        with open(output_path, 'w') as f:
            f.write(encrypted_data)
        
        logger.info(f"File encrypted successfully: {file_path} -> {output_path}")
        return output_path
        
    except Exception as e:
        logger.error(f"File encryption failed: {e}")
        raise EncryptionError(f"File encryption failed: {e}")


def decrypt_file(encrypted_file_path: str, output_path: Optional[str] = None) -> str:
    """
    Decrypt an encrypted file.
    
    Args:
        encrypted_file_path: Path to encrypted file
        output_path: Output path for decrypted file
        
    Returns:
        Path to decrypted file
        
    Raises:
        EncryptionError: If file decryption fails
    """
    try:
        if not output_path:
            if encrypted_file_path.endswith('.encrypted'):
                output_path = encrypted_file_path[:-10]  # Remove .encrypted
            else:
                output_path = encrypted_file_path + ".decrypted"
        
        with open(encrypted_file_path, 'r') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_data(encrypted_data)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data.encode('utf-8'))
        
        logger.info(f"File decrypted successfully: {encrypted_file_path} -> {output_path}")
        return output_path
        
    except Exception as e:
        logger.error(f"File decryption failed: {e}")
        raise EncryptionError(f"File decryption failed: {e}")


def mask_pii(text: str, mask_char: str = "*") -> str:
    """
    Mask PII data in text with a specified character.
    
    Args:
        text: Text containing potential PII
        mask_char: Character to use for masking
        
    Returns:
        Text with PII masked
    """
    import re
    
    # Email masking
    text = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        lambda m: f"{m.group()[0]}{'*' * (len(m.group()) - 2)}{m.group()[-1] if '@' in m.group() else ''}",
        text
    )
    
    # Phone number masking (various formats)
    text = re.sub(
        r'\b(\+?1?[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        lambda m: f"{'*' * (len(m.group()) - 4)}{m.group()[-4:]}",
        text
    )
    
    # SSN masking
    text = re.sub(
        r'\b\d{3}-\d{2}-\d{4}\b',
        f"***-**-{mask_char * 4}",
        text
    )
    
    # Credit card masking
    text = re.sub(
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        lambda m: f"{'*' * (len(m.group()) - 4)}{m.group()[-4:]}",
        text
    )
    
    return text


# Initialize global encryption manager
try:
    _encryption_manager = EncryptionManager()
    logger.info(f"Encryption initialized (key fingerprint: {_encryption_manager.get_key_fingerprint()})")
except Exception as e:
    logger.error(f"Failed to initialize encryption: {e}")
    _encryption_manager = None