from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64
import secrets
import logging
from typing import Union, Tuple, Optional, Dict, Any
import hmac
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("encryptor")

class EncryptionError(Exception):
    """Custom exception for encryption-related errors"""
    pass

# Supported encryption methods
ENCRYPTION_METHODS = {
    "none": "No encryption",
    "aes": "AES-256 GCM mode with key derivation",
    "xor": "XOR with SHA-256 key derivation"
}

def pad(data: bytes) -> bytes:
    """
    PKCS#7 padding for block cipher alignment
    
    Args:
        data: Raw bytes to pad
        
    Returns:
        Padded data
    """
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding with validation
    
    Args:
        data: Padded data
        
    Returns:
        Unpadded data
        
    Raises:
        EncryptionError: If padding is invalid
    """
    if not data:
        logger.error("Empty data for unpadding")
        raise EncryptionError("Empty data for unpadding")
    
    try:
        pad_len = data[-1]
        if pad_len > 16 or pad_len < 1:
            logger.error(f"Invalid padding length: {pad_len}")
            raise EncryptionError("Invalid padding")
        
        if not all(byte == pad_len for byte in data[-pad_len:]):
            logger.error("Padding verification failed")
            raise EncryptionError("Padding verification failed")
        
        return data[:-pad_len]
    except IndexError:
        logger.error("Padding error: Data too short")
        raise EncryptionError("Data too short for unpadding")

def derive_key(key: Union[str, bytes], salt: Optional[bytes] = None, 
              key_length: int = 32) -> Tuple[bytes, bytes]:
    """
    Derive a secure encryption key using scrypt KDF
    
    Args:
        key: Base key (string or bytes)
        salt: Optional salt for key derivation
        key_length: Desired key length in bytes
        
    Returns:
        Tuple of (derived key, salt used)
    """
    if salt is None:
        salt = get_random_bytes(16)
    
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    logger.debug(f"Deriving key with salt length: {len(salt)}")
    
    try:
        derived_key = scrypt(key, salt, key_len=key_length, N=2**14, r=8, p=1)
        return derived_key, salt
    except Exception as e:
        logger.error(f"Key derivation failed: {str(e)}")
        raise EncryptionError(f"Key derivation failed: {str(e)}")

def encrypt_aes_gcm(data: bytes, key: Union[str, bytes]) -> bytes:
    """
    Encrypt data using AES-GCM (Authenticated Encryption)
    
    Args:
        data: Data to encrypt
        key: Encryption key (string or bytes)
    
    Returns:
        Encrypted data in format: salt (16B) + nonce (12B) + tag (16B) + ciphertext
    
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        # Ensure data is properly padded
        padded_data = pad(data)
        
        # Derive key if string or wrong length
        if isinstance(key, str) or len(key) not in (16, 24, 32):
            key, salt = derive_key(key)
        else:
            salt = get_random_bytes(16)  # Still need salt for consistent format
        
        # Generate nonce
        nonce = get_random_bytes(12)
        
        # Create cipher and encrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(padded_data)
        
        # Combine components for output
        result = salt + nonce + tag + ciphertext
        logger.debug(f"AES encryption complete. Output size: {len(result)} bytes")
        
        return result
    except Exception as e:
        logger.error(f"AES-GCM encryption failed: {str(e)}")
        raise EncryptionError(f"AES-GCM encryption failed: {str(e)}")

def decrypt_aes_gcm(data: bytes, key: Union[str, bytes]) -> bytes:
    """
    Decrypt AES-GCM encrypted data
    
    Args:
        data: Encrypted data with format: salt + nonce + tag + ciphertext
        key: Encryption key (string or bytes)
    
    Returns:
        Decrypted data
        
    Raises:
        EncryptionError: If decryption fails
    """
    if len(data) < 44:  # 16 (salt) + 12 (nonce) + 16 (tag)
        logger.error("Data too short for AES-GCM format")
        raise EncryptionError("Data too short for AES-GCM format")
    
    try:
        # Extract components
        salt = data[:16]
        nonce = data[16:28]
        tag = data[28:44]
        ciphertext = data[44:]
        
        # Derive key if needed
        if isinstance(key, str) or len(key) not in (16, 24, 32):
            key, _ = derive_key(key, salt=salt)
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Remove padding
        result = unpad(plaintext)
        logger.debug(f"AES decryption complete. Output size: {len(result)} bytes")
        
        return result
    except Exception as e:
        logger.error(f"AES-GCM decryption failed: {str(e)}")
        raise EncryptionError(f"AES-GCM decryption failed: {str(e)}")

def encrypt_xor(data: bytes, key: str) -> bytes:
    """
    Encrypt data using XOR with key derivation
    
    Args:
        data: Data to encrypt
        key: XOR key string
    
    Returns:
        XOR-encrypted data with HMAC
    
    Raises:
        EncryptionError: If key is invalid
    """
    if not key:
        logger.error("Empty XOR key")
        raise EncryptionError("XOR key cannot be empty")
    
    try:
        # Derive consistent XOR key from input
        key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
        
        # Use full key for better security instead of just first byte
        expanded_key = key_bytes * (len(data) // len(key_bytes) + 1)
        expanded_key = expanded_key[:len(data)]
        
        # Perform XOR encryption with full key
        encrypted = bytes([a ^ b for a, b in zip(data, expanded_key)])
        
        # Add HMAC for integrity checking
        hmac_digest = hmac.new(key_bytes, encrypted, hashlib.sha256).digest()
        result = hmac_digest[:8] + encrypted  # First 8 bytes of HMAC as checksum
        
        logger.debug(f"XOR encryption complete. Output size: {len(result)} bytes")
        return result
    except Exception as e:
        logger.error(f"XOR encryption failed: {str(e)}")
        raise EncryptionError(f"XOR encryption failed: {str(e)}")

def decrypt_xor(data: bytes, key: str) -> bytes:
    """
    Decrypt XOR encrypted data
    
    Args:
        data: Encrypted data with format: hmac_digest + ciphertext
        key: XOR key string
    
    Returns:
        Decrypted data
        
    Raises:
        EncryptionError: If decryption fails or data integrity check fails
    """
    if len(data) < 8:
        logger.error("Data too short for XOR format")
        raise EncryptionError("Data too short for XOR format")
    
    try:
        # Extract components
        hmac_check = data[:8]
        ciphertext = data[8:]
        
        # Derive key
        key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
        
        # Verify HMAC
        expected_hmac = hmac.new(key_bytes, ciphertext, hashlib.sha256).digest()[:8]
        if not hmac.compare_digest(hmac_check, expected_hmac):
            logger.error("XOR HMAC verification failed")
            raise EncryptionError("Data integrity check failed")
        
        # Expand key to match ciphertext length
        expanded_key = key_bytes * (len(ciphertext) // len(key_bytes) + 1)
        expanded_key = expanded_key[:len(ciphertext)]
        
        # Perform XOR decryption (same as encryption)
        plaintext = bytes([a ^ b for a, b in zip(ciphertext, expanded_key)])
        
        logger.debug(f"XOR decryption complete. Output size: {len(plaintext)} bytes")
        return plaintext
    except Exception as e:
        logger.error(f"XOR decryption failed: {str(e)}")
        raise EncryptionError(f"XOR decryption failed: {str(e)}")

def encrypt_stub(stub: Union[str, bytes], method: str, key: Optional[str] = None) -> bytes:
    """
    Encrypt stub code using specified method
    
    Args:
        stub: The stub code to encrypt (string or bytes)
        method: Encryption method ('aes', 'xor', or 'none')
        key: Encryption key (optional for 'none')
    
    Returns:
        Encrypted data as bytes
    
    Raises:
        EncryptionError: For invalid parameters or encryption failures
        ValueError: For invalid method
    """
    if not stub:
        logger.error("Empty stub data")
        raise EncryptionError("Empty stub data")
    
    # Convert string to bytes if needed
    if isinstance(stub, str):
        data = stub.encode('utf-8')
    else:
        data = stub

    method = method.lower()
    logger.info(f"Encrypting {len(data)} bytes with method: {method}")
    
    try:
        if method == "aes":
            if not key:
                logger.error("Missing key for AES encryption")
                raise EncryptionError("AES encryption requires a key")
            return encrypt_aes_gcm(data, key)
        
        elif method == "xor":
            if not key:
                logger.error("Missing key for XOR encryption")
                raise EncryptionError("XOR encryption requires a key")
            return encrypt_xor(data, key)
        
        elif method == "none":
            logger.debug("No encryption applied")
            return data
        
        else:
            logger.error(f"Unknown encryption method: {method}")
            raise ValueError(f"Unsupported encryption method: {method}. " +
                           f"Valid methods are: {', '.join(ENCRYPTION_METHODS.keys())}")
    
    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise EncryptionError(f"Encryption failed: {str(e)}")

def decrypt_stub(encrypted_stub: bytes, method: str, key: Optional[str] = None) -> bytes:
    """
    Decrypt stub code using specified method
    
    Args:
        encrypted_stub: The encrypted stub code
        method: Encryption method used ('aes', 'xor', or 'none')
        key: Decryption key (optional for 'none')
    
    Returns:
        Decrypted data as bytes
    
    Raises:
        EncryptionError: For invalid parameters or decryption failures
        ValueError: For invalid method
    """
    if not encrypted_stub:
        logger.error("Empty encrypted data")
        raise EncryptionError("Empty encrypted data")
    
    method = method.lower()
    logger.info(f"Decrypting {len(encrypted_stub)} bytes with method: {method}")
    
    try:
        if method == "aes":
            if not key:
                logger.error("Missing key for AES decryption")
                raise EncryptionError("AES decryption requires a key")
            return decrypt_aes_gcm(encrypted_stub, key)
        
        elif method == "xor":
            if not key:
                logger.error("Missing key for XOR decryption")
                raise EncryptionError("XOR decryption requires a key")
            return decrypt_xor(encrypted_stub, key)
        
        elif method == "none":
            logger.debug("No decryption needed")
            return encrypted_stub
        
        else:
            logger.error(f"Unknown encryption method: {method}")
            raise ValueError(f"Unsupported encryption method: {method}. " +
                           f"Valid methods are: {', '.join(ENCRYPTION_METHODS.keys())}")
    
    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise EncryptionError(f"Decryption failed: {str(e)}")

def get_encryption_methods() -> Dict[str, str]:
    """
    Get all supported encryption methods
    
    Returns:
        Dictionary of method names and descriptions
    """
    return dict(ENCRYPTION_METHODS)


# Testing functionality when module is run directly
if __name__ == "__main__":
    # Simple self-test
    print("Encryption Self-Test")
    print("===================")
    
    # Test data
    test_data = b"This is a test of the encryption module."
    test_key = "SecretKey123"
    
    # Test each encryption method
    for method in ENCRYPTION_METHODS:
        try:
            print(f"\nTesting {method} encryption:")
            if method == "none":
                encrypted = encrypt_stub(test_data, method)
                decrypted = decrypt_stub(encrypted, method)
            else:
                encrypted = encrypt_stub(test_data, method, test_key)
                decrypted = decrypt_stub(encrypted, method, test_key)
            
            print(f"  Original: {test_data}")
            print(f"  Encrypted length: {len(encrypted)} bytes")
            print(f"  Decrypted: {decrypted}")
            print(f"  Success: {test_data == decrypted}")
        except Exception as e:
            print(f"  Error: {str(e)}")