import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet


class CryptoService:
    """Service for encryption, decryption, and password hashing"""

    ITERATIONS = 100000

    @staticmethod
    def pbkdf2(password: str, salt: bytes, iterations: int = 100000, key_length: int = 32) -> bytes:
        """
        PBKDF2 implementation using hashlib

        Args:
            password: Password to hash
            salt: Salt for hashing
            iterations: Number of iterations
            key_length: Length of derived key

        Returns:
            Derived key as bytes
        """
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, key_length)

    @staticmethod
    def hash_master_password(password: str) -> str:
        """
        Hash master password using PBKDF2 with random salt
        This is one-way hashing for authentication

        Args:
            password: Master password to hash

        Returns:
            Hashed password with salt as string (salt:hash)
        """
        # Generate random salt
        salt = os.urandom(16)

        # Derive key using PBKDF2
        key = CryptoService.pbkdf2(password, salt, CryptoService.ITERATIONS, 32)

        # Combine salt and hash, then base64 encode
        hashed = base64.b64encode(salt + key).decode()
        return hashed

    @staticmethod
    def verify_master_password(password: str, hashed_password: str) -> bool:
        """
        Verify master password against stored hash

        Args:
            password: Plain master password to verify
            hashed_password: Stored hashed password (salt:hash)

        Returns:
            True if password matches, False otherwise
        """
        try:
            # Decode the stored hash
            decoded = base64.b64decode(hashed_password)

            # Extract salt and hash
            salt = decoded[:16]
            stored_hash = decoded[16:]

            # Hash the input password with the same salt
            key = CryptoService.pbkdf2(password, salt, CryptoService.ITERATIONS, 32)

            # Compare the hashes using constant-time comparison
            return hmac.compare_digest(key, stored_hash)
        except Exception:
            return False

    @staticmethod
    def generate_encryption_key(master_password: str, salt: bytes = None) -> bytes:
        """
        Generate Fernet encryption key from master password
        This key is used to encrypt/decrypt individual passwords

        Args:
            master_password: User's master password
            salt: Optional salt for key derivation (if None, uses empty bytes for consistency)

        Returns:
            Fernet key as bytes
        """
        if salt is None:
            salt = b''  # Empty salt for deterministic key generation

        # Derive key using PBKDF2
        key = CryptoService.pbkdf2(master_password, salt, CryptoService.ITERATIONS, 32)
        # Fernet requires base64 encoded key
        return base64.urlsafe_b64encode(key)

    @staticmethod
    def encrypt_password(password: str, master_password: str) -> str:
        """
        Encrypt individual password using Fernet with master password derived key

        Args:
            password: Password to encrypt (e.g., Gmail password)
            master_password: User's master password

        Returns:
            Encrypted password as string
        """
        try:
            encryption_key = CryptoService.generate_encryption_key(master_password)
            cipher_suite = Fernet(encryption_key)
            encrypted_password = cipher_suite.encrypt(password.encode())
            return encrypted_password.decode()
        except Exception as e:
            raise Exception(f"Error encrypting password: {str(e)}")

    @staticmethod
    def decrypt_password(encrypted_password: str, master_password: str) -> str:
        """
        Decrypt individual password using Fernet with master password derived key

        Args:
            encrypted_password: Encrypted password string
            master_password: User's master password

        Returns:
            Decrypted password as string
        """
        try:
            encryption_key = CryptoService.generate_encryption_key(master_password)
            cipher_suite = Fernet(encryption_key)
            decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
            return decrypted_password.decode()
        except Exception as e:
            raise Exception(f"Error decrypting password: {str(e)}")