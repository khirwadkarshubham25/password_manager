import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet


class CryptoService:

    ITERATIONS = 100000

    @staticmethod
    def pbkdf2(password: str, salt: bytes, iterations: int = 100000, key_length: int = 32) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, key_length)

    @staticmethod
    def hash_master_password(password: str) -> str:
        salt = os.urandom(16)
        key = CryptoService.pbkdf2(password, salt, CryptoService.ITERATIONS, 32)
        hashed = base64.b64encode(salt + key).decode()
        return hashed

    @staticmethod
    def verify_master_password(password: str, hashed_password: str) -> bool:
        try:
            decoded = base64.b64decode(hashed_password)
            salt = decoded[:16]
            stored_hash = decoded[16:]
            key = CryptoService.pbkdf2(password, salt, CryptoService.ITERATIONS, 32)
            return hmac.compare_digest(key, stored_hash)
        except Exception:
            return False

    @staticmethod
    def generate_encryption_key(master_password: str, salt: bytes = None) -> bytes:
        if salt is None:
            salt = b''

        key = CryptoService.pbkdf2(master_password, salt, CryptoService.ITERATIONS, 32)
        return base64.urlsafe_b64encode(key)

    @staticmethod
    def encrypt_password(password: str, master_password: str) -> str:
        try:
            encryption_key = CryptoService.generate_encryption_key(master_password)
            cipher_suite = Fernet(encryption_key)
            encrypted_password = cipher_suite.encrypt(password.encode())
            return encrypted_password.decode()
        except Exception as e:
            raise Exception(f"Error encrypting password: {str(e)}")

    @staticmethod
    def decrypt_password(encrypted_password: str, master_password: str) -> str:
        try:
            encryption_key = CryptoService.generate_encryption_key(master_password)
            cipher_suite = Fernet(encryption_key)
            decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
            return decrypted_password.decode()
        except Exception as e:
            raise Exception(f"Error decrypting password: {str(e)}")