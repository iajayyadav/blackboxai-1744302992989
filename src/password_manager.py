from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import sqlite3
import os

class PasswordManager:
    """Handles secure password management and verification."""
    
    SALT_SIZE = 32
    KEY_SIZE = 32
    MIN_PASSWORD_LENGTH = 8
    
    def __init__(self, db_path="data/history.db"):
        """Initialize the password manager with database connection."""
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize the database with password table."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create password table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS password_data (
                        id INTEGER PRIMARY KEY,
                        password_hash BLOB NOT NULL,
                        salt BLOB NOT NULL
                    )
                ''')
                
                conn.commit()
                
        except sqlite3.Error as e:
            raise Exception(f"Password database initialization failed: {str(e)}")

    def validate_password_strength(self, password: str) -> bool:
        """
        Validate password strength requirements.
        Returns True if password meets requirements, False otherwise.
        """
        if len(password) < self.MIN_PASSWORD_LENGTH:
            return False
            
        # Check for at least one uppercase letter
        if not any(c.isupper() for c in password):
            return False
            
        # Check for at least one lowercase letter
        if not any(c.islower() for c in password):
            return False
            
        # Check for at least one digit
        if not any(c.isdigit() for c in password):
            return False
            
        # Check for at least one special character
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            return False
            
        return True

    def hash_password(self, password: str, salt: bytes = None) -> tuple:
        """
        Hash the password using PBKDF2 with a high iteration count.
        Returns (hash, salt) tuple.
        """
        if salt is None:
            salt = get_random_bytes(self.SALT_SIZE)
            
        password_hash = PBKDF2(
            password.encode(),
            salt,
            dkLen=self.KEY_SIZE,
            count=1000000,  # High iteration count for security
            hmac_hash_module=SHA256
        )
        
        return password_hash, salt

    def set_password(self, password: str) -> bool:
        """
        Set a new password in the database.
        Returns True if successful, False otherwise.
        """
        try:
            if not self.validate_password_strength(password):
                raise ValueError("Password does not meet strength requirements")
                
            password_hash, salt = self.hash_password(password)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clear existing password data
                cursor.execute('DELETE FROM password_data')
                
                # Insert new password data
                cursor.execute('''
                    INSERT INTO password_data (password_hash, salt)
                    VALUES (?, ?)
                ''', (password_hash, salt))
                
                conn.commit()
                return True
                
        except Exception as e:
            raise Exception(f"Failed to set password: {str(e)}")

    def verify_password(self, password: str) -> bool:
        """
        Verify if the provided password matches the stored password.
        Returns True if password is correct, False otherwise.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get stored password data
                cursor.execute('SELECT password_hash, salt FROM password_data LIMIT 1')
                result = cursor.fetchone()
                
                if not result:
                    raise ValueError("No password has been set")
                    
                stored_hash, salt = result
                
                # Hash the provided password with the stored salt
                test_hash, _ = self.hash_password(password, salt)
                
                # Compare hashes in constant time
                return self._constant_time_compare(stored_hash, test_hash)
                
        except Exception as e:
            raise Exception(f"Password verification failed: {str(e)}")

    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time to prevent timing attacks.
        """
        if len(a) != len(b):
            return False
            
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    def get_encryption_key(self, password: str) -> bytes:
        """
        Get the encryption key derived from the password.
        Raises an exception if the password is incorrect.
        """
        if not self.verify_password(password):
            raise ValueError("Incorrect password")
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT salt FROM password_data LIMIT 1')
            salt = cursor.fetchone()[0]
            
        key, _ = self.hash_password(password, salt)
        return key
