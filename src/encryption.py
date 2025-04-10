from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

class FileEncryptor:
    """Handles file encryption and decryption using AES-256."""
    
    SALT_SIZE = 32
    KEY_SIZE = 32  # for AES-256
    BLOCK_SIZE = 16
    
    @staticmethod
    def generate_key(password: str, salt: bytes = None) -> tuple:
        """Generate an encryption key from password using PBKDF2."""
        if salt is None:
            salt = get_random_bytes(FileEncryptor.SALT_SIZE)
        key = PBKDF2(
            password.encode(),
            salt,
            dkLen=FileEncryptor.KEY_SIZE,
            count=1000000  # High iteration count for security
        )
        return key, salt

    def encrypt_file(self, file_path: str, password: str) -> str:
        """
        Encrypt a file using AES-256-CBC with password-derived key.
        Returns the path of the encrypted file.
        """
        try:
            # Generate key and salt
            key, salt = self.generate_key(password)
            
            # Generate random IV
            iv = get_random_bytes(AES.block_size)
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Create output file path
            output_path = f"{file_path}.locked"
            
            # Read and encrypt file
            with open(file_path, 'rb') as file_in:
                file_data = file_in.read()
                
                # Pad the data
                padded_data = pad(file_data, AES.block_size)
                
                # Encrypt the data
                encrypted_data = cipher.encrypt(padded_data)
                
                # Write salt, IV, and encrypted data to output file
                with open(output_path, 'wb') as file_out:
                    file_out.write(salt)  # First SALT_SIZE bytes are the salt
                    file_out.write(iv)    # Next BLOCK_SIZE bytes are the IV
                    file_out.write(encrypted_data)  # Rest is encrypted data
                    
            return output_path
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    def decrypt_file(self, encrypted_file_path: str, password: str) -> str:
        """
        Decrypt a file using AES-256-CBC with password-derived key.
        Returns the path of the decrypted file.
        """
        try:
            # Read the encrypted file
            with open(encrypted_file_path, 'rb') as file_in:
                # Read salt and IV
                salt = file_in.read(self.SALT_SIZE)
                iv = file_in.read(AES.block_size)
                
                # Read encrypted data
                encrypted_data = file_in.read()
                
                # Generate key from password and salt
                key, _ = self.generate_key(password, salt)
                
                # Create cipher
                cipher = AES.new(key, AES.MODE_CBC, iv)
                
                # Decrypt and unpad the data
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                
                # Create output file path (remove .locked extension)
                output_path = encrypted_file_path[:-7] if encrypted_file_path.endswith('.locked') else f"{encrypted_file_path}_decrypted"
                
                # Write decrypted data
                with open(output_path, 'wb') as file_out:
                    file_out.write(decrypted_data)
                    
                return output_path
                
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
