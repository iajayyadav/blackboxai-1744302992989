from src.encryption import FileEncryptor
from src.password_manager import PasswordManager
from src.db_logger import HistoryLogger
import argparse
import os

class SecureFileLockerCLI:
    def __init__(self):
        self.encryptor = FileEncryptor()
        self.password_manager = PasswordManager()
        self.history_logger = HistoryLogger()

    def set_password(self, password):
        """Set the encryption password"""
        try:
            self.password_manager.set_password(password)
            print("✅ Password set successfully!")
            return True
        except ValueError as e:
            print(f"❌ Error: {str(e)}")
            return False

    def encrypt_file(self, file_path, password):
        """Encrypt a file"""
        try:
            if not os.path.exists(file_path):
                print("❌ Error: File not found!")
                return False

            encrypted_path = self.encryptor.encrypt_file(file_path, password)
            self.history_logger.log_operation(file_path, "encrypt", "success")
            print(f"✅ File encrypted successfully! Saved as: {encrypted_path}")
            return True
        except Exception as e:
            self.history_logger.log_operation(file_path, "encrypt", "failed", str(e))
            print(f"❌ Encryption failed: {str(e)}")
            return False

    def decrypt_file(self, file_path, password):
        """Decrypt a file"""
        try:
            if not os.path.exists(file_path):
                print("❌ Error: File not found!")
                return False

            if not file_path.endswith('.locked'):
                print("❌ Error: Not an encrypted file (must end with .locked)")
                return False

            decrypted_path = self.encryptor.decrypt_file(file_path, password)
            self.history_logger.log_operation(file_path, "decrypt", "success")
            print(f"✅ File decrypted successfully! Saved as: {decrypted_path}")
            return True
        except Exception as e:
            self.history_logger.log_operation(file_path, "decrypt", "failed", str(e))
            print(f"❌ Decryption failed: {str(e)}")
            return False

    def show_history(self):
        """Display operation history"""
        try:
            history = self.history_logger.get_history()
            if not history:
                print("No operation history found.")
                return

            print("\n📋 Operation History:")
            print("-" * 80)
            print(f"{'Timestamp':<20} {'Operation':<10} {'Status':<10} {'File':<30}")
            print("-" * 80)
            
            for entry in history:
                timestamp = entry['timestamp'][:19]  # Truncate microseconds
                print(f"{timestamp:<20} {entry['operation']:<10} {entry['status']:<10} {os.path.basename(entry['file_path']):<30}")
            
            print("-" * 80)
        except Exception as e:
            print(f"❌ Error retrieving history: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Secure File Locker - CLI Version")
    parser.add_argument('action', choices=['encrypt', 'decrypt', 'set-password', 'history'],
                       help='Action to perform')
    parser.add_argument('--file', '-f', help='File to encrypt/decrypt')
    parser.add_argument('--password', '-p', help='Password for encryption/decryption')

    args = parser.parse_args()
    
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    app = SecureFileLockerCLI()

    if args.action == 'set-password':
        if not args.password:
            print("❌ Error: Password is required for set-password action")
            return
        app.set_password(args.password)

    elif args.action == 'encrypt':
        if not args.file or not args.password:
            print("❌ Error: Both file and password are required for encryption")
            return
        app.encrypt_file(args.file, args.password)

    elif args.action == 'decrypt':
        if not args.file or not args.password:
            print("❌ Error: Both file and password are required for decryption")
            return
        app.decrypt_file(args.file, args.password)

    elif args.action == 'history':
        app.show_history()

if __name__ == "__main__":
    main()
