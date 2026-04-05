from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import hashlib
import json
from datetime import datetime

class EncryptionLayer:
    def __init__(self):
        self.key_file = 'encryption_key.key'
        self.user_keys_file = 'user_keys.json'
        self.master_key = self._load_or_create_key()
        self.fernet = Fernet(self.master_key)
        self.user_keys = self._load_user_keys()
    
    def _load_or_create_key(self):
        """Load existing master key or create a new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as key_file:
                key_file.write(key)
            return key
    
    def _load_user_keys(self):
        """Load user-specific encryption keys"""
        if os.path.exists(self.user_keys_file):
            try:
                with open(self.user_keys_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_user_keys(self):
        """Save user-specific encryption keys"""
        with open(self.user_keys_file, 'w') as f:
            json.dump(self.user_keys, f)
    
    def _derive_fernet_key_from_password(self, password, salt):
        """Derive a proper Fernet key from password using PBKDF2"""
        # Convert password to bytes
        password_bytes = password.encode('utf-8')
        
        # Create PBKDF2 key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Fernet requires 32 bytes
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        # Derive key
        key_bytes = kdf.derive(password_bytes)
        
        # Convert to base64 URL-safe format that Fernet expects
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        
        return fernet_key
    
    def generate_user_key(self, user_id, user_password):
        """Generate and store user-specific encryption key"""
        # Generate random salt for this user
        salt = os.urandom(32)
        
        # Derive Fernet key from password
        fernet_key = self._derive_fernet_key_from_password(user_password, salt)
        
        # Store salt for this user (not the key itself)
        self.user_keys[str(user_id)] = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'created_at': datetime.utcnow().isoformat()
        }
        self._save_user_keys()
        
        return fernet_key
    
    def get_user_key(self, user_id, user_password):
        """Retrieve and regenerate user key from password"""
        if str(user_id) not in self.user_keys:
            return self.generate_user_key(user_id, user_password)
        
        user_info = self.user_keys[str(user_id)]
        salt = base64.b64decode(user_info['salt'])
        
        # Derive Fernet key from password using the stored salt
        fernet_key = self._derive_fernet_key_from_password(user_password, salt)
        
        return fernet_key
    
    def verify_user_key(self, user_id, user_password):
        """Verify if the provided password generates the correct key"""
        try:
            # Get the key for this user
            key = self.get_user_key(user_id, user_password)
            
            # Test encryption/decryption with a test string
            fernet = Fernet(key)
            test_data = b"test_encryption_verification"
            encrypted = fernet.encrypt(test_data)
            decrypted = fernet.decrypt(encrypted)
            
            return decrypted == test_data
        except Exception as e:
            print(f"Key verification failed: {e}")
            return False
    
    def encrypt_file(self, file_data, user_key=None):
        """Encrypt file data using Fernet symmetric encryption"""
        try:
            if user_key:
                # Ensure user_key is bytes and properly formatted
                if isinstance(user_key, str):
                    user_key = user_key.encode()
                fernet = Fernet(user_key)
            else:
                fernet = self.fernet
            
            encrypted_data = fernet.encrypt(file_data)
            return encrypted_data
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_data, user_key=None):
        """Decrypt file data"""
        try:
            if user_key:
                # Ensure user_key is bytes and properly formatted
                if isinstance(user_key, str):
                    user_key = user_key.encode()
                fernet = Fernet(user_key)
            else:
                fernet = self.fernet
            
            decrypted_data = fernet.decrypt(encrypted_data)
            return decrypted_data
        except Exception as e:
            raise Exception(f"Decryption failed: Invalid key or corrupted file. {str(e)}")
    
    def generate_file_hash(self, file_data):
        """Generate SHA-256 hash for file integrity"""
        return hashlib.sha256(file_data).hexdigest()
    
    def verify_file_integrity(self, file_data, expected_hash):
        """Verify file integrity using hash comparison"""
        actual_hash = self.generate_file_hash(file_data)
        return actual_hash == expected_hash