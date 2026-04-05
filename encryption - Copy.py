# encryption.py
import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import hashlib

class EncryptionLayer:
    def __init__(self, key_file='encryption_key.key'):
        self.key_file = key_file
        self.user_keys_file = 'user_keys.json'
        self.master_key = self._load_or_generate_master_key()
        
    def _load_or_generate_master_key(self):
        """Load existing master key or generate a new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key
    
    def generate_master_key(self, password=None):
        """
        Generate a master encryption key for a user
        If password is provided, derive key from password
        Otherwise generate a random key
        """
        if password:
            # Derive key from password using PBKDF2
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Store salt with the key (or separately)
            return key
        else:
            # Generate random key
            return Fernet.generate_key()
    
    def generate_user_key(self, user_id, password):
        """
        Generate and store a user-specific encryption key derived from their password
        """
        # Generate salt for this user
        salt = os.urandom(16)
        
        # Derive key from password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        user_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Store the key and salt
        self.store_user_key(user_id, user_key, password, salt)
        
        return user_key
    
    def store_user_key(self, user_id, user_key, password, salt=None):
        """
        Store user's encryption key with salt
        """
        user_keys = {}
        
        # Load existing keys if file exists
        if os.path.exists(self.user_keys_file):
            try:
                with open(self.user_keys_file, 'r') as f:
                    user_keys = json.load(f)
            except:
                user_keys = {}
        
        # If salt not provided, generate it
        if salt is None:
            salt = os.urandom(16)
        
        # Store key and salt (key is base64 encoded already)
        user_keys[str(user_id)] = {
            'key': user_key.decode() if isinstance(user_key, bytes) else user_key,
            'salt': base64.b64encode(salt).decode(),
            'created_at': str(__import__('datetime').datetime.utcnow())
        }
        
        # Save to file
        with open(self.user_keys_file, 'w') as f:
            json.dump(user_keys, f, indent=2)
    
    def get_user_key(self, user_id, password):
        """
        Retrieve and derive user's encryption key using their password
        """
        if not os.path.exists(self.user_keys_file):
            raise Exception("User keys file not found")
        
        with open(self.user_keys_file, 'r') as f:
            user_keys = json.load(f)
        
        user_id_str = str(user_id)
        if user_id_str not in user_keys:
            # Generate new key for this user
            return self.generate_user_key(user_id, password)
        
        # Get stored salt
        salt = base64.b64decode(user_keys[user_id_str]['salt'])
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        user_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Verify it matches the stored key
        stored_key = user_keys[user_id_str]['key']
        if user_key.decode() != stored_key:
            raise Exception("Invalid password - key mismatch")
        
        return user_key
    
    def verify_user_key(self, user_id, password):
        """
        Verify if the password generates the correct key
        """
        try:
            key = self.get_user_key(user_id, password)
            return True
        except Exception:
            return False
    
    def encrypt_file(self, file_data, key=None):
        """
        Encrypt file data using provided key or master key
        """
        if key is None:
            key = self.master_key
        
        # Ensure key is bytes
        if isinstance(key, str):
            key = key.encode()
        
        f = Fernet(key)
        encrypted_data = f.encrypt(file_data)
        return encrypted_data
    
    def decrypt_file(self, encrypted_data, key=None):
        """
        Decrypt file data using provided key or master key
        """
        if key is None:
            key = self.master_key
        
        # Ensure key is bytes
        if isinstance(key, str):
            key = key.encode()
        
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data
    
    def generate_file_hash(self, file_data):
        """
        Generate SHA-256 hash of file for integrity checking
        """
        return hashlib.sha256(file_data).hexdigest()
    
    def get_encryption_key_info(self, user_id):
        """
        Get information about user's encryption key without revealing the key
        """
        if not os.path.exists(self.user_keys_file):
            return None
        
        with open(self.user_keys_file, 'r') as f:
            user_keys = json.load(f)
        
        user_id_str = str(user_id)
        if user_id_str in user_keys:
            return {
                'has_key': True,
                'created_at': user_keys[user_id_str].get('created_at'),
                'key_type': 'Fernet (AES-256)',
                'derivation': 'PBKDF2 with SHA-256',
                'iterations': 100000
            }
        
        return {'has_key': False}