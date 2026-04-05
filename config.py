import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///privacy_protection.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Encryption settings
    ENCRYPTION_KEY_FILE = 'encryption_key.key'
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    
    # Privacy thresholds
    SENSITIVE_DATA_THRESHOLD = 0.7
    ANOMALY_THRESHOLD = 0.85
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')  # Your email address
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')  # Your email password or app-specific password
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or MAIL_USERNAME
    
    # Optional: Email settings for different providers
    # For Gmail: MAIL_SERVER='smtp.gmail.com', MAIL_PORT=587, MAIL_USE_TLS=True
    # For Outlook: MAIL_SERVER='smtp-mail.outlook.com', MAIL_PORT=587, MAIL_USE_TLS=True
    # For Yahoo: MAIL_SERVER='smtp.mail.yahoo.com', MAIL_PORT=587, MAIL_USE_TLS=True
    # For custom domain: Configure based on your email provider