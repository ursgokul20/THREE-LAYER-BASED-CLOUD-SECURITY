# email_utils.py
from flask_mail import Mail, Message
import os
import traceback
from datetime import datetime

# Create mail instance
mail = Mail()

def init_email(app):
    """Initialize email extension"""
    try:
        mail.init_app(app)
        print("✅ Email extension initialized successfully")
        print(f"   SMTP Server: {app.config.get('MAIL_SERVER')}")
        print(f"   SMTP Port: {app.config.get('MAIL_PORT')}")
        print(f"   Username set: {bool(app.config.get('MAIL_USERNAME'))}")
        print(f"   Password set: {bool(app.config.get('MAIL_PASSWORD'))}")
        return True
    except Exception as e:
        print(f"❌ Error initializing email: {str(e)}")
        return False

def send_encryption_key_email(user, encryption_key, app):
    """Send encryption key to user's email with detailed error handling"""
    try:
        with app.app_context():
            print(f"\n📧 Starting email send process for {user.email}")
            
            # Check if mail is initialized
            if 'mail' not in app.extensions:
                print("❌ Flask-Mail not initialized in app.extensions")
                return False
            
            # Check if email is configured
            if not app.config.get('MAIL_USERNAME'):
                print("❌ MAIL_USERNAME not configured in app config")
                return False
            
            if not app.config.get('MAIL_PASSWORD'):
                print("❌ MAIL_PASSWORD not configured in app config")
                return False
            
            # Create email subject and body
            subject = f"Your Encryption Key - Privacy Shield System"
            
            body = f"""
Dear {user.username},

Welcome to Privacy Shield System! Your account has been successfully created.

YOUR ENCRYPTION KEY:
{encryption_key}

⚠️ IMPORTANT: Keep this key safe! You need it to decrypt your files.

Key Details:
- Type: Fernet (AES-256)
- Created: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

How to use:
1. When downloading a file, you'll be prompted for an encryption key
2. Paste this key directly into the key prompt
3. The file will be decrypted and downloaded

Security Recommendations:
- Store this key in a password manager
- Never share this key with anyone
- Use the "Export Key" feature in your dashboard for backups

Best regards,
Privacy Shield Team
"""
            
            # Create message
            msg = Message(
                subject=subject,
                sender=app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME'),
                recipients=[user.email],
                body=body
            )
            
            print(f"📤 Attempting to send email via {app.config.get('MAIL_SERVER')}:{app.config.get('MAIL_PORT')}")
            print(f"   From: {msg.sender}")
            print(f"   To: {user.email}")
            
            # Send the email
            mail.send(msg)
            print(f"✅ Email sent successfully to {user.email}\n")
            return True
            
    except Exception as e:
        print(f"❌ Error sending email: {str(e)}")
        print("Full traceback:")
        print(traceback.format_exc())
        return False

def send_test_email(email, app):
    """Send test email to verify configuration"""
    try:
        with app.app_context():
            print(f"\n📧 Sending test email to {email}")
            
            # Check if mail is initialized
            if 'mail' not in app.extensions:
                print("❌ Flask-Mail not initialized in app.extensions")
                return False
            
            if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
                print("❌ Email not configured properly")
                return False
            
            subject = "Test Email - Privacy Shield System"
            
            body = f"""
This is a test email from Privacy Shield System.

Configuration:
- SMTP Server: {app.config.get('MAIL_SERVER')}
- SMTP Port: {app.config.get('MAIL_PORT')}
- TLS Enabled: {app.config.get('MAIL_USE_TLS')}
- From Email: {app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')}
- Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

If you're receiving this, your email configuration is working correctly!

Best regards,
Privacy Shield Team
"""
            
            msg = Message(
                subject=subject,
                sender=app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME'),
                recipients=[email],
                body=body
            )
            
            mail.send(msg)
            print(f"✅ Test email sent successfully to {email}\n")
            return True
            
    except Exception as e:
        print(f"❌ Error sending test email: {str(e)}")
        print(traceback.format_exc())
        return False