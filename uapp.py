from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import io
import json
import traceback

# At the top of app.py, before importing Config
from dotenv import load_dotenv
load_dotenv()

from config import Config
from models import db, User, File, AccessLog
from encryption import EncryptionLayer
from access_control import AccessControlLayer
from privacy_monitor import PrivacyMonitor

# Remove email imports completely for now
# from email_utils import send_encryption_key_email, send_test_email

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)

# Remove mail.init_app(app) - COMMENT OR DELETE THIS LINE

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize layers
encryption_layer = EncryptionLayer()
access_control = AccessControlLayer(app)
privacy_monitor = PrivacyMonitor()

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/test-email')
def test_email():
    """Test email functionality"""
    test_email = "mnchandana436@gmail.com"  # Your test email
    test_username = "TestUser"
    test_key = "gAAAAABmQz8xTestKeyHere1234567890"
    
    success = send_encryption_key_email_direct(test_email, test_username, test_key)
    
    if success:
        return jsonify({"message": "Test email sent successfully!"})
    else:
        return jsonify({"error": "Failed to send test email"}), 500

def verify_key_works(self, key, test_data=None):
    """Verify that a key is valid and can encrypt/decrypt"""
    try:
        from cryptography.fernet import Fernet
        
        if test_data is None:
            test_data = b"test_data_for_verification"
        
        # Ensure key is bytes
        if isinstance(key, str):
            key = key.encode()
        
        # Create Fernet instance
        fernet = Fernet(key)
        
        # Test encryption
        encrypted = fernet.encrypt(test_data)
        
        # Test decryption
        decrypted = fernet.decrypt(encrypted)
        
        # Verify it works
        return decrypted == test_data
        
    except Exception as e:
        print(f"Key verification failed: {str(e)}")
        return False

def get_user_key_info(self, user_id):
    """Get information about user's key without revealing it"""
    if not os.path.exists(self.user_keys_file):
        return None
    
    with open(self.user_keys_file, 'r') as f:
        user_keys = json.load(f)
    
    user_id_str = str(user_id)
    if user_id_str in user_keys:
        stored_key = user_keys[user_id_str]['key']
        
        # Verify the key works
        key_works = self.verify_key_works(stored_key)
        
        return {
            'has_key': True,
            'key_length': len(stored_key),
            'key_valid': key_works,
            'key_preview': stored_key[:20] + '...',
            'created_at': user_keys[user_id_str].get('created_at'),
            'salt_exists': 'salt' in user_keys[user_id_str]
        }
    
    return {'has_key': False}
    
# Add this method to your EncryptionLayer class in encryption.py

def verify_key_works(self, key, test_data=None):
    """Verify that a key is valid and can encrypt/decrypt"""
    try:
        from cryptography.fernet import Fernet
        
        if test_data is None:
            test_data = b"test_data_for_verification"
        
        # Ensure key is bytes
        if isinstance(key, str):
            key = key.encode()
        
        # Create Fernet instance
        fernet = Fernet(key)
        
        # Test encryption
        encrypted = fernet.encrypt(test_data)
        
        # Test decryption
        decrypted = fernet.decrypt(encrypted)
        
        # Verify it works
        return decrypted == test_data
        
    except Exception as e:
        print(f"Key verification failed: {str(e)}")
        return False

def get_user_key_info(self, user_id):
    """Get information about user's key without revealing it"""
    if not os.path.exists(self.user_keys_file):
        return None
    
    with open(self.user_keys_file, 'r') as f:
        user_keys = json.load(f)
    
    user_id_str = str(user_id)
    if user_id_str in user_keys:
        stored_key = user_keys[user_id_str]['key']
        
        # Verify the key works
        key_works = self.verify_key_works(stored_key)
        
        return {
            'has_key': True,
            'key_length': len(stored_key),
            'key_valid': key_works,
            'key_preview': stored_key[:20] + '...',
            'created_at': user_keys[user_id_str].get('created_at'),
            'salt_exists': 'salt' in user_keys[user_id_str]
        }
    
    return {'has_key': False}
@app.route('/debug-test-current-key')
@login_required
def debug_test_current_key():
    """Test if the current user's key works"""
    try:
        # Get stored key info
        key_info = encryption_layer.get_user_key_info(current_user.id)
        
        if key_info and key_info.get('has_key'):
            return jsonify({
                'has_key': True,
                'key_valid': key_info.get('key_valid', False),
                'key_length': key_info.get('key_length', 0),
                'key_preview': key_info.get('key_preview', ''),
                'message': 'Key is valid and working' if key_info.get('key_valid') else 'Key exists but may be corrupted'
            })
        else:
            return jsonify({
                'has_key': False,
                'message': 'No key found for this user'
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 400
@app.route('/send-test-email/<test_email>')
def send_test_email_route(test_email):
    """Send a test email to verify configuration"""
    # Check if mail is initialized
    if 'mail' not in app.extensions:
        return jsonify({
            "success": False, 
            "message": "Flask-Mail not initialized. Please restart the application."
        }), 500
    
    success = send_test_email(test_email, app)
    
    if success:
        return jsonify({"success": True, "message": f"Test email sent to {test_email}"})
    else:
        return jsonify({"success": False, "message": "Failed to send test email. Check console for details."}), 500


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Validate email
        if not email or '@' not in email:
            flash('Please enter a valid email address', 'error')
            return redirect(url_for('register'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        
        db.session.add(user)
        db.session.commit()
        
        try:
            # Generate user encryption key
            user_key = encryption_layer.generate_user_key(user.id, password)
            
            # Convert key to string
            key_string = user_key.decode() if isinstance(user_key, bytes) else str(user_key)
            
            # Print to console
            print("\n" + "="*80)
            print(f"🔑 ENCRYPTION KEY FOR {username}")
            print(f"📧 Email: {email}")
            print(f"🔐 Key: {key_string}")
            print("="*80)
            
            # Send email with the key
            email_sent = send_encryption_key_email_direct(email, username, key_string)
            
            if email_sent:
                flash('✅ Registration successful! Your encryption key has been sent to your email. Please check your inbox (and spam folder).', 'success')
            else:
                # If email fails, show key on screen
                flash(f'⚠️ Registration successful, but email failed. PLEASE COPY THIS KEY NOW: {key_string}', 'warning')
                # Store in session to show on next page
                session['temp_key'] = key_string
                session['temp_username'] = username
                return redirect(url_for('show_key'))
                
        except Exception as e:
            print(f"Error during registration: {str(e)}")
            print(traceback.format_exc())
            flash('Registration failed. Please try again.', 'error')
            db.session.rollback()
            return redirect(url_for('register'))
        
        return redirect(url_for('login'))
    
    return render_template('register.html')
@app.route('/show-key')
def show_key():
    """Display the encryption key after registration (fallback if email fails)"""
    key = session.pop('temp_key', None)
    username = session.pop('temp_username', None)
    
    if not key or not username:
        flash('No key found. Please register again.', 'error')
        return redirect(url_for('register'))
    
    return render_template('show_key.html', 
                         key=key, 
                         username=username,
                         key_length=len(key))
                         
 
@app.route('/test-key-after-registration/<key>')
def test_key_after_registration(key):
    """Test if a key is valid (for testing only)"""
    try:
        from cryptography.fernet import Fernet
        
        # Test the key
        fernet = Fernet(key.encode())
        test_data = b"test"
        encrypted = fernet.encrypt(test_data)
        decrypted = fernet.decrypt(encrypted)
        
        if decrypted == test_data:
            return jsonify({
                'success': True,
                'message': 'Key is valid and working!',
                'key_length': len(key)
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Key verification failed'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400 
@app.route('/download-key-file/<filename>')
def download_key_file(filename):
    """Download the saved key file"""
    try:
        # Security: only allow key files
        if not filename.startswith('key_') or not filename.endswith('.txt'):
            flash('Invalid file', 'error')
            return redirect(url_for('index'))
        
        filepath = os.path.join('keys', filename)
        if os.path.exists(filepath):
            return send_file(
                filepath,
                as_attachment=True,
                download_name=filename,
                mimetype='text/plain'
            )
        else:
            flash('Key file not found', 'error')
            return redirect(url_for('index'))
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('index'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            # Verify and get user key
            try:
                user_key = encryption_layer.get_user_key(user.id, password)
                # Store key in session (encoded as string)
                session['user_key'] = user_key.decode()
                session['user_id'] = user.id
            except Exception as e:
                print(f"Error loading encryption key: {str(e)}")
                flash('Warning: Could not load encryption key. Some features may be limited.', 'warning')
            
            login_user(user, remember=remember)
            
            # Log the login
            log = AccessLog(
                user_id=user.id,
                file_id=None,
                action='login',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string if request.user_agent else 'Unknown'
            )
            db.session.add(log)
            db.session.commit()
            
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')
@app.route('/debug-email-config')
def debug_email_config():
    """Debug email configuration"""
    config_info = {
        'MAIL_SERVER': app.config.get('MAIL_SERVER'),
        'MAIL_PORT': app.config.get('MAIL_PORT'),
        'MAIL_USE_TLS': app.config.get('MAIL_USE_TLS'),
        'MAIL_USE_SSL': app.config.get('MAIL_USE_SSL'),
        'MAIL_USERNAME': app.config.get('MAIL_USERNAME'),
        'MAIL_PASSWORD_SET': bool(app.config.get('MAIL_PASSWORD')),
        'MAIL_DEFAULT_SENDER': app.config.get('MAIL_DEFAULT_SENDER'),
        'is_configured': bool(app.config.get('MAIL_USERNAME') and app.config.get('MAIL_PASSWORD'))
    }
    return jsonify(config_info)
@app.route('/logout')
@login_required
def logout():
    # Clear session keys
    session.pop('user_key', None)
    session.pop('user_id', None)
    logout_user()
    return redirect(url_for('index'))
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_encryption_key_email_direct(recipient_email, username, encryption_key):
    """Send encryption key directly using SMTP"""
    try:
        # Email configuration
        sender_email = "gokulakannanr5456@gmail.com"
        password = "snon deff gnce nmdy"
        
        subject = "🔑 Your Encryption Key - Privacy Shield System"
        
        # Create email body
        body = f"""
Dear {username},

Welcome to Privacy Shield System! Your account has been successfully created.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
YOUR ENCRYPTION KEY:
{encryption_key}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ IMPORTANT: Save this key immediately! You need it to decrypt your files.

Key Details:
• Type: Fernet (AES-256)
• Created: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

How to use:
1. When downloading a file, you'll be prompted for an encryption key
2. Copy and paste this key exactly as shown above
3. The file will be decrypted and downloaded

Security Recommendations:
• Store this key in a password manager
• Never share this key with anyone
• If you lose this key, you CANNOT recover your encrypted files
• You can export your key anytime from the Key Management page

Best regards,
Privacy Shield Team
"""
        
        # Create HTML version for better formatting
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4CAF50; color: white; padding: 20px; text-align: center; }}
        .key-box {{ background-color: #f4f4f4; border: 1px solid #ddd; padding: 15px; margin: 20px 0; border-radius: 5px; font-family: monospace; word-break: break-all; }}
        .warning {{ background-color: #ffeb3b; border-left: 4px solid #f44336; padding: 15px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #777; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Privacy Shield System</h1>
            <p>Your Encryption Key</p>
        </div>
        
        <div class="warning">
            <strong>⚠️ IMPORTANT SECURITY NOTICE</strong><br>
            This key can decrypt ALL your files. Keep it secure!
        </div>
        
        <p>Dear {username},</p>
        
        <p>Welcome to Privacy Shield System! Your account has been successfully created.</p>
        
        <p><strong>Your Encryption Key:</strong></p>
        <div class="key-box">
            <code>{encryption_key}</code>
        </div>
        
        <p><strong>Key Details:</strong></p>
        <ul>
            <li>Type: Fernet (AES-256)</li>
            <li>Derivation: PBKDF2 with SHA-256</li>
            <li>Created: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</li>
        </ul>
        
        <p><strong>How to use:</strong></p>
        <ol>
            <li>When downloading a file, you'll be prompted for an encryption key</li>
            <li>Paste this key directly into the key prompt</li>
            <li>The file will be decrypted and downloaded</li>
        </ol>
        
        <div class="warning">
            <strong>🔒 Security Recommendations:</strong>
            <ul>
                <li>Save this key in a password manager immediately</li>
                <li>Delete this email after saving your key</li>
                <li>Never share this key with anyone</li>
                <li>Use the "Export Key" feature in your dashboard for backups</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>Privacy Shield System - Protecting Your Data</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Create the email
        msg = MIMEMultipart('alternative')
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        
        # Attach both plain text and HTML versions
        msg.attach(MIMEText(body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Connect to SMTP server and send
        print(f"\n📧 Sending encryption key to {recipient_email}")
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(msg)
        server.quit()
        
        print(f"✅ Email sent successfully to {recipient_email}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False
@app.route('/dashboard')
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).all()
    access_logs = AccessLog.query.filter_by(user_id=current_user.id).order_by(AccessLog.access_time.desc()).limit(10).all()
    
    # Get security metrics
    metrics = privacy_monitor.generate_security_metrics(files, access_logs)
    
    return render_template('dashboard.html', files=files, access_logs=access_logs, metrics=metrics)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@access_control.rate_limit(max_requests=50)
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file:
            # Read file data
            file_data = file.read()
            filename = secure_filename(file.filename)
            
            # Layer 3: Real-time file analysis during upload
            analysis = privacy_monitor.analyze_file_content(file_data, filename)
            
            # Get encryption type from form
            encryption_type = request.form.get('encryption', 'user')
            
            # Get user key for encryption
            user_key = None
            if encryption_type == 'user':
                if 'user_key' in session:
                    user_key = session['user_key'].encode()
                else:
                    flash('User encryption key not available. Using master key.', 'warning')
                    encryption_type = 'master'
            
            # Layer 1: Encrypt file
            try:
                if user_key:
                    encrypted_data = encryption_layer.encrypt_file(file_data, user_key)
                else:
                    encrypted_data = encryption_layer.encrypt_file(file_data)
            except Exception as e:
                flash(f'Encryption failed: {str(e)}', 'error')
                return redirect(request.url)
            
            file_hash = encryption_layer.generate_file_hash(file_data)
            
            # Save encrypted file
            encrypted_filename = f"enc_{datetime.utcnow().timestamp()}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Calculate values from analysis
            risk_score = analysis.get('risk_score', 0.0)
            privacy_level = analysis.get('risk_level', 'medium')
            classification = analysis.get('classification', 'normal')
            
            # Save file metadata
            new_file = File(
                filename=filename,
                encrypted_filename=encrypted_filename,
                file_path=file_path,
                file_size=len(file_data),
                encryption_algorithm='Fernet (AES-128)',
                sensitivity_score=risk_score,
                privacy_level=privacy_level,
                user_id=current_user.id,
                classification=classification,
                risk_score=risk_score,
                threat_count=len(analysis.get('threats_detected', [])),
                sensitive_count=len(analysis.get('sensitive_data', [])),
                file_hash=file_hash,
                file_type=analysis.get('file_type', 'unknown'),
                quarantine_status=(classification == 'malicious'),
                analysis_details=json.dumps(analysis),
                encryption_type=encryption_type
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            # Log the upload
            log = AccessLog(
                user_id=current_user.id,
                file_id=new_file.id,
                action='upload',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string if request.user_agent else 'Unknown',
                risk_level=analysis.get('risk_level', 'low'),
                additional_info=json.dumps({
                    'classification': classification,
                    'risk_score': risk_score,
                    'encryption_type': encryption_type
                })
            )
            db.session.add(log)
            db.session.commit()
            
            flash(f'File uploaded successfully! Classification: {classification.upper()}', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Layer 2: Access Control
    if not access_control.check_file_permission(current_user, file):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if this is a POST request with key submission
    if request.method == 'POST':
        key_input = request.form.get('encryption_key')
        
        if not key_input:
            flash('Please enter your encryption key', 'error')
            return render_template('key_prompt.html', file=file)
        
        try:
            # Clean the key
            key_input = key_input.strip()
            
            print(f"\n🔐 Attempting to decrypt file: {file.filename}")
            print(f"   File encryption type: {file.encryption_type}")
            
            # Handle different encryption types
            if file.encryption_type == 'master':
                print(f"   This file uses MASTER encryption")
                print(f"   Using master key from system")
                # For master encryption, we need to use the system master key
                # Get the master key from encryption layer
                user_key = encryption_layer.master_key
                print(f"   Using master key (system-wide)")
            else:
                # User encryption - use provided key
                print(f"   This file uses USER encryption")
                print(f"   Key provided: {key_input[:30]}...")
                user_key = key_input.encode()
            
            # Read encrypted file
            with open(file.file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt
            decrypted_data = encryption_layer.decrypt_file(encrypted_data, user_key)
            
            print(f"✅ Successfully decrypted file: {file.filename}")
            
            # Log successful download
            log = AccessLog(
                user_id=current_user.id,
                file_id=file.id,
                action='download',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string if request.user_agent else 'Unknown'
            )
            db.session.add(log)
            db.session.commit()
            
            # Send decrypted file
            return send_file(
                io.BytesIO(decrypted_data),
                download_name=file.filename,
                as_attachment=True,
                mimetype='application/octet-stream'
            )
            
        except Exception as e:
            error_msg = str(e)
            print(f"❌ Decryption failed: {error_msg}")
            print(traceback.format_exc())
            
            if "Invalid token" in error_msg:
                if file.encryption_type == 'master':
                    flash('Failed to decrypt with master key. The file may be corrupted.', 'error')
                else:
                    flash('Invalid encryption key! The key you provided does not match the one used to encrypt this file.', 'error')
            else:
                flash(f'Decryption failed: {error_msg}', 'error')
            
            return render_template('key_prompt.html', file=file, error=True)
    
    # GET request - show key prompt
    return render_template('key_prompt.html', file=file)
    
@app.route('/reencrypt-file/<int:file_id>', methods=['POST'])
@login_required
def reencrypt_file(file_id):
    """Re-encrypt a file from master to user encryption"""
    file = File.query.get_or_404(file_id)
    
    if file.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    if file.encryption_type != 'master':
        flash('File is already using user encryption', 'info')
        return redirect(url_for('dashboard'))
    
    try:
        # Read encrypted file
        with open(file.file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt with master key
        decrypted_data = encryption_layer.decrypt_file(encrypted_data, encryption_layer.master_key)
        
        # Re-encrypt with user key
        if 'user_key' in session:
            user_key = session['user_key'].encode()
            new_encrypted_data = encryption_layer.encrypt_file(decrypted_data, user_key)
            
            # Save back to file
            with open(file.file_path, 'wb') as f:
                f.write(new_encrypted_data)
            
            # Update file record
            file.encryption_type = 'user'
            db.session.commit()
            
            flash('File re-encrypted with your user key successfully!', 'success')
        else:
            flash('User key not found in session. Please login again.', 'error')
            
    except Exception as e:
        flash(f'Re-encryption failed: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))    
    
@app.route('/check-file-encryption')
@login_required
def check_file_encryption():
    """Check encryption type of all files"""
    files = File.query.filter_by(user_id=current_user.id).all()
    
    result = []
    for file in files:
        result.append({
            'id': file.id,
            'filename': file.filename,
            'encryption_type': file.encryption_type,
            'uploaded_at': str(file.uploaded_at),
            'download_url': f'/download/{file.id}'
        })
    
    return jsonify(result)
@app.route('/debug-full-key-info')
@login_required
def debug_full_key_info():
    """Get complete key information for debugging"""
    try:
        debug_info = {
            'user_id': current_user.id,
            'username': current_user.username,
            'key_file_exists': os.path.exists('user_keys.json')
        }
        
        if os.path.exists('user_keys.json'):
            with open('user_keys.json', 'r') as f:
                user_keys = json.load(f)
            
            user_id_str = str(current_user.id)
            if user_id_str in user_keys:
                stored_key = user_keys[user_id_str]['key']
                debug_info['stored_key'] = stored_key
                debug_info['stored_key_length'] = len(stored_key)
                debug_info['stored_key_first_10'] = stored_key[:10]
                debug_info['stored_key_last_10'] = stored_key[-10:]
                debug_info['stored_key_contains_spaces'] = ' ' in stored_key
                debug_info['stored_key_contains_newline'] = '\n' in stored_key
                
                # Check if key is valid Fernet
                from cryptography.fernet import Fernet
                try:
                    fernet = Fernet(stored_key.encode())
                    debug_info['key_valid_format'] = True
                    
                    # Test encryption/decryption
                    test_data = b"test"
                    encrypted = fernet.encrypt(test_data)
                    decrypted = fernet.decrypt(encrypted)
                    debug_info['key_works'] = (decrypted == test_data)
                except Exception as e:
                    debug_info['key_valid_format'] = False
                    debug_info['key_error'] = str(e)
        
        return jsonify(debug_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
        
@app.route('/debug-set-test-key', methods=['POST'])
@login_required
def debug_set_test_key():
    """Manually set a test key for debugging"""
    data = request.get_json()
    test_key = data.get('test_key')
    
    if not test_key:
        return jsonify({'error': 'No key provided'}), 400
    
    try:
        # Read existing keys
        if os.path.exists('user_keys.json'):
            with open('user_keys.json', 'r') as f:
                user_keys = json.load(f)
        else:
            user_keys = {}
        
        # Update user's key
        user_id_str = str(current_user.id)
        if user_id_str not in user_keys:
            user_keys[user_id_str] = {}
        
        user_keys[user_id_str]['key'] = test_key
        user_keys[user_id_str]['salt'] = "debug_salt"
        user_keys[user_id_str]['created_at'] = str(datetime.utcnow())
        
        # Save back
        with open('user_keys.json', 'w') as f:
            json.dump(user_keys, f, indent=2)
        
        return jsonify({
            'success': True,
            'message': f'Test key set for user {current_user.username}',
            'key': test_key
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400
@app.route('/test-key-page')
@login_required
def test_key_page():
    """Test key page"""
    return render_template('test_key.html')  
@app.route('/api/check-encryption-status', methods=['GET'])
@login_required
def check_encryption_status():
    """Check if user has encryption key"""
    try:
        if os.path.exists('user_keys.json'):
            with open('user_keys.json', 'r') as f:
                user_keys = json.load(f)
            
            user_id = str(current_user.id)
            has_key = user_id in user_keys
            
            return jsonify({
                'has_key': has_key,
                'user_id': user_id,
                'key_file_exists': True
            })
        else:
            return jsonify({
                'has_key': False,
                'key_file_exists': False
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/test-manual-key', methods=['POST'])
@login_required
def test_manual_key():
    """Test if a manual key works"""
    data = request.get_json()
    key_input = data.get('key')
    
    if not key_input:
        return jsonify({'valid': False, 'error': 'No key provided'}), 400
    
    try:
        # Try to create Fernet with the key
        from cryptography.fernet import Fernet
        fernet = Fernet(key_input.encode())
        
        # Test encryption/decryption
        test_data = b"test"
        encrypted = fernet.encrypt(test_data)
        decrypted = fernet.decrypt(encrypted)
        
        valid = decrypted == test_data
        
        return jsonify({'valid': valid})
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)})

@app.route('/api/reset-encryption-key', methods=['POST'])
@login_required
def reset_encryption_key():
    """Reset user's encryption key (WARNING: makes old files inaccessible)"""
    data = request.get_json()
    new_password = data.get('new_password')
    
    if not new_password:
        return jsonify({'success': False, 'error': 'No password provided'}), 400
    
    try:
        # Generate new encryption key with new password
        encryption_layer.generate_user_key(current_user.id, new_password)
        
        return jsonify({
            'success': True,
            'message': 'Encryption key reset successfully'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400
@app.route('/debug-key')
@login_required
def debug_key():
    """Debug key page"""
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('debug_key.html', files=files)
    
    
@app.route('/debug-file-encryption/<int:file_id>')
@login_required
def debug_file_encryption(file_id):
    """See what encryption was used for a file"""
    file = File.query.get_or_404(file_id)
    
    if file.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({
        'filename': file.filename,
        'encryption_type': file.encryption_type,
        'encryption_algorithm': file.encryption_algorithm,
        'uploaded_at': str(file.uploaded_at),
        'file_size': file.file_size,
        'encrypted_filename': file.encrypted_filename
    })
@app.route('/api/get-encryption-debug', methods=['GET'])
@login_required
def get_encryption_debug():
    """Get debug information about encryption"""
    debug_info = {
        'user_id': current_user.id,
        'username': current_user.username,
        'key_file_exists': os.path.exists('user_keys.json')
    }
    
    if os.path.exists('user_keys.json'):
        try:
            with open('user_keys.json', 'r') as f:
                user_keys = json.load(f)
            user_id_str = str(current_user.id)
            debug_info['has_salt'] = user_id_str in user_keys
            if debug_info['has_salt']:
                debug_info['salt_exists'] = True
                debug_info['salt_length'] = len(user_keys[user_id_str].get('salt', ''))
        except:
            debug_info['error_reading_keys'] = True
    
    return jsonify(debug_info)    
    
    
@app.route('/debug-password-check')
@login_required
def debug_password_check():
    """Debug endpoint to check password issues"""
    from werkzeug.security import check_password_hash
    
    user = current_user
    
    # This will help us see if the password hash is valid
    # Note: We can't actually test the password here without user input
    
    return jsonify({
        'username': user.username,
        'user_id': user.id,
        'has_password_hash': bool(user.password_hash),
        'encryption_type_available': os.path.exists('user_keys.json'),
        'message': 'Go to Key Management page to test your password'
    })
@app.route('/export-key', methods=['POST'])
@login_required
def export_key():
    """Export user's encryption key"""
    password = request.form.get('password')
    
    if not password:
        flash('Please enter your password to export key', 'error')
        return redirect(url_for('key_management'))
    
    try:
        # Verify password
        user = User.query.get(current_user.id)
        if not check_password_hash(user.password_hash, password):
            flash('Invalid password!', 'error')
            return redirect(url_for('key_management'))
        
        # Get the encryption key derived from password
        encryption_key = encryption_layer.get_user_key(current_user.id, password)
        
        # Create key file content
        key_info = {
            'username': current_user.username,
            'user_id': current_user.id,
            'encryption_key': encryption_key.decode(),
            'key_type': 'Fernet (AES-256)',
            'derivation': 'PBKDF2 with SHA-256',
            'iterations': 100000,
            'created_at': datetime.utcnow().isoformat(),
            'warning': 'KEEP THIS KEY SAFE! Anyone with this key can decrypt your files.'
        }
        
        # Create a text file with the key
        key_text = f"""
ENCRYPTION KEY EXPORT
=====================

Username: {current_user.username}
User ID: {current_user.id}
Key Type: Fernet (AES-256)
Key Derivation: PBKDF2 with SHA-256
Iterations: 100,000

YOUR ENCRYPTION KEY:
{encryption_key.decode()}

⚠️ IMPORTANT SECURITY NOTICE:
- This key can decrypt ALL your user-encrypted files
- Keep this key in a safe place
- Do not share this key with anyone
- If you lose this key, you cannot recover your files
- Store this key in a password manager or encrypted file

To use this key:
1. When downloading files, you can use this key instead of your password
2. Paste this key directly into the key prompt

Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """
        
        # Return as downloadable file
        return send_file(
            io.BytesIO(key_text.encode()),
            download_name=f"{current_user.username}_encryption_key.txt",
            as_attachment=True,
            mimetype='text/plain'
        )
        
    except Exception as e:
        flash(f'Error exporting key: {str(e)}', 'error')
        return redirect(url_for('key_management'))
@app.route('/file/<int:file_id>')
@login_required
def view_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Layer 2: Access Control
    if not access_control.check_file_permission(current_user, file):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # Log the access
    log = AccessLog(
        user_id=current_user.id,
        file_id=file.id,
        action='view',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string if request.user_agent else 'Unknown'
    )
    db.session.add(log)
    db.session.commit()
    
    # Get file risk summary
    risk_summary = privacy_monitor.get_file_risk_summary(file)
    
    return render_template('file_details.html', file=file, risk_summary=risk_summary)

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Layer 2: Access Control
    if not access_control.check_file_permission(current_user, file):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # Delete physical file
    if os.path.exists(file.file_path):
        os.remove(file.file_path)
    
    # Log deletion
    log = AccessLog(
        user_id=current_user.id,
        file_id=file.id,
        action='delete',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string if request.user_agent else 'Unknown'
    )
    db.session.add(log)
    
    # Delete database record
    db.session.delete(file)
    db.session.commit()
    
    flash('File deleted successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/privacy-report')
@login_required
def privacy_report():
    files = File.query.filter_by(user_id=current_user.id).all()
    access_logs = AccessLog.query.filter_by(user_id=current_user.id).order_by(AccessLog.access_time.desc()).limit(100).all()
    
    report = privacy_monitor.generate_privacy_report(current_user, files, access_logs)
    
    return render_template('privacy_report.html', report=report)
@app.route('/key-management')
@login_required
def key_management():
    """Key management page"""
    return render_template('key_management.html')
@app.route('/test-key-with-file/<int:file_id>')
@login_required
def test_key_with_file(file_id):
    """Test if the user's stored key can decrypt a file"""
    file = File.query.get_or_404(file_id)
    
    if file.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        # Get the user's stored key
        if os.path.exists('user_keys.json'):
            with open('user_keys.json', 'r') as f:
                user_keys = json.load(f)
            
            user_id_str = str(current_user.id)
            if user_id_str in user_keys:
                stored_key = user_keys[user_id_str]['key']
                
                # Try to decrypt the file with stored key
                with open(file.file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = encryption_layer.decrypt_file(encrypted_data, stored_key.encode())
                
                return jsonify({
                    'success': True,
                    'message': 'Stored key works!',
                    'key_preview': stored_key[:20] + '...',
                    'file_name': file.filename
                })
            else:
                return jsonify({'error': 'No stored key found for user'}), 404
        else:
            return jsonify({'error': 'user_keys.json not found'}), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Stored key does not work with this file'
        }), 400
@app.route('/debug-key-comparison')
@login_required
def debug_key_comparison():
    """Compare stored key with key derived from password"""
    try:
        # This is just for debugging - you'll need to enter your password
        return jsonify({
            'message': 'Please use the test-key API endpoint with your password'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400
        
@app.route('/debug-show-stored-key')
@login_required
def debug_show_stored_key():
    """Show the actual stored key (for debugging only)"""
    try:
        if os.path.exists('user_keys.json'):
            with open('user_keys.json', 'r') as f:
                user_keys = json.load(f)
            
            user_id_str = str(current_user.id)
            if user_id_str in user_keys:
                stored_key = user_keys[user_id_str]['key']
                
                return jsonify({
                    'stored_key': stored_key,
                    'stored_key_length': len(stored_key),
                    'stored_key_preview': stored_key[:30] + "...",
                    'username': current_user.username,
                    'user_id': current_user.id
                })
        return jsonify({'error': 'No key found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/debug-compare-keys', methods=['POST'])
@login_required
def debug_compare_keys():
    """Compare a provided key with the stored key"""
    data = request.get_json()
    provided_key = data.get('key')
    
    if not provided_key:
        return jsonify({'error': 'No key provided'}), 400
    
    try:
        # Get stored key
        if os.path.exists('user_keys.json'):
            with open('user_keys.json', 'r') as f:
                user_keys = json.load(f)
            
            user_id_str = str(current_user.id)
            if user_id_str in user_keys:
                stored_key = user_keys[user_id_str]['key']
                
                # Compare keys
                match = (provided_key.strip() == stored_key)
                
                return jsonify({
                    'match': match,
                    'provided_length': len(provided_key),
                    'stored_length': len(stored_key),
                    'provided_preview': provided_key[:30] + "...",
                    'stored_preview': stored_key[:30] + "...",
                    'message': 'Keys match!' if match else 'Keys do not match'
                })
        
        return jsonify({'error': 'No stored key found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/debug-test-decryption/<int:file_id>', methods=['POST'])
@login_required
def debug_test_decryption(file_id):
    """Test decryption with a specific key"""
    data = request.get_json()
    provided_key = data.get('key')
    
    if not provided_key:
        return jsonify({'error': 'No key provided'}), 400
    
    file = File.query.get_or_404(file_id)
    
    if file.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        # Try to decrypt with provided key
        user_key = provided_key.encode()
        
        # Read encrypted file
        with open(file.file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt
        decrypted_data = encryption_layer.decrypt_file(encrypted_data, user_key)
        
        return jsonify({
            'success': True,
            'message': 'Decryption successful!',
            'file_size': len(decrypted_data)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Decryption failed with this key'
        }), 400     
@app.route('/api/test-key', methods=['POST'])
@login_required
def test_key():
    """Test if provided password generates the correct key"""
    data = request.get_json()
    password = data.get('password')
    
    if not password:
        return jsonify({'valid': False, 'error': 'No password provided'}), 400
    
    try:
        # Verify the user's password generates a valid key
        is_valid = encryption_layer.verify_user_key(current_user.id, password)
        
        if is_valid:
            return jsonify({
                'valid': True,
                'message': 'Key is valid! Your password works correctly.'
            })
        else:
            return jsonify({
                'valid': False,
                'message': 'Invalid password. The encryption key derived from this password does not match.'
            })
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 400
@app.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    """API endpoint for file analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    file_data = file.read()
    
    analysis = privacy_monitor.analyze_file_content(file_data, file.filename)
    
    return jsonify(analysis)

@app.route('/api/files')
@login_required
def api_get_files():
    files = File.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': f.id,
        'filename': f.filename,
        'size': f.file_size,
        'privacy_level': f.privacy_level,
        'classification': f.classification,
        'risk_score': f.risk_score,
        'encryption_type': f.encryption_type,
        'uploaded_at': f.uploaded_at.isoformat()
    } for f in files])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)