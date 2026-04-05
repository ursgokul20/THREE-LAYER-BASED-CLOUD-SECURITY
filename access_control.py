from functools import wraps
from flask import request, jsonify, session
from flask_login import current_user
import jwt
from datetime import datetime, timedelta
import re

class AccessControlLayer:
    def __init__(self, app):
        self.app = app
        self.secret_key = app.config['SECRET_KEY']
        
    def role_required(self, *roles):
        """Decorator for role-based access control"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not current_user.is_authenticated:
                    return jsonify({'error': 'Authentication required'}), 401
                
                if current_user.role not in roles:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    def generate_access_token(self, user_id, expiration_hours=24):
        """Generate JWT token for API access"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=expiration_hours),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_token(self, token):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload['user_id']
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def check_file_permission(self, user, file):
        """Check if user has permission to access a file"""
        if user.role == 'admin':
            return True
        return file.user_id == user.id
    
    def validate_input(self, data, rules):
        """Validate input data against rules"""
        for field, rule in rules.items():
            if field not in data:
                return False, f"Missing field: {field}"
            
            value = data[field]
            
            # Check required
            if rule.get('required', False) and not value:
                return False, f"Field {field} is required"
            
            # Check type
            if 'type' in rule:
                if rule['type'] == 'string' and not isinstance(value, str):
                    return False, f"Field {field} must be a string"
                elif rule['type'] == 'integer' and not isinstance(value, int):
                    return False, f"Field {field} must be an integer"
                elif rule['type'] == 'email' and not self._validate_email(value):
                    return False, f"Field {field} must be a valid email"
            
            # Check length
            if 'min_length' in rule and len(value) < rule['min_length']:
                return False, f"Field {field} must be at least {rule['min_length']} characters"
            
            if 'max_length' in rule and len(value) > rule['max_length']:
                return False, f"Field {field} must be at most {rule['max_length']} characters"
        
        return True, "Validation passed"
    
    def _validate_email(self, email):
        """Validate email format"""
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None
    
    def rate_limit(self, max_requests=100, window_seconds=3600):
        """Rate limiting decorator"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Get client IP
                client_ip = request.remote_addr
                
                # Check rate limit in session
                if 'request_count' not in session:
                    session['request_count'] = 1
                    session['window_start'] = datetime.utcnow().timestamp()
                else:
                    window_start = session.get('window_start', 0)
                    current_time = datetime.utcnow().timestamp()
                    
                    if current_time - window_start > window_seconds:
                        # Reset window
                        session['request_count'] = 1
                        session['window_start'] = current_time
                    else:
                        session['request_count'] = session.get('request_count', 0) + 1
                
                if session.get('request_count', 0) > max_requests:
                    return jsonify({'error': 'Rate limit exceeded'}), 429
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator