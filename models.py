from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    key_salt = db.Column(db.String(100), nullable=True)  # Store key salt
    files = db.relationship('File', backref='owner', lazy=True)
    access_logs = db.relationship('AccessLog', backref='user', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    encrypted_filename = db.Column(db.String(200), unique=True)
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    encryption_algorithm = db.Column(db.String(50))
    sensitivity_score = db.Column(db.Float, default=0.0)
    privacy_level = db.Column(db.String(20))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # New fields
    classification = db.Column(db.String(50), default='normal')
    risk_score = db.Column(db.Float, default=0.0)
    threat_count = db.Column(db.Integer, default=0)
    sensitive_count = db.Column(db.Integer, default=0)
    file_hash = db.Column(db.String(64), nullable=True)
    file_type = db.Column(db.String(100), nullable=True)
    quarantine_status = db.Column(db.Boolean, default=False)
    analysis_details = db.Column(db.Text, nullable=True)
    encryption_type = db.Column(db.String(20), default='master')  # master or user
    
    access_logs = db.relationship('AccessLog', backref='file', lazy=True)
    
    def get_analysis_details(self):
        if self.analysis_details:
            return json.loads(self.analysis_details)
        return {}

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=True)
    action = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    access_time = db.Column(db.DateTime, default=datetime.utcnow)
    is_anomaly = db.Column(db.Boolean, default=False)
    anomaly_score = db.Column(db.Float, default=0.0)
    additional_info = db.Column(db.Text, nullable=True)
    risk_level = db.Column(db.String(20), default='low')