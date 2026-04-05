import re
import json
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
import numpy as np
from collections import defaultdict
import joblib
import os
import hashlib
import struct

class PrivacyMonitor:
    def __init__(self):
        self.sensitive_patterns = {
            'credit_card': {
                'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                'severity': 'critical',
                'description': 'Credit card number detected'
            },
            'ssn': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'severity': 'critical',
                'description': 'Social Security Number detected'
            },
            'email': {
                'pattern': r'\b[\w\.-]+@[\w\.-]+\.\w+\b',
                'severity': 'medium',
                'description': 'Email address detected'
            },
            'phone': {
                'pattern': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                'severity': 'medium',
                'description': 'Phone number detected'
            },
            'ip_address': {
                'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'severity': 'low',
                'description': 'IP address detected'
            },
            'password': {
                'pattern': r'(?i)(password|passwd|pwd)[=:]\s*\S+',
                'severity': 'critical',
                'description': 'Password in plain text detected'
            },
            'api_key': {
                'pattern': r'(?i)(api[_-]?key|apikey|secret)[=:]\s*\S+',
                'severity': 'critical',
                'description': 'API key detected'
            },
            'bank_account': {
                'pattern': r'\b\d{10,15}\b',
                'severity': 'critical',
                'description': 'Potential bank account number detected'
            },
            'medical_id': {
                'pattern': r'\b[A-Z]{2}\d{8,10}\b',
                'severity': 'high',
                'description': 'Medical ID number detected'
            },
            'passport': {
                'pattern': r'\b[A-Z]{1,2}\d{6,8}\b',
                'severity': 'high',
                'description': 'Passport number detected'
            },
            'drivers_license': {
                'pattern': r'\b[A-Z]{1,2}\d{6,8}\b',
                'severity': 'high',
                'description': 'Driver\'s license number detected'
            }
        }
        
        # File type detection using magic numbers (expanded)
        self.file_signatures = {
            'application/pdf': [b'%PDF'],
            'image/jpeg': [b'\xFF\xD8\xFF'],
            'image/png': [b'\x89PNG\r\n\x1A\n'],
            'image/gif': [b'GIF87a', b'GIF89a'],
            'image/bmp': [b'BM'],
            'image/webp': [b'RIFF', b'WEBP'],
            'application/zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
            'application/msword': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],  # OLE2 header
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [b'PK\x03\x04'],  # DOCX
            'application/vnd.ms-excel': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],  # XLS
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': [b'PK\x03\x04'],  # XLSX
            'application/vnd.ms-powerpoint': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],  # PPT
            'application/vnd.openxmlformats-officedocument.presentationml.presentation': [b'PK\x03\x04'],  # PPTX
            'text/plain': [],  # Default fallback
            'application/json': [b'{', b'['],
            'text/html': [b'<!DOCTYPE', b'<html', b'<HTML'],
            'text/xml': [b'<?xml'],
            'application/javascript': [b'function', b'var ', b'let ', b'const '],
            'application/x-python': [b'#!/usr/bin/env python', b'import ', b'def '],
            'application/x-java': [b'public class', b'import java'],
            'application/x-php': [b'<?php'],
            'application/x-shockwave-flash': [b'FWS', b'CWS'],
            'video/mp4': [b'ftypmp4', b'ftypisom'],
            'audio/mpeg': [b'ID3'],
            'application/x-executable': [b'MZ', b'ELF']
        }
        
        # File type risk levels
        self.file_type_risks = {
            'text/plain': 'medium',
            'application/pdf': 'high',
            'application/msword': 'high',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'high',
            'application/vnd.ms-excel': 'high',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'high',
            'application/vnd.ms-powerpoint': 'high',
            'image/jpeg': 'low',
            'image/png': 'low',
            'image/gif': 'low',
            'image/bmp': 'low',
            'image/webp': 'low',
            'application/zip': 'medium',
            'application/json': 'low',
            'text/html': 'medium',
            'application/javascript': 'high',
            'application/x-python': 'high',
            'application/x-java': 'high',
            'application/x-php': 'high',
            'application/x-executable': 'critical',
            'video/mp4': 'low',
            'audio/mpeg': 'low'
        }
        
        self.anomaly_detector = None
        self.training_data = []
        self.model_path = 'anomaly_model.joblib'
        self.threat_signatures = self._load_threat_signatures()
        self._load_or_create_model()
    
    def _detect_file_type(self, file_data):
        """Detect file type using magic numbers without imghdr"""
        if not file_data:
            return 'application/octet-stream'
        
        # Check known file signatures
        for mime_type, signatures in self.file_signatures.items():
            for signature in signatures:
                if file_data.startswith(signature):
                    return mime_type
        
        # Check for common image formats using their signatures (already covered above)
        # JPEG, PNG, GIF, BMP, WEBP are already covered in file_signatures
        
        # Check for text files by content
        try:
            # Try to decode as UTF-8 and check if it's mostly text
            sample = file_data[:1024].decode('utf-8', errors='ignore')
            # If more than 70% of characters are printable ASCII, treat as text
            printable_chars = sum(32 <= ord(c) < 127 or c in '\n\r\t' for c in sample)
            if len(sample) > 0 and printable_chars / len(sample) > 0.7:
                # Check for specific text-based formats
                if sample.strip().startswith('{') or sample.strip().startswith('['):
                    return 'application/json'
                elif sample.strip().startswith('<?xml'):
                    return 'text/xml'
                elif '<html' in sample.lower() or '<!DOCTYPE' in sample:
                    return 'text/html'
                else:
                    return 'text/plain'
        except:
            pass
        
        return 'application/octet-stream'
    
    def _load_threat_signatures(self):
        """Load threat signatures for malware/virus detection"""
        return {
            'suspicious_scripts': [
                (r'eval\s*\(', 'JavaScript eval() usage'),
                (r'exec\s*\(', 'Command execution'),
                (r'system\s*\(', 'System command execution'),
                (r'base64_decode', 'Base64 decoding'),
                (r'cmd\.exe', 'Windows command prompt'),
                (r'powershell', 'PowerShell script'),
                (r'rm\s+-rf', 'Dangerous file removal'),
                (r'drop\s+table', 'SQL injection'),
                (r'UNION\s+SELECT', 'SQL injection'),
                (r'<script>', 'JavaScript injection'),
                (r'onclick=', 'Inline JavaScript'),
                (r'onload=', 'Inline JavaScript'),
                (r'<?php', 'PHP code detected'),
                (r'<%', 'ASP/JSP code detected'),
                (r'Runtime\.exec', 'Java runtime execution'),
                (r'ProcessBuilder', 'Java process execution'),
                (r'os\.system', 'Python system call'),
                (r'subprocess\.', 'Python subprocess call'),
                (r'CreateObject', 'ActiveX object creation'),
                (r'WScript\.Shell', 'Windows Script Host')
            ],
            'suspicious_strings': [
                'malware', 'virus', 'trojan', 'ransomware',
                'cryptominer', 'keylogger', 'backdoor',
                'exploit', 'payload', 'shellcode',
                'rootkit', 'worm', 'spyware', 'adware'
            ],
            'suspicious_headers': [
                (b'%PDF-1.', b'PDF with potential exploits'),
                (b'PK\x03\x04', b'Archive with potential malicious content')
            ]
        }
    
    def _load_or_create_model(self):
        """Load existing anomaly detection model or create new one"""
        if os.path.exists(self.model_path):
            try:
                self.anomaly_detector = joblib.load(self.model_path)
            except:
                self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        else:
            self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
    
    def analyze_file_content(self, file_data, filename):
        """Comprehensive file analysis during upload"""
        try:
            # Detect file type
            file_type = self._detect_file_type(file_data)
            
            # Initialize results
            analysis = {
                'filename': filename,
                'file_type': file_type,
                'file_size': len(file_data),
                'is_abnormal': False,
                'threats_detected': [],
                'sensitive_data': [],
                'risk_score': 0.0,
                'risk_level': 'low',
                'recommendations': [],
                'classification': 'normal'  # normal, suspicious, malicious, sensitive
            }
            
            # 1. Check for malware/virus signatures
            threat_analysis = self._check_for_threats(file_data)
            if threat_analysis['has_threats']:
                analysis['is_abnormal'] = True
                if len(threat_analysis['threats']) > 3:
                    analysis['classification'] = 'malicious'
                else:
                    analysis['classification'] = 'suspicious'
                analysis['threats_detected'].extend(threat_analysis['threats'])
                analysis['risk_score'] += min(0.5 + (len(threat_analysis['threats']) * 0.1), 1.0)
            
            # 2. Check for sensitive data (only for text-based files)
            if 'text' in file_type or 'pdf' in file_type or 'document' in file_type or 'xml' in file_type or 'json' in file_type:
                try:
                    # Try to decode as text
                    if 'text' in file_type or 'json' in file_type or 'xml' in file_type:
                        content = file_data.decode('utf-8', errors='ignore')
                    else:
                        # For binary files, try to extract readable text
                        content = self._extract_text_from_binary(file_data)
                    
                    sensitive_analysis = self.detect_sensitive_data(content)
                    if sensitive_analysis['has_sensitive_data']:
                        analysis['is_abnormal'] = True
                        if analysis['classification'] == 'normal':
                            analysis['classification'] = 'sensitive'
                        analysis['sensitive_data'].extend(sensitive_analysis['findings'])
                        analysis['risk_score'] += sensitive_analysis['sensitivity_score'] * 0.4
                except Exception as e:
                    pass
            
            # 3. Check file size anomalies
            if len(file_data) > 50 * 1024 * 1024:  # >50MB
                analysis['is_abnormal'] = True
                analysis['threats_detected'].append({
                    'type': 'large_file',
                    'severity': 'medium',
                    'description': f'Unusually large file size: {len(file_data) / (1024*1024):.1f}MB'
                })
                analysis['risk_score'] += 0.2
            
            # 4. Check for executable content
            if self._is_executable_content(file_data, file_type):
                analysis['is_abnormal'] = True
                analysis['classification'] = 'malicious'
                analysis['threats_detected'].append({
                    'type': 'executable_content',
                    'severity': 'high',
                    'description': 'Executable code detected in non-executable file'
                })
                analysis['risk_score'] += 0.4
            
            # 5. Check for suspicious file extensions
            suspicious_extensions = ['.exe', '.bat', '.sh', '.ps1', '.vbs', '.js', '.jar', '.msi', '.scr', '.com', '.dll']
            if any(filename.lower().endswith(ext) for ext in suspicious_extensions):
                analysis['is_abnormal'] = True
                analysis['classification'] = 'malicious'
                analysis['threats_detected'].append({
                    'type': 'suspicious_extension',
                    'severity': 'high',
                    'description': f'Executable file extension: {os.path.splitext(filename)[1]}'
                })
                analysis['risk_score'] += 0.3
            
            # 6. Check for double extensions (e.g., .pdf.exe)
            if filename.count('.') > 1:
                analysis['is_abnormal'] = True
                analysis['threats_detected'].append({
                    'type': 'double_extension',
                    'severity': 'high',
                    'description': 'File has multiple extensions (potential malware hiding)'
                })
                analysis['risk_score'] += 0.25
            
            # 7. Calculate final risk level
            analysis['risk_score'] = min(analysis['risk_score'], 1.0)
            analysis['risk_level'] = self._calculate_risk_level(analysis['risk_score'])
            
            # 8. Generate recommendations
            analysis['recommendations'] = self._generate_recommendations(analysis)
            
            return analysis
            
        except Exception as e:
            return {
                'is_abnormal': True,
                'classification': 'error',
                'error': str(e),
                'risk_level': 'high',
                'risk_score': 0.5,
                'filename': filename,
                'file_size': len(file_data) if file_data else 0
            }
    
    def _check_for_threats(self, file_data):
        """Check for known threat patterns"""
        threats = []
        has_threats = False
        
        # Convert to string for regex matching
        try:
            file_str = file_data.decode('utf-8', errors='ignore')
            
            for pattern, description in self.threat_signatures['suspicious_scripts']:
                matches = re.finditer(pattern, file_str, re.IGNORECASE)
                for match in matches:
                    threats.append({
                        'type': 'suspicious_script',
                        'severity': 'high',
                        'description': f'{description} detected: {pattern}',
                        'position': match.span()
                    })
                    has_threats = True
                    
            # Check for suspicious strings
            for suspicious in self.threat_signatures['suspicious_strings']:
                if suspicious in file_str.lower():
                    threats.append({
                        'type': 'suspicious_keyword',
                        'severity': 'medium',
                        'description': f'Suspicious keyword found: {suspicious}'
                    })
                    has_threats = True
                    
        except:
            pass
        
        # Check for suspicious file headers
        for header, description in self.threat_signatures['suspicious_headers']:
            if file_data.startswith(header):
                # PDF with JavaScript is suspicious
                if header == b'%PDF-1.' and b'/JavaScript' in file_data:
                    threats.append({
                        'type': 'pdf_javascript',
                        'severity': 'high',
                        'description': 'PDF contains JavaScript (potential malware)'
                    })
                    has_threats = True
        
        return {'has_threats': has_threats, 'threats': threats}
    
    def _extract_text_from_binary(self, file_data):
        """Extract readable text from binary files"""
        # Extract strings that look like text
        text = ''
        current_string = ''
        
        for byte in file_data[:10000]:  # Limit to first 10KB
            if 32 <= byte <= 126 or byte in [9, 10, 13]:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) > 3:
                    text += current_string + '\n'
                current_string = ''
        
        return text
    
    def _is_executable_content(self, file_data, file_type):
        """Check if file contains executable content"""
        # Check for executable patterns
        executable_patterns = [
            b'#!/usr/bin/env',
            b'#!/bin/',
            b'<script>',
            b'%!PS',
            b'#!',
            b'MZ',  # Windows executable
            b'ELF',  # Linux executable
            b'PE\0\0'  # Portable Executable
        ]
        
        for pattern in executable_patterns:
            if pattern in file_data[:1024]:
                return True
        
        return False
    
    def detect_sensitive_data(self, content):
        """Detect sensitive information in file content"""
        findings = []
        
        for data_type, info in self.sensitive_patterns.items():
            matches = re.finditer(info['pattern'], content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': data_type,
                    'value': self._mask_sensitive_value(data_type, match.group()),
                    'position': match.span(),
                    'severity': info['severity'],
                    'description': info['description']
                })
        
        # Calculate sensitivity score (cap at 1.0)
        sensitivity_score = min(len(findings) / len(self.sensitive_patterns), 1.0)
        
        return {
            'has_sensitive_data': len(findings) > 0,
            'findings': findings,
            'sensitivity_score': sensitivity_score,
            'privacy_level': self._determine_privacy_level(sensitivity_score)
        }
    
    def _mask_sensitive_value(self, data_type, value):
        """Mask sensitive values for display"""
        if data_type == 'credit_card':
            return f"****-****-****-{value[-4:]}"
        elif data_type == 'ssn':
            return f"***-**-{value[-4:]}"
        elif data_type == 'email':
            parts = value.split('@')
            if len(parts) == 2:
                return f"{parts[0][:2]}***@{parts[1]}"
            return value
        elif data_type == 'phone':
            return f"***-***-{value[-4:]}"
        elif data_type in ['passport', 'drivers_license']:
            return f"{value[:2]}*****{value[-2:]}"
        else:
            return f"{value[:10]}..." if len(value) > 10 else value
    
    def _determine_privacy_level(self, score):
        """Determine privacy level based on sensitivity score"""
        if score < 0.3:
            return 'low'
        elif score < 0.7:
            return 'medium'
        else:
            return 'high'
    
    def _calculate_risk_level(self, score):
        """Calculate risk level from score"""
        if score < 0.2:
            return 'low'
        elif score < 0.5:
            return 'medium'
        elif score < 0.7:
            return 'high'
        else:
            return 'critical'
    
    def _generate_recommendations(self, analysis):
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if analysis['classification'] == 'malicious':
            recommendations.append("⚠️ MALICIOUS FILE DETECTED: Do not open this file. Contact security team immediately.")
            recommendations.append("File has been quarantined and access restricted.")
            recommendations.append("Run antivirus scan immediately.")
        
        if analysis['classification'] == 'suspicious':
            recommendations.append("⚠️ Suspicious patterns detected. Exercise caution when accessing this file.")
            recommendations.append("Consider scanning with antivirus software before opening.")
            recommendations.append("Monitor access logs for this file.")
        
        if analysis['classification'] == 'sensitive':
            recommendations.append("🔒 Sensitive data detected. File has been encrypted with highest security level.")
            recommendations.append("Limit access to authorized personnel only.")
            recommendations.append("Enable audit logging for this file.")
            recommendations.append("Consider redacting sensitive information if sharing externally.")
        
        if analysis['risk_score'] > 0.5:
            recommendations.append(f"High risk file detected (score: {analysis['risk_score']:.1%}). Consider additional verification.")
        
        if len(analysis.get('sensitive_data', [])) > 5:
            recommendations.append("Multiple sensitive data instances detected. Review file content for data leakage.")
        
        if len(analysis.get('threats_detected', [])) > 0:
            recommendations.append(f"Found {len(analysis['threats_detected'])} potential threats. Run security scan.")
        
        if not recommendations:
            recommendations.append("✅ File appears safe. Standard security measures are sufficient.")
            recommendations.append("Regular backups recommended.")
        
        return recommendations
    
    def analyze_access_patterns(self, access_logs):
        """Analyze user access patterns for anomalies using ML"""
        if len(access_logs) < 10:
            return {'is_anomaly': False, 'reason': 'Insufficient data', 'confidence': 0.0}
        
        # Extract features for anomaly detection
        features = []
        for log in access_logs:
            features.append([
                float(log.user_id),
                float(log.file_id) if log.file_id else 0,
                datetime.timestamp(log.access_time) if hasattr(log.access_time, 'timestamp') else 0,
                1.0 if log.action == 'download' else 0.0,
                1.0 if log.action == 'view' else 0.0,
                1.0 if log.action == 'upload' else 0.0,
                1.0 if log.action == 'delete' else 0.0
            ])
        
        features = np.array(features)
        
        if len(features) < 5:
            return {'is_anomaly': False, 'reason': 'Insufficient features', 'confidence': 0.0}
        
        try:
            # Train or update model
            if len(self.training_data) > 0 and isinstance(self.training_data, np.ndarray):
                self.training_data = np.vstack([self.training_data, features])
            else:
                self.training_data = features
            
            if len(self.training_data) >= 10:
                self.anomaly_detector.fit(self.training_data)
                joblib.dump(self.anomaly_detector, self.model_path)
                
                # Predict anomalies
                predictions = self.anomaly_detector.predict(features)
                anomaly_scores = self.anomaly_detector.score_samples(features)
                
                return {
                    'is_anomaly': bool(predictions[-1] == -1),
                    'anomaly_score': float(anomaly_scores[-1]),
                    'confidence': abs(float(anomaly_scores[-1])),
                    'predictions': predictions.tolist(),
                    'reason': 'ML-based anomaly detection'
                }
        except Exception as e:
            return {'is_anomaly': False, 'reason': str(e), 'confidence': 0.0}
        
        return {'is_anomaly': False, 'reason': 'Model not trained', 'confidence': 0.0}
    
    def monitor_data_breaches(self, file_access_history, current_access):
        """Monitor for potential data breaches"""
        alerts = []
        
        # Check for unusual access times
        if file_access_history:
            access_times = [log.access_time.hour for log in file_access_history if hasattr(log.access_time, 'hour')]
            if access_times:
                avg_access_time = np.mean(access_times)
                current_hour = current_access.access_time.hour if hasattr(current_access.access_time, 'hour') else 0
                
                if abs(current_hour - avg_access_time) > 6:
                    alerts.append({
                        'type': 'unusual_access_time',
                        'severity': 'medium',
                        'description': f'Access at unusual hour: {current_hour} (normal: {avg_access_time:.0f})'
                    })
        
        # Check for rapid successive accesses
        if len(file_access_history) >= 5:
            recent_accesses = sorted(file_access_history[-10:], key=lambda x: x.access_time)
            time_diffs = []
            for i in range(len(recent_accesses)-1):
                diff = (recent_accesses[i+1].access_time - recent_accesses[i].access_time).total_seconds()
                time_diffs.append(diff)
            
            if time_diffs and np.mean(time_diffs) < 60:
                alerts.append({
                    'type': 'rapid_access',
                    'severity': 'high',
                    'description': f'Rapid successive file accesses detected (avg {np.mean(time_diffs):.0f} seconds)'
                })
        
        # Check for access from different IPs
        if len(file_access_history) >= 5:
            unique_ips = set(log.ip_address for log in file_access_history[-20:] if log.ip_address)
            if len(unique_ips) > 3:
                alerts.append({
                    'type': 'multiple_ip_access',
                    'severity': 'medium',
                    'description': f'Access from {len(unique_ips)} different IP addresses'
                })
        
        return alerts
    
    def generate_privacy_report(self, user, files, access_logs):
        """Generate comprehensive privacy report"""
        report = {
            'user_id': user.id,
            'username': user.username,
            'generated_at': datetime.utcnow().isoformat(),
            'summary': {},
            'files_analysis': [],
            'access_analysis': {},
            'recommendations': []
        }
        
        # Analyze files
        sensitive_files = 0
        malicious_files = 0
        high_risk_files = 0
        total_files = len(files)
        total_risk_score = 0
        
        for file in files:
            # Get file attributes safely
            sensitivity_score = float(file.sensitivity_score) if hasattr(file, 'sensitivity_score') and file.sensitivity_score else 0.0
            privacy_level = file.privacy_level if hasattr(file, 'privacy_level') else 'low'
            classification = getattr(file, 'classification', 'normal')
            risk_score = getattr(file, 'risk_score', 0.0)
            threat_count = getattr(file, 'threat_count', 0)
            sensitive_count = getattr(file, 'sensitive_count', 0)
            
            file_info = {
                'id': file.id,
                'filename': file.filename,
                'sensitivity_score': sensitivity_score,
                'privacy_level': privacy_level,
                'classification': classification,
                'risk_score': risk_score,
                'file_size': file.file_size,
                'threat_count': threat_count,
                'sensitive_count': sensitive_count,
                'uploaded_at': file.uploaded_at.isoformat() if file.uploaded_at else None
            }
            report['files_analysis'].append(file_info)
            
            # Count different file types
            if sensitivity_score > 0.5:
                sensitive_files += 1
            if classification == 'malicious':
                malicious_files += 1
            if risk_score > 0.7:
                high_risk_files += 1
            
            total_risk_score += risk_score
        
        # Analyze access patterns
        total_accesses = len(access_logs)
        unique_files_accessed = 0
        if access_logs:
            unique_files_accessed = len(set(log.file_id for log in access_logs if log.file_id))
        
        # Get recent anomalies
        recent_anomalies = []
        for log in access_logs[-20:]:
            if hasattr(log, 'is_anomaly') and log.is_anomaly:
                recent_anomalies.append({
                    'file_id': log.file_id,
                    'action': log.action,
                    'time': log.access_time.isoformat() if log.access_time else None,
                    'anomaly_score': float(log.anomaly_score) if hasattr(log, 'anomaly_score') and log.anomaly_score else 0.0
                })
        
        # Get action counts
        action_counts = {}
        for log in access_logs:
            action = log.action
            action_counts[action] = action_counts.get(action, 0) + 1
        
        report['access_analysis'] = {
            'total_accesses': total_accesses,
            'unique_files_accessed': unique_files_accessed,
            'anomalies_detected': len(recent_anomalies),
            'action_counts': action_counts,
            'recent_anomalies': recent_anomalies
        }
        
        # Generate summary
        avg_risk_score = total_risk_score / total_files if total_files > 0 else 0
        
        report['summary'] = {
            'total_files': total_files,
            'sensitive_files': sensitive_files,
            'malicious_files': malicious_files,
            'high_risk_files': high_risk_files,
            'sensitive_percentage': (sensitive_files / total_files * 100) if total_files > 0 else 0,
            'total_accesses': total_accesses,
            'anomalies_detected': len(recent_anomalies),
            'total_actions': sum(action_counts.values()),
            'average_risk_score': avg_risk_score
        }
        
        # Generate recommendations based on analysis
        recommendations = []
        
        # File-based recommendations
        if total_files > 0:
            if sensitive_files / total_files > 0.5:
                recommendations.append(
                    f"⚠️ High percentage of sensitive files detected ({sensitive_files}/{total_files}). "
                    "Consider implementing additional encryption and access controls."
                )
            
            if malicious_files > 0:
                recommendations.append(
                    f"🚨 {malicious_files} malicious file(s) detected! "
                    "Immediately quarantine and investigate these files."
                )
            
            if high_risk_files > 0:
                recommendations.append(
                    f"⚠️ {high_risk_files} high-risk file(s) found. "
                    "Review these files and consider additional security measures."
                )
            
            # Check for large files
            large_files = [f for f in files if f.file_size > 10 * 1024 * 1024]  # >10MB
            if len(large_files) > 10:
                recommendations.append(
                    f"Large number of large files detected ({len(large_files)}). "
                    "Consider archiving or compressing old files."
                )
        
        # Access-based recommendations
        if total_accesses > 0:
            # Check for unusual access patterns
            if action_counts.get('download', 0) > action_counts.get('view', 0) * 2:
                recommendations.append(
                    "Unusual number of downloads compared to views. "
                    "Monitor for potential data exfiltration."
                )
            
            if len(recent_anomalies) > 5:
                recommendations.append(
                    f"High number of anomalies detected ({len(recent_anomalies)}). "
                    "Review access logs for potential security incidents."
                )
            
            # Check for many deletions
            if action_counts.get('delete', 0) > 10:
                recommendations.append(
                    f"Many file deletions detected ({action_counts.get('delete', 0)}). "
                    "Verify if these deletions are authorized."
                )
        
        # General recommendations
        if total_files > 0 and total_accesses < 5:
            recommendations.append(
                "Low file access rate. Consider reviewing file retention policies."
            )
        
        if avg_risk_score > 0.5:
            recommendations.append(
                f"High average risk score ({avg_risk_score:.1%}). "
                "Review all high-risk files and implement additional security measures."
            )
        
        if not recommendations:
            recommendations.append(
                "✅ No immediate security concerns detected. "
                "Continue regular monitoring and maintain current security practices."
            )
        
        report['recommendations'] = recommendations
        
        return report
    
    def generate_security_metrics(self, files, access_logs):
        """Generate security metrics for dashboard"""
        metrics = {
            'total_files': len(files),
            'total_accesses': len(access_logs),
            'sensitive_files': 0,
            'malicious_files': 0,
            'anomalies': 0,
            'average_risk_score': 0.0,
            'total_threats': 0,
            'total_sensitive_instances': 0
        }
        
        total_risk = 0
        for file in files:
            if hasattr(file, 'sensitivity_score') and file.sensitivity_score:
                if file.sensitivity_score > 0.5:
                    metrics['sensitive_files'] += 1
                total_risk += file.sensitivity_score
            
            if hasattr(file, 'classification') and file.classification == 'malicious':
                metrics['malicious_files'] += 1
            
            if hasattr(file, 'threat_count') and file.threat_count:
                metrics['total_threats'] += file.threat_count
            
            if hasattr(file, 'sensitive_count') and file.sensitive_count:
                metrics['total_sensitive_instances'] += file.sensitive_count
        
        for log in access_logs:
            if hasattr(log, 'is_anomaly') and log.is_anomaly:
                metrics['anomalies'] += 1
        
        if files:
            metrics['average_risk_score'] = total_risk / len(files)
        
        return metrics
    
    def get_file_risk_summary(self, file):
        """Get risk summary for a single file"""
        summary = {
            'filename': file.filename,
            'risk_level': 'low',
            'risk_score': 0.0,
            'issues': []
        }
        
        if hasattr(file, 'sensitivity_score') and file.sensitivity_score:
            summary['risk_score'] = file.sensitivity_score
            if file.sensitivity_score > 0.7:
                summary['risk_level'] = 'critical'
            elif file.sensitivity_score > 0.3:
                summary['risk_level'] = 'medium'
        
        if hasattr(file, 'classification') and file.classification == 'malicious':
            summary['risk_level'] = 'critical'
            summary['issues'].append('Malicious file detected')
        elif hasattr(file, 'classification') and file.classification == 'suspicious':
            summary['risk_level'] = 'high'
            summary['issues'].append('Suspicious patterns detected')
        
        if hasattr(file, 'threat_count') and file.threat_count and file.threat_count > 0:
            summary['issues'].append(f'{file.threat_count} threat(s) detected')
        
        if hasattr(file, 'sensitive_count') and file.sensitive_count and file.sensitive_count > 0:
            summary['issues'].append(f'{file.sensitive_count} sensitive data instance(s) found')
        
        if not summary['issues']:
            summary['issues'].append('No immediate security concerns')
        
        return summary