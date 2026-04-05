from app import app, db
from sqlalchemy import text
import sqlite3

def migrate_database():
    """Add new columns to existing tables"""
    with app.app_context():
        # Get database connection
        conn = sqlite3.connect('privacy_protection.db')
        cursor = conn.cursor()
        
        # Check and add columns to File table
        try:
            cursor.execute("PRAGMA table_info(file)")
            columns = [column[1] for column in cursor.fetchall()]
            
            new_columns = {
                'classification': 'TEXT DEFAULT "normal"',
                'risk_score': 'REAL DEFAULT 0.0',
                'threat_count': 'INTEGER DEFAULT 0',
                'sensitive_count': 'INTEGER DEFAULT 0',
                'file_hash': 'TEXT',
                'file_type': 'TEXT',
                'quarantine_status': 'BOOLEAN DEFAULT 0',
                'analysis_details': 'TEXT'
            }
            
            for col, col_type in new_columns.items():
                if col not in columns:
                    cursor.execute(f"ALTER TABLE file ADD COLUMN {col} {col_type}")
                    print(f"Added column {col} to file table")
        except Exception as e:
            print(f"Error migrating file table: {e}")
        
        # Check and add columns to access_log table
        try:
            cursor.execute("PRAGMA table_info(access_log)")
            columns = [column[1] for column in cursor.fetchall()]
            
            new_columns = {
                'additional_info': 'TEXT',
                'risk_level': 'TEXT DEFAULT "low"',
                'session_id': 'TEXT',
                'location': 'TEXT',
                'device_type': 'TEXT'
            }
            
            for col, col_type in new_columns.items():
                if col not in columns:
                    cursor.execute(f"ALTER TABLE access_log ADD COLUMN {col} {col_type}")
                    print(f"Added column {col} to access_log table")
        except Exception as e:
            print(f"Error migrating access_log table: {e}")
        
        # Create new tables
        try:
            # Create ThreatIntelligence table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_type TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    description TEXT,
                    detected_count INTEGER DEFAULT 0,
                    last_detected DATETIME,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("Created threat_intelligence table")
            
            # Create AnomalyDetectionModel table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_detection_model (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_name TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    model_path TEXT,
                    accuracy REAL DEFAULT 0.0,
                    training_samples INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            """)
            print("Created anomaly_detection_model table")
            
            # Create SecurityEvent table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_event (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    user_id INTEGER,
                    file_id INTEGER,
                    ip_address TEXT,
                    event_data TEXT,
                    resolved BOOLEAN DEFAULT 0,
                    resolved_at DATETIME,
                    resolved_by INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES user(id),
                    FOREIGN KEY(file_id) REFERENCES file(id),
                    FOREIGN KEY(resolved_by) REFERENCES user(id)
                )
            """)
            print("Created security_event table")
            
            # Create DataBreachLog table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS data_breach_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    breach_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    user_id INTEGER,
                    file_id INTEGER,
                    affected_data TEXT,
                    breach_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    detected_by TEXT DEFAULT 'system',
                    mitigation_taken TEXT,
                    is_resolved BOOLEAN DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES user(id),
                    FOREIGN KEY(file_id) REFERENCES file(id)
                )
            """)
            print("Created data_breach_log table")
            
        except Exception as e:
            print(f"Error creating new tables: {e}")
        
        # Commit changes
        conn.commit()
        conn.close()
        
        print("Database migration completed successfully!")

if __name__ == '__main__':
    migrate_database()