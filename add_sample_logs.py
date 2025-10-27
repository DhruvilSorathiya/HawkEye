"""
Add sample system logs to demonstrate the System Logs feature.
Run this script to populate the system logs with sample data.
"""

import sqlite3
import time
import os

# Get the database path
db_path = os.path.join(os.path.dirname(__file__), 'hawkeye.db')

if not os.path.exists(db_path):
    print(f"Database not found at {db_path}")
    print("Please run HawkEye first to create the database.")
    exit(1)

# Connect to database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check if system logs table exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tbl_system_logs'")
if not cursor.fetchone():
    print("System logs table doesn't exist yet.")
    print("Please access the admin dashboard and click on 'System Logs' first to create the table.")
    conn.close()
    exit(1)

# Sample logs to add
current_time = int(time.time())
sample_logs = [
    ('INFO', 'SYSTEM', 'HawkEye system started successfully', None, None, '127.0.0.1', 'System', None, current_time - 7200),
    ('INFO', 'DATABASE', 'Database connection established', None, None, None, None, None, current_time - 7100),
    ('INFO', 'SYSTEM_SETTINGS', 'System settings loaded from database', None, None, None, None, None, current_time - 7000),
    ('INFO', 'AUTH', 'Admin authentication module initialized', None, None, None, None, None, current_time - 6900),
    ('WARNING', 'SCAN', 'Scan queue is empty', None, None, None, None, None, current_time - 6800),
    ('INFO', 'SYSTEM', 'Web server listening on port 5002', None, None, '127.0.0.1', 'CherryPy/18.8.0', None, current_time - 6700),
    ('INFO', 'DATABASE', 'Database backup completed successfully', None, None, None, None, None, current_time - 3600),
    ('WARNING', 'SYSTEM', 'High memory usage detected: 85%', None, None, None, None, None, current_time - 3000),
    ('INFO', 'USER_MANAGEMENT', 'User session cleanup completed', None, None, None, None, None, current_time - 2400),
    ('ERROR', 'SCAN', 'Scan timeout for target: example.com', None, None, '192.168.1.100', None, '{"scan_id": "test-123", "timeout": 300}', current_time - 1800),
    ('INFO', 'SYSTEM_SETTINGS', 'Setting "max_scan_threads" updated to "15"', None, 1, '127.0.0.1', 'Mozilla/5.0', None, current_time - 1200),
    ('INFO', 'API', 'API rate limit check passed', None, None, '192.168.1.50', None, None, current_time - 900),
    ('WARNING', 'AUTH', 'Failed login attempt for user: testuser', None, None, '192.168.1.200', 'Mozilla/5.0', None, current_time - 600),
    ('INFO', 'SCAN', 'New scan initiated: Network Scan #42', None, 1, '127.0.0.1', 'Mozilla/5.0', '{"scan_type": "network", "target": "192.168.1.0/24"}', current_time - 300),
    ('CRITICAL', 'DATABASE', 'Database connection pool exhausted', None, None, None, None, None, current_time - 120),
    ('INFO', 'SYSTEM', 'Database connection pool recovered', None, None, None, None, None, current_time - 60),
    ('INFO', 'USER_MANAGEMENT', 'New user account created: john_doe', None, 1, '127.0.0.1', 'Mozilla/5.0', None, current_time - 30),
    ('INFO', 'SYSTEM', 'System logs feature accessed', None, 1, '127.0.0.1', 'Mozilla/5.0', None, current_time),
]

print(f"Adding {len(sample_logs)} sample log entries...")

try:
    cursor.executemany("""
        INSERT INTO tbl_system_logs 
        (log_level, log_category, log_message, user_id, admin_id, ip_address, user_agent, additional_data, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, sample_logs)
    
    conn.commit()
    print(f"✓ Successfully added {len(sample_logs)} sample log entries!")
    print("\nYou can now view these logs in the admin dashboard under 'System Logs'.")
    
except Exception as e:
    print(f"✗ Error adding sample logs: {e}")
    conn.rollback()

finally:
    conn.close()
