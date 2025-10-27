"""
Database migration script to add indexes for scan logs optimization
This will significantly improve log page performance
"""

import sqlite3
import os
import sys

def add_log_indexes():
    """Add indexes to tbl_scan_log for better performance"""
    
    # Get database path
    db_path = "hawkeye.test.db"
    
    if not os.path.exists(db_path):
        print(f"Error: Database file '{db_path}' not found!")
        print("Please run this script from the HawkEye root directory.")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("Adding indexes to improve log page performance...")
        
        # Check if indexes already exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_scan_logs_type'")
        if cursor.fetchone():
            print("✓ Index 'idx_scan_logs_type' already exists")
        else:
            cursor.execute("CREATE INDEX idx_scan_logs_type ON tbl_scan_log (scan_instance_id, type)")
            print("✓ Created index 'idx_scan_logs_type'")
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_scan_logs_generated'")
        if cursor.fetchone():
            print("✓ Index 'idx_scan_logs_generated' already exists")
        else:
            cursor.execute("CREATE INDEX idx_scan_logs_generated ON tbl_scan_log (scan_instance_id, generated DESC)")
            print("✓ Created index 'idx_scan_logs_generated'")
        
        conn.commit()
        
        # Analyze the table to update statistics
        print("\nAnalyzing table to update query optimizer statistics...")
        cursor.execute("ANALYZE tbl_scan_log")
        conn.commit()
        
        # Show index info
        print("\nCurrent indexes on tbl_scan_log:")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='tbl_scan_log'")
        for row in cursor.fetchall():
            print(f"  - {row[0]}")
        
        conn.close()
        
        print("\n✓ Database optimization completed successfully!")
        print("\nPerformance improvements:")
        print("  - Faster log filtering by type (INFO, WARNING, ERROR, DEBUG)")
        print("  - Faster log sorting by date")
        print("  - Reduced query time for large log tables")
        print("\nYou can now restart the application to see the improvements.")
        
        return True
        
    except sqlite3.Error as e:
        print(f"✗ Database error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("HawkEye - Log Performance Optimization")
    print("=" * 60)
    print()
    
    success = add_log_indexes()
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)
