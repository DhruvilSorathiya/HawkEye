#!/usr/bin/env python3
"""
Database Migration Script for HawkEye
Adds new columns and tables for password reset and scan ownership features.
"""

import sqlite3
import sys
import os

def migrate_database(db_path='hawkeye.db'):
    """Migrate the database to add new features."""
    
    if not os.path.exists(db_path):
        print(f"Error: Database file '{db_path}' not found!")
        print("Please make sure you're running this from the  directory.")
        return False
    
    print(f"Migrating database: {db_path}")
    print("-" * 50)
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check current schema
        print("\n1. Checking tbl_scan_instance columns...")
        cursor.execute("PRAGMA table_info(tbl_scan_instance)")
        cols = [r[1] for r in cursor.fetchall()]
        print(f"   Current columns: {', '.join(cols)}")
        
        # Add created_by_user_id column
        if 'created_by_user_id' not in cols:
            print("\n2. Adding created_by_user_id column...")
            cursor.execute("ALTER TABLE tbl_scan_instance ADD COLUMN created_by_user_id INTEGER REFERENCES tbl_users(id)")
            conn.commit()
            print("   ✓ created_by_user_id column added")
        else:
            print("\n2. created_by_user_id column already exists ✓")
        
        # Add created_by_admin_id column
        if 'created_by_admin_id' not in cols:
            print("\n3. Adding created_by_admin_id column...")
            cursor.execute("ALTER TABLE tbl_scan_instance ADD COLUMN created_by_admin_id INTEGER REFERENCES tbl_admins(id)")
            conn.commit()
            print("   ✓ created_by_admin_id column added")
        else:
            print("\n3. created_by_admin_id column already exists ✓")
        
        # Create indexes
        print("\n4. Creating indexes...")
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_instance_user ON tbl_scan_instance (created_by_user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_instance_admin ON tbl_scan_instance (created_by_admin_id)")
            conn.commit()
            print("   ✓ Indexes created")
        except sqlite3.Error as e:
            print(f"   Warning: Could not create indexes: {e}")
        
        # Check if password reset table exists
        print("\n5. Checking for tbl_password_reset_tokens table...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tbl_password_reset_tokens'")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            print("\n6. Creating tbl_password_reset_tokens table...")
            cursor.execute("""
                CREATE TABLE tbl_password_reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES tbl_users(id),
                    admin_id INTEGER REFERENCES tbl_admins(id),
                    token VARCHAR NOT NULL UNIQUE,
                    created_at INT NOT NULL,
                    expires_at INT NOT NULL,
                    used INT NOT NULL DEFAULT 0
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON tbl_password_reset_tokens (token)")
            conn.commit()
            print("   ✓ tbl_password_reset_tokens table created")
        else:
            print("\n6. tbl_password_reset_tokens table already exists ✓")
        
        # Verify changes
        print("\n7. Verifying changes...")
        cursor.execute("PRAGMA table_info(tbl_scan_instance)")
        cols = [r[1] for r in cursor.fetchall()]
        
        success = True
        if 'created_by_user_id' in cols:
            print("   ✓ created_by_user_id verified")
        else:
            print("   ✗ created_by_user_id missing!")
            success = False
        
        if 'created_by_admin_id' in cols:
            print("   ✓ created_by_admin_id verified")
        else:
            print("   ✗ created_by_admin_id missing!")
            success = False
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tbl_password_reset_tokens'")
        if cursor.fetchone():
            print("   ✓ tbl_password_reset_tokens verified")
        else:
            print("   ✗ tbl_password_reset_tokens missing!")
            success = False
        
        # Count existing scans
        cursor.execute("SELECT COUNT(*) FROM tbl_scan_instance")
        total_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM tbl_scan_instance WHERE created_by_user_id IS NULL AND created_by_admin_id IS NULL")
        orphaned_scans = cursor.fetchone()[0]
        
        print(f"\n8. Scan statistics:")
        print(f"   Total scans: {total_scans}")
        print(f"   Orphaned scans (no owner): {orphaned_scans}")
        
        if orphaned_scans > 0:
            print(f"\n   Note: {orphaned_scans} existing scans have no owner.")
            print("   These scans will only appear in the admin panel.")
            print("   You can assign them to users manually if needed.")
        
        conn.close()
        
        if success:
            print("\n" + "=" * 50)
            print("✓ Migration completed successfully!")
            print("=" * 50)
            print("\nYou can now restart your HawkEye application.")
            return True
        else:
            print("\n" + "=" * 50)
            print("✗ Migration completed with errors!")
            print("=" * 50)
            return False
            
    except sqlite3.Error as e:
        print(f"\n✗ Error during migration: {e}")
        return False
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("HawkEye Database Migration Script")
    print("=" * 50)
    
    # Check if custom database path provided
    db_path = 'hawkeye.db'
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    
    success = migrate_database(db_path)
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)
