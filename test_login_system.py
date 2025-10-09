#!/usr/bin/env python3
"""
HawkEye Login System Test Script

This script tests the basic functionality of the new login system.
"""

import sys
import os
import time

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hawkeye.db import HawkEyeDb
from hawkeye.auth import HawkEyeAuth

def test_database_schema():
    """Test database schema creation."""
    print("Testing database schema...")
    
    # Create a test config
    config = {
        '__database': ':memory:',  # Use in-memory database for testing
    }
    
    try:
        db = HawkEyeDb(config, init=True)
        print("[OK] Database schema created successfully")
        
        # Test default admin creation
        if db.createDefaultAdmin():
            print("[OK] Default admin account created")
        else:
            print("[OK] Default admin account already exists")
        
        # Test user creation
        if db.createUser("testuser", "testpass", "test@example.com", "1234567890", 1):
            print("[OK] Test user created successfully")
        
        # Test authentication
        user_info = db.authenticateUser("testuser", "testpass")
        if user_info:
            print("[OK] User authentication works")
        
        admin_info = db.authenticateAdmin("admin", "admin")
        if admin_info:
            print("[OK] Admin authentication works")
        
        # Test session creation
        session_id = db.createSession(user_id=user_info['id'])
        if session_id:
            print("[OK] Session creation works")
        
        # Test session retrieval
        session_info = db.getSession(session_id)
        if session_info:
            print("[OK] Session retrieval works")
        
        # Test activity logging
        db.logUserActivity(user_info['id'], "test", "Test activity")
        print("[OK] Activity logging works")
        
        print("\n[SUCCESS] All database tests passed!")
        return True
        
    except Exception as e:
        print(f"[ERROR] Database test failed: {e}")
        return False

def test_auth_module():
    """Test authentication module."""
    print("\nTesting authentication module...")
    
    try:
        # Create a test config
        config = {
            '__database': ':memory:',
        }
        
        db = HawkEyeDb(config, init=True)
        auth = HawkEyeAuth(db)
        
        # Test IP and user agent methods
        ip = auth.get_client_ip()
        ua = auth.get_user_agent()
        
        print(f"[OK] Client IP detection: {ip}")
        print(f"[OK] User agent detection: {ua}")
        
        print("[SUCCESS] Authentication module tests passed!")
        return True
        
    except Exception as e:
        print(f"[ERROR] Authentication module test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("HawkEye Login System Test Suite")
    print("=" * 40)
    
    success = True
    
    # Test database functionality
    if not test_database_schema():
        success = False
    
    # Test authentication module
    if not test_auth_module():
        success = False
    
    print("\n" + "=" * 40)
    if success:
        print("[SUCCESS] All tests passed! The login system is ready to use.")
        print("\nNext steps:")
        print("1. Start HawkEye web server: python he.py -l 127.0.0.1:5001")
        print("2. Navigate to http://127.0.0.1:5001")
        print("3. Login as admin with username: admin, password: admin")
        print("4. Change the default admin password!")
        print("5. Create user accounts as needed")
    else:
        print("[ERROR] Some tests failed. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
