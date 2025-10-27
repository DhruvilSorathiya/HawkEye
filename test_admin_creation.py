"""
Test script to verify admin creation endpoint works correctly.
"""
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hawkeye import HawkEyeDb

def test_admin_creation():
    """Test the createAdmin method with all parameters."""
    print("Testing admin creation...")
    
    # Initialize database
    config = {
        '__database': 'hawkeye.test.db',
        '__modules__': {},
        '_debug': True
    }
    
    try:
        db = HawkEyeDb(config, init=True)
        print("[OK] Database initialized")
        
        # Create default admin if needed
        db.createDefaultAdmin()
        print("[OK] Default admin exists")
        
        # Test creating a new admin with mobile parameter
        result = db.createAdmin(
            username="testadmin",
            password="testpass123",
            email="testadmin@example.com",
            mobile="9876543210",
            created_by_admin_id=1
        )
        
        if result:
            print("[OK] Admin created successfully with mobile parameter")
            
            # Verify the admin was created
            with db.dbhLock:
                db.dbh.execute("SELECT username, email, mobile FROM tbl_admins WHERE username = ?", ("testadmin",))
                admin = db.dbh.fetchone()
                if admin:
                    print(f"[OK] Admin verified: username={admin[0]}, email={admin[1]}, mobile={admin[2]}")
                else:
                    print("[ERROR] Admin not found in database")
        else:
            print("[ERROR] Failed to create admin")
            
        # Clean up test admin
        with db.dbhLock:
            db.dbh.execute("DELETE FROM tbl_admins WHERE username = ?", ("testadmin",))
            db.conn.commit()
        print("[OK] Test admin cleaned up")
        
        print("\n✅ All tests passed!")
        return True
        
    except Exception as e:
        print(f"[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Clean up test database
        if os.path.exists('hawkeye.test.db'):
            os.remove('hawkeye.test.db')
            print("[OK] Test database removed")

if __name__ == "__main__":
    success = test_admin_creation()
    sys.exit(0 if success else 1)
