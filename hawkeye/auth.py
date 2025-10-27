"""
HawkEye Authentication Module

This module handles user and admin authentication, session management,
and authorization for the HawkEye web application.
"""

import cherrypy
import time
from typing import Optional, Dict, Any


class HawkEyeAuth:
    """HawkEye Authentication handler."""
    
    def __init__(self, db_handler):
        """Initialize authentication handler.
        
        Args:
            db_handler: HawkEyeDb instance
        """
        self.db = db_handler
    
    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Get current logged-in user from session.
        
        Returns:
            dict: user info if logged in, None otherwise
        """
        session_id = cherrypy.session.get('session_id')
        if not session_id:
            return None
            
        session_info = self.db.getSession(session_id)
        if not session_info:
            return None
            
        if session_info['user_id']:
            # Get user info
            users = self.db.getAllUsers()
            for user in users:
                if user[0] == session_info['user_id']:
                    return {
                        'id': user[0],
                        'username': user[1],
                        'email': user[2],
                        'mobile': user[3],
                        'type': 'user'
                    }
        elif session_info['admin_id']:
            # Get admin info
            with self.db.dbhLock:
                try:
                    self.db.dbh.execute("SELECT id, username, email FROM tbl_admins WHERE id = ?", (session_info['admin_id'],))
                    result = self.db.dbh.fetchone()
                    if result:
                        return {
                            'id': result[0],
                            'username': result[1],
                            'email': result[2],
                            'type': 'admin'
                        }
                except Exception:
                    pass
                    
        return None
    
    def require_auth(self, user_type: str = None) -> bool:
        """Require authentication for a page.
        
        Args:
            user_type (str): 'user', 'admin', or None for any
            
        Returns:
            bool: True if authenticated, False otherwise
        """
        user = self.get_current_user()
        if not user:
            return False
            
        if user_type and user['type'] != user_type:
            return False
            
        return True
    
    def login_user(self, username: str, password: str, ip_address: str = None, user_agent: str = None) -> bool:
        """Login a user.
        
        Args:
            username (str): username
            password (str): password
            ip_address (str): IP address
            user_agent (str): user agent
            
        Returns:
            bool: True if login successful
        """
        user_info = self.db.authenticateUser(username, password)
        if not user_info:
            return False
            
        # Create session
        session_id = self.db.createSession(
            user_id=user_info['id'],
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Store session in CherryPy session
        cherrypy.session['session_id'] = session_id
        cherrypy.session['user_type'] = 'user'
        cherrypy.session['user_id'] = user_info['id']
        
        # Log activity
        self.db.logUserActivity(
            user_id=user_info['id'],
            activity_type='login',
            activity_description='User logged in',
            ip_address=ip_address
        )
        
        # Log to system logs
        self.db.logSystemEvent(
            'INFO',
            'AUTH',
            f'User "{username}" logged in successfully',
            user_id=user_info['id'],
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return True
    
    def login_admin(self, username: str, password: str, ip_address: str = None, user_agent: str = None, verify_only: bool = False) -> bool:
        """Login an admin.
        
        Args:
            username (str): username
            password (str): password
            ip_address (str): IP address
            user_agent (str): user agent
            verify_only (bool): if True, only verify credentials without creating session
            
        Returns:
            bool: True if login successful
        """
        admin_info = self.db.authenticateAdmin(username, password)
        if not admin_info:
            return False
        
        # If verify_only, just return True without creating session
        if verify_only:
            return True
            
        # Create session
        session_id = self.db.createSession(
            admin_id=admin_info['id'],
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Store session in CherryPy session
        cherrypy.session['session_id'] = session_id
        cherrypy.session['user_type'] = 'admin'
        cherrypy.session['admin_id'] = admin_info['id']
        
        # Log admin activity
        self.db.logUserActivity(
            admin_id=admin_info['id'],
            activity_type='login',
            activity_description='Admin logged in',
            ip_address=ip_address
        )
        
        # Log to system logs
        self.db.logSystemEvent(
            'INFO',
            'AUTH',
            f'Admin "{username}" logged in successfully',
            admin_id=admin_info['id'],
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return True
    
    def logout(self) -> bool:
        """Logout current user.
        
        Returns:
            bool: True if logout successful
        """
        session_id = cherrypy.session.get('session_id')
        if session_id:
            self.db.deleteSession(session_id)
            
        # Clear CherryPy session
        cherrypy.session.clear()
        
        return True
    
    def get_client_ip(self) -> str:
        """Get client IP address.
        
        Returns:
            str: IP address
        """
        # Try to get real IP from headers
        forwarded_for = cherrypy.request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
            
        real_ip = cherrypy.request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
            
        # Fallback to remote address
        return cherrypy.request.remote.ip
    
    def get_user_agent(self) -> str:
        """Get user agent string.
        
        Returns:
            str: user agent
        """
        return cherrypy.request.headers.get('User-Agent', '')
