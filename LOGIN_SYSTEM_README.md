# HawkEye Login System

This document describes the new authentication system implemented in HawkEye.

## Features

### 1. Dual Login System
- **User Login**: For regular users to access scans and perform OSINT investigations
- **Admin Login**: For administrators to manage users and system settings

### 2. User Management
- Admins can create new user accounts with username, password, email, and mobile number
- User activity tracking and monitoring
- User status management (activate/deactivate)

### 3. Admin Management
- Admin-to-admin authentication for creating new admin accounts
- Default admin account: `admin` / `admin` (change after first login!)
- Admin dashboard with system overview and user management

### 4. Security Features
- Session-based authentication with 24-hour expiration
- Password hashing using SHA-256
- Activity logging for all user actions
- IP address tracking
- Secure logout functionality

### 5. User Interface
- Attractive, responsive login pages
- Modern gradient backgrounds and animations
- User-friendly error messages
- Forgot password functionality

## Database Schema

The system adds the following tables to the existing HawkEye database:

- `tbl_users`: User accounts
- `tbl_admins`: Admin accounts  
- `tbl_user_sessions`: Active user sessions
- `tbl_user_activity`: User activity logs

## Usage

### First Time Setup
1. Start HawkEye web server
2. Navigate to the application URL
3. You'll be redirected to the login selection page
4. Click "Admin Login"
5. Use credentials: `admin` / `admin`
6. **IMPORTANT**: Change the default admin password immediately!

### Creating Users
1. Login as admin
2. Go to Admin Dashboard
3. Click "Create User" button
4. Fill in user details (username, password, email, mobile)
5. User can now login with their credentials

### Creating Additional Admins
1. Login as existing admin
2. Go to Admin Dashboard
3. Click "Create New Admin"
4. Fill in admin details
5. New admin can login with their credentials

## Default Credentials

**Admin Account:**
- Username: `admin`
- Password: `admin`

**⚠️ SECURITY WARNING: Change the default admin password immediately after first login!**

## Routes

- `/login` - Login selection page
- `/login/user` - User login page
- `/login/admin` - Admin login page
- `/logout` - Logout handler
- `/admin` - Admin dashboard
- `/forgot-password` - Password reset page

## Security Considerations

1. **Change Default Password**: The default admin password must be changed immediately
2. **Strong Passwords**: Encourage users to use strong passwords
3. **Regular Monitoring**: Review user activity logs regularly
4. **Session Management**: Sessions expire after 24 hours for security
5. **IP Tracking**: All login attempts and activities are logged with IP addresses

## Integration

The login system is fully integrated with the existing HawkEye functionality:
- All scan operations require user authentication
- User activities are logged for admin monitoring
- Existing scan data remains accessible to authenticated users
- Admin panel provides comprehensive user management

## Technical Details

- **Authentication**: Session-based with SHA-256 password hashing
- **Session Storage**: Database-backed sessions with expiration
- **Activity Logging**: Comprehensive logging of all user actions
- **UI Framework**: Bootstrap-based responsive design
- **Backend**: CherryPy with Mako templates
- **Database**: SQLite with new authentication tables
