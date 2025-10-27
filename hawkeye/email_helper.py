"""
Email Helper Module for HawkEye
Handles sending password reset emails
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class EmailHelper:
    """Helper class for sending emails."""
    
    def __init__(self, smtp_host='smtp.gmail.com', smtp_port=587, smtp_user='', smtp_password='', from_email=''):
        """Initialize email helper.
        
        Args:
            smtp_host (str): SMTP server host
            smtp_port (int): SMTP server port
            smtp_user (str): SMTP username
            smtp_password (str): SMTP password
            from_email (str): From email address
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_email = from_email or smtp_user
        
    def send_password_reset_email(self, to_email, username, reset_link):
        """Send password reset email.
        
        Args:
            to_email (str): Recipient email address
            username (str): Username
            reset_link (str): Password reset link
            
        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'HawkEye - Password Reset Request'
            msg['From'] = self.from_email
            msg['To'] = to_email
            
            # Create HTML content
            html_content = f"""
            <html>
              <head></head>
              <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                  <h2 style="color: #667eea;">HawkEye Password Reset</h2>
                  <p>Hello <strong>{username}</strong>,</p>
                  <p>We received a request to reset your password. Click the button below to reset your password:</p>
                  <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Reset Password</a>
                  </div>
                  <p>Or copy and paste this link into your browser:</p>
                  <p style="background: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all;">
                    <a href="{reset_link}" style="color: #667eea;">{reset_link}</a>
                  </p>
                  <p style="color: #999; font-size: 0.9em; margin-top: 30px;">
                    <strong>Note:</strong> This link will expire in 1 hour. If you didn't request this password reset, please ignore this email.
                  </p>
                  <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                  <p style="color: #999; font-size: 0.85em; text-align: center;">
                    This is an automated message from HawkEye. Please do not reply to this email.
                  </p>
                </div>
              </body>
            </html>
            """
            
            # Create plain text version
            text_content = f"""
            HawkEye Password Reset
            
            Hello {username},
            
            We received a request to reset your password. Click the link below to reset your password:
            
            {reset_link}
            
            This link will expire in 1 hour. If you didn't request this password reset, please ignore this email.
            
            ---
            This is an automated message from HawkEye. Please do not reply to this email.
            """
            
            # Attach both versions
            part1 = MIMEText(text_content, 'plain')
            part2 = MIMEText(html_content, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            if not self.smtp_user or not self.smtp_password:
                return (False, "Email configuration not set. Please configure SMTP settings.")
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            return (True, "Email sent successfully")
            
        except smtplib.SMTPAuthenticationError:
            return (False, "SMTP authentication failed. Please check email credentials.")
        except smtplib.SMTPException as e:
            return (False, f"SMTP error: {str(e)}")
        except Exception as e:
            return (False, f"Error sending email: {str(e)}")
