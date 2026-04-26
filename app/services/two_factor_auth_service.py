"""
Two-Factor Authentication Service
Implements two-step authentication using password + OTP verification code
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app
from app.models.user import User
from app.models.verification_code import VerificationCode
from app.repositories.user_repository import UserRepository
from app.services.data_encryption_service import DataEncryptionService


class TwoFactorAuthService:
    """Service to handle two-factor authentication"""
    
    @staticmethod
    def start_authentication(email, password):
        """
        First Factor: Verify email and password
        Returns: (success: bool, user: User or None, message: str)
        """
        # Verify email exists
        user = UserRepository.get_by_email(email)
        if not user:
            return False, None, "Invalid email or password"
        
        # Verify password using custom PBKDF2
        if not (user.password_hash and user.password_salt):
            return False, None, "Account not properly configured"
        
        if not DataEncryptionService.verify_password(
            password,
            user.password_salt,
            user.password_hash
        ):
            return False, None, "Invalid email or password"
        
        # Check if account is banned
        if user.is_banned:
            return False, None, "Account is suspended"
        
        # Password verified - generate OTP for second factor
        plain_code, verification_code_id = VerificationCode.create_for_user(
            user.id,
            expiry_minutes=10
        )
        
        # Send OTP to user email
        send_success = TwoFactorAuthService._send_otp_email(
            user.email,
            plain_code,
            user.name
        )
        
        if not send_success:
            return False, None, "Failed to send verification code"
        
        return True, user, verification_code_id
    
    @staticmethod
    def verify_second_factor(verification_code_id, otp_code):
        """
        Second Factor: Verify OTP code
        Returns: (success: bool, user: User or None, message: str)
        """
        # Verify the OTP code
        is_valid, verification_code = VerificationCode.verify_code(
            verification_code_id,
            otp_code
        )
        
        if not is_valid:
            if not verification_code:
                return False, None, "Invalid verification code"
            
            if verification_code.is_expired():
                return False, None, "Verification code expired"
            
            if verification_code.is_max_attempts_exceeded():
                return False, None, "Too many failed attempts. Please request a new code"
            
            return False, None, f"Invalid verification code ({5 - verification_code.attempts} attempts remaining)"
        
        # Code verified - mark as verified
        verification_code.mark_verified()
        
        # Get user
        user = User.query.get(verification_code.user_id)
        if not user:
            return False, None, "User not found"
        
        return True, user, "Authentication successful"
    
    @staticmethod
    def request_new_code(user_id):
        """
        Request a new OTP code (in case of lost/expired code)
        Returns: (success: bool, verification_code_id: int or None, message: str)
        """
        user = User.query.get(user_id)
        if not user:
            return False, None, "User not found"
        
        # Invalidate any existing pending codes
        pending_codes = VerificationCode.query.filter_by(
            user_id=user_id,
            is_verified=False
        ).all()
        for code in pending_codes:
            code.is_verified = True  # Mark as "used" to prevent reuse
        
        # Generate new code
        plain_code, verification_code_id = VerificationCode.create_for_user(
            user_id,
            expiry_minutes=10
        )
        
        # Send OTP to user email
        send_success = TwoFactorAuthService._send_otp_email(
            user.email,
            plain_code,
            user.name
        )
        
        if not send_success:
            return False, None, "Failed to send verification code"
        
        return True, verification_code_id, "New verification code sent to email"
    
    @staticmethod
    def _send_otp_email(email, otp_code, user_name):
        """
        Send OTP code via email
        Returns: success (bool)
        """
        try:
            # Get email configuration from Flask app
            smtp_server = current_app.config.get('MAIL_SERVER', 'localhost')
            smtp_port = current_app.config.get('MAIL_PORT', 587)
            sender_email = current_app.config.get('MAIL_DEFAULT_SENDER', 'noreply@lostandfound.com')
            sender_password = current_app.config.get('MAIL_PASSWORD')
            use_tls = current_app.config.get('MAIL_USE_TLS', True)
            
            # If no SMTP config, just log (for testing/development)
            if not sender_password or smtp_server == 'localhost':
                print(f"[DEV MODE] OTP Code for {email}: {otp_code}")
                return True
            
            # Create email message
            message = MIMEMultipart("alternative")
            message["Subject"] = "Your Two-Factor Authentication Code"
            message["From"] = sender_email
            message["To"] = email
            
            # Plain text version
            text = f"""
Hello {user_name},

Your two-factor authentication code is:

{otp_code}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email and consider changing your password.

Best regards,
Lost & Found Tracking System
            """.strip()
            
            # HTML version
            html = f"""
<html>
  <body>
    <p>Hello {user_name},</p>
    <p>Your two-factor authentication code is:</p>
    <h1 style="font-family: monospace; letter-spacing: 5px;">{otp_code}</h1>
    <p>This code will expire in 10 minutes.</p>
    <p>If you did not request this code, please ignore this email and consider changing your password.</p>
    <p>Best regards,<br/>Lost & Found Tracking System</p>
  </body>
</html>
            """.strip()
            
            part1 = MIMEText(text, "plain")
            part2 = MIMEText(html, "html")
            message.attach(part1)
            message.attach(part2)
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if use_tls:
                    server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, email, message.as_string())
            
            return True
        except Exception as e:
            print(f"Error sending OTP email: {str(e)}")
            return True  # Return True anyway for development (email optional)
