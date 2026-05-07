"""
Session Security Service - Requirement 12
Handles secure session management, CSRF protection, and rate limiting
"""

import os
import secrets
import time
from datetime import datetime, timedelta
from flask import session, request

class SessionSecurityService:
    """Service for managing secure sessions"""
    
    # Session timeout: TEMPORARILY 10 MINUTES FOR TESTING (normally 30 minutes)
    SESSION_TIMEOUT = 10 * 60  # 10 minutes for testing
    
    # Failed login attempt tracking
    FAILED_LOGIN_ATTEMPTS = {}  # Format: {ip_address: [(timestamp, count)]}
    MAX_FAILED_ATTEMPTS = 5  # Max attempts before lockout
    LOCKOUT_DURATION = 15 * 60  # 15 minute lockout
    
    @staticmethod
    def generate_csrf_token():
        """Generate a CSRF token for form protection"""
        token = secrets.token_hex(32)  # 64-character token
        session['csrf_token'] = token
        session.modified = True  # Ensure session is saved to browser
        return token
    
    @staticmethod
    def get_csrf_token():
        """Get the current CSRF token from session"""
        if 'csrf_token' not in session:
            return SessionSecurityService.generate_csrf_token()
        return session['csrf_token']
    
    @staticmethod
    def validate_csrf_token(token):
        """Validate CSRF token from form submission"""
        stored_token = session.get('csrf_token')
        if not stored_token or not token:
            return False
        return secrets.compare_digest(stored_token, token)
    
    @staticmethod
    def init_session(user_id, user_email, user_name=None, is_admin=False):
        """Initialize secure session after successful login"""
        # Regenerate session ID (prevent session fixation)
        old_session = dict(session)
        session.clear()
        
        # Set new session data
        session['user_id'] = user_id
        session['user_email'] = user_email
        session['user_name'] = user_name or ""
        session['is_admin'] = is_admin
        session['login_time'] = time.time()
        session['last_activity'] = time.time()
        
        # Generate new CSRF token
        SessionSecurityService.generate_csrf_token()
        
        return True
    
    @staticmethod
    def check_session_timeout():
        """Check if session has timed out due to inactivity"""
        if 'user_id' not in session:
            return False  # No active session
        
        last_activity = session.get('last_activity', time.time())
        current_time = time.time()
        
        if current_time - last_activity > SessionSecurityService.SESSION_TIMEOUT:
            session.clear()
            session.modified = True
            return True  # Session timed out
        
        # Update last activity time
        session['last_activity'] = current_time
        session.modified = True
        return False
    
    @staticmethod
    def track_failed_login(email):
        """Track failed login attempts for rate limiting"""
        ip_address = request.remote_addr
        current_time = time.time()
        
        if ip_address not in SessionSecurityService.FAILED_LOGIN_ATTEMPTS:
            SessionSecurityService.FAILED_LOGIN_ATTEMPTS[ip_address] = []
        
        # Clean up old attempts (older than lockout duration)
        attempts = SessionSecurityService.FAILED_LOGIN_ATTEMPTS[ip_address]
        attempts = [(ts, count) for ts, count in attempts if current_time - ts < SessionSecurityService.LOCKOUT_DURATION]
        
        # Add current failed attempt
        attempts.append((current_time, 1))
        SessionSecurityService.FAILED_LOGIN_ATTEMPTS[ip_address] = attempts
        
        return len(attempts)
    
    @staticmethod
    def clear_failed_login(email):
        """Clear failed login attempts after successful login"""
        ip_address = request.remote_addr
        if ip_address in SessionSecurityService.FAILED_LOGIN_ATTEMPTS:
            del SessionSecurityService.FAILED_LOGIN_ATTEMPTS[ip_address]
    
    @staticmethod
    def is_login_locked(email):
        """Check if IP is locked out due to too many failed attempts"""
        ip_address = request.remote_addr
        current_time = time.time()
        
        if ip_address not in SessionSecurityService.FAILED_LOGIN_ATTEMPTS:
            return False
        
        attempts = SessionSecurityService.FAILED_LOGIN_ATTEMPTS[ip_address]
        
        # Count attempts within lockout window
        recent_attempts = [ts for ts, _ in attempts if current_time - ts < SessionSecurityService.LOCKOUT_DURATION]
        
        return len(recent_attempts) >= SessionSecurityService.MAX_FAILED_ATTEMPTS
    
    @staticmethod
    def get_lockout_time_remaining(email):
        """Get remaining lockout time in seconds"""
        ip_address = request.remote_addr
        current_time = time.time()
        
        if ip_address not in SessionSecurityService.FAILED_LOGIN_ATTEMPTS:
            return 0
        
        attempts = SessionSecurityService.FAILED_LOGIN_ATTEMPTS[ip_address]
        
        if not attempts:
            return 0
        
        oldest_attempt = min(ts for ts, _ in attempts)
        remaining = SessionSecurityService.LOCKOUT_DURATION - (current_time - oldest_attempt)
        
        return max(0, int(remaining))
    
    @staticmethod
    def destroy_session():
        """Destroy session on logout"""
        # Save any pending flash messages before clearing
        flashes = session.pop('_flashes', None)
        
        # Clear entire session - removes all user data
        session.clear()
        
        # Restore flash messages so the goodbye message displays
        if flashes:
            session['_flashes'] = flashes
        
        # Mark session as modified to ensure Flask updates the cookie
        session.modified = True
        return True
