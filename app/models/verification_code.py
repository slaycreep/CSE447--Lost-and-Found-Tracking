"""
Verification Code Model for Two-Step Authentication
Stores OTP codes for users during authentication
"""
from app import db
from datetime import datetime, timedelta


class VerificationCode(db.Model):
    """Stores one-time verification codes for two-step authentication"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    
    # OTP code hashed with salt (using PBKDF2 from scratch)
    code_hash = db.Column(db.String(256), nullable=False)
    code_salt = db.Column(db.String(256), nullable=False)
    
    # Plain text code stored ONLY in development for testing
    plain_code_dev = db.Column(db.String(6), nullable=True)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=db.func.now())
    expires_at = db.Column(db.DateTime, nullable=False)  # Code expires after X minutes
    
    # Verification tracking
    is_verified = db.Column(db.Boolean, default=False)
    attempts = db.Column(db.Integer, default=0)  # Track failed verification attempts
    max_attempts = 5  # Max failed attempts before blocking
    
    # Relationship
    user = db.relationship("User", backref="verification_codes", uselist=True)
    
    def is_expired(self):
        """Check if verification code has expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_max_attempts_exceeded(self):
        """Check if max verification attempts exceeded"""
        return self.attempts >= self.max_attempts
    
    def mark_verified(self):
        """Mark code as successfully verified"""
        self.is_verified = True
        db.session.commit()
    
    def increment_attempts(self):
        """Increment failed attempt counter"""
        self.attempts += 1
        db.session.commit()
    
    @staticmethod
    def create_for_user(user_id, expiry_minutes=10):
        """
        Create a new verification code for user
        Returns: (plain_code, verification_code_id)
        Plain code is sent to user, hashed version stored in DB
        """
        from app.services.data_encryption_service import DataEncryptionService
        import os
        import base64
        from flask import current_app
        
        # Generate 6-digit OTP using HMAC-based derivation
        random_bytes = os.urandom(16)
        
        # Use HMAC to derive deterministic bytes from random data
        from app.utils.encryption_algorithms import HMACIntegrity
        hmac_key = b'OTP-GENERATION-KEY'
        hmac_result = HMACIntegrity.create_mac(random_bytes, hmac_key)
        
        # Decode base64 result to get binary
        hmac_binary = base64.b64decode(hmac_result)
        
        # Convert first 4 bytes to integer and take modulo 10^6 for 6-digit number
        code_number = int.from_bytes(hmac_binary[:4], 'big') % 1000000
        plain_code = str(code_number).zfill(6)
        
        # Hash the code with salt before storing
        code_salt, code_hash = DataEncryptionService.hash_password(plain_code)
        
        # Calculate expiry time
        expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        
        # Create verification code record
        verification_code = VerificationCode(
            user_id=user_id,
            code_hash=code_hash,
            code_salt=code_salt,
            expires_at=expires_at,
            plain_code_dev=plain_code if current_app.debug else None  # Store only in dev mode
        )
        db.session.add(verification_code)
        db.session.commit()
        
        return plain_code, verification_code.id
    
    @staticmethod
    def get_pending_code(user_id):
        """Get active (non-expired, non-verified) verification code for user"""
        return VerificationCode.query.filter_by(
            user_id=user_id,
            is_verified=False
        ).filter(
            VerificationCode.expires_at > datetime.utcnow()
        ).first()
    
    @staticmethod
    def verify_code(verification_code_id, plain_code):
        """
        Verify a code against stored hash
        Returns: (success: bool, verification_code: VerificationCode or None)
        """
        from app.services.data_encryption_service import DataEncryptionService
        
        verification_code = VerificationCode.query.get(verification_code_id)
        
        if not verification_code:
            return False, None
        
        # Check if expired
        if verification_code.is_expired():
            return False, verification_code
        
        # Check if already verified
        if verification_code.is_verified:
            return False, verification_code
        
        # Check if max attempts exceeded
        if verification_code.is_max_attempts_exceeded():
            return False, verification_code
        
        # Verify code against hash
        if DataEncryptionService.verify_password(
            plain_code,
            verification_code.code_salt,
            verification_code.code_hash
        ):
            # Code matches!
            return True, verification_code
        else:
            # Code doesn't match - increment attempts
            verification_code.increment_attempts()
            return False, verification_code
