from app import db
from app.models.user_report import UserReport

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # Legacy fields (kept for compatibility, some will be deprecated)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)  # No longer unique - encrypted version is unique
    password = db.Column(db.String(200), nullable=False)
    
    # Encrypted user data fields
    # These store BASE64-encoded ciphertexts
    name_encrypted = db.Column(db.Text)
    email_encrypted = db.Column(db.Text)
    contact_info_encrypted = db.Column(db.Text)
    
    # HMAC tags for integrity verification
    name_hmac = db.Column(db.String(256))
    email_hmac = db.Column(db.String(256))
    contact_info_hmac = db.Column(db.String(256))
    
    # Hash for password verification (using custom PBKDF2)
    password_hash = db.Column(db.String(256))
    password_salt = db.Column(db.String(256))
    
    # Access control & status
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    contribution = db.Column(db.Integer, default=0)
    
    # Relationships
    posts = db.relationship("Post", backref="user", lazy=True)
    reported_by = db.relationship(
        "UserReport",
        foreign_keys=[UserReport.reporter_id],
        backref="reporter",
        lazy=True,
    )
    reports_against = db.relationship(
        "UserReport",
        foreign_keys=[UserReport.reported_user_id],
        backref="reported_user",
        lazy=True,
    )
    
    def get_decrypted_data(self, user_keys_model):
        """
        Decrypt user data using their keypairs
        Returns dict with decrypted username, email, contact_info
        """
        from app.services.data_encryption_service import DataEncryptionService
        
        if not user_keys_model:
            # Fallback to plaintext if no keys exist (shouldn't happen)
            return {
                "name": self.name,
                "email": self.email,
                "contact_info": getattr(self, 'contact_info_encrypted', None) or ""
            }
        
        result = {}
        rsa_private_key = user_keys_model.get_rsa_private_key()
        
        # Decrypt username
        if self.name_encrypted:
            result['name'] = DataEncryptionService.decrypt_user_data(
                self.name_encrypted, self.name_hmac, rsa_private_key
            )
        else:
            result['name'] = self.name
        
        # Decrypt email
        if self.email_encrypted:
            result['email'] = DataEncryptionService.decrypt_user_data(
                self.email_encrypted, self.email_hmac, rsa_private_key
            )
        else:
            result['email'] = self.email
        
        # Decrypt contact info
        if self.contact_info_encrypted:
            result['contact_info'] = DataEncryptionService.decrypt_user_data(
                self.contact_info_encrypted, self.contact_info_hmac, rsa_private_key
            )
        else:
            result['contact_info'] = ""
        
        return result
