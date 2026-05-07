from app import db
from datetime import datetime

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(500), nullable=False)
    category_id = db.Column(db.Integer)
    category_name = db.Column(db.String(100))
    post_date = db.Column(db.DateTime, default=datetime.utcnow)
    lOrF_date = db.Column(db.DateTime)
    location = db.Column(db.String(200))
    images = db.Column(db.String(1000))
    status = db.Column(db.Boolean, default=True)
    share_count = db.Column(db.Integer, default=0)
    verification_status = db.Column(db.String(50), default="pending")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    type = db.Column(db.String(50))
    item_name = db.Column(db.String(100))
    contact_method = db.Column(db.String(50))
    
    # Encrypted post data fields (base64-encoded ciphertexts)
    description_encrypted = db.Column(db.Text)
    item_name_encrypted = db.Column(db.Text)
    location_encrypted = db.Column(db.Text)
    contact_method_encrypted = db.Column(db.Text)
    
    # HMAC tags for integrity verification
    description_hmac = db.Column(db.String(256))
    item_name_hmac = db.Column(db.String(256))
    location_hmac = db.Column(db.String(256))
    contact_method_hmac = db.Column(db.String(256))
    
    verification_claims = db.relationship("VerificationClaim", backref="post", lazy=True)

    # Relationship with backref and cascade
    chats = db.relationship('Chat', backref=db.backref('post', lazy=True), cascade='all, delete-orphan')
    
    def get_decrypted_data(self):
        """
        Decrypt post data using the user's ECC keypair
        Returns dict with decrypted description, item_name, location, contact_method
        """
        from app.services.key_management_service import KeyManagementService
        from app.services.data_encryption_service import DataEncryptionService
        
        result = {}
        
        try:
            # Retrieve user's keys using KeyManagementService
            keys = KeyManagementService.retrieve_keys(
                user_id=self.user_id,
                master_password="default-key-encryption"
            )
            ecc_private_key = keys['ecc_private']
            
            # Decrypt each field if encrypted
            if self.description_encrypted:
                result['description'] = DataEncryptionService.decrypt_post_data(
                    self.description_encrypted, self.description_hmac, ecc_private_key
                )
            else:
                result['description'] = self.description
            
            if self.item_name_encrypted:
                result['item_name'] = DataEncryptionService.decrypt_post_data(
                    self.item_name_encrypted, self.item_name_hmac, ecc_private_key
                )
            else:
                result['item_name'] = self.item_name
            
            if self.location_encrypted:
                result['location'] = DataEncryptionService.decrypt_post_data(
                    self.location_encrypted, self.location_hmac, ecc_private_key
                )
            else:
                result['location'] = self.location
            
            if self.contact_method_encrypted:
                result['contact_method'] = DataEncryptionService.decrypt_post_data(
                    self.contact_method_encrypted, self.contact_method_hmac, ecc_private_key
                )
            else:
                result['contact_method'] = self.contact_method
        
        except Exception as e:
            # Fallback to plaintext if key retrieval fails
            result = {
                "description": self.description,
                "item_name": self.item_name,
                "location": self.location,
                "contact_method": self.contact_method
            }
        
        return result
