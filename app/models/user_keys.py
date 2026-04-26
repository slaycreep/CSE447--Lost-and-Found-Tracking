"""
User Key Management Model
Stores RSA and ECC keypairs for each user
"""
from app import db
import json


class UserKeys(db.Model):
    """Stores encryption keys for each user"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)
    
    # RSA Keys (2048-bit) - stored as JSON
    rsa_public_key = db.Column(db.Text, nullable=False)  # JSON: {"n": ..., "e": ...}
    rsa_private_key = db.Column(db.Text, nullable=False)  # JSON: {"n": ..., "e": ..., "d": ..., "p": ..., "q": ...}
    
    # ECC Keys (P-256) - stored as JSON
    ecc_public_key = db.Column(db.Text, nullable=False)  # JSON: {"type": "ECC-P256", "x": ..., "y": ...}
    ecc_private_key = db.Column(db.Text, nullable=False)  # JSON: {"type": "ECC-P256", "d": ..., "x": ..., "y": ...}
    
    # Key metadata
    key_version = db.Column(db.Integer, default=1)  # For key rotation tracking
    created_at = db.Column(db.DateTime, default=db.func.now())
    rotated_at = db.Column(db.DateTime)  # Track when keys were last rotated
    
    # Relationship
    user = db.relationship("User", backref="user_keys", uselist=False)
    
    def get_rsa_public_key(self):
        """Parse and return RSA public key"""
        return json.loads(self.rsa_public_key)
    
    def get_rsa_private_key(self):
        """Parse and return RSA private key"""
        return json.loads(self.rsa_private_key)
    
    def get_ecc_public_key(self):
        """Parse and return ECC public key"""
        return json.loads(self.ecc_public_key)
    
    def get_ecc_private_key(self):
        """Parse and return ECC private key"""
        return json.loads(self.ecc_private_key)
    
    def set_rsa_keys(self, public_key, private_key):
        """Set RSA keys from dict"""
        self.rsa_public_key = json.dumps(public_key)
        self.rsa_private_key = json.dumps(private_key)
    
    def set_ecc_keys(self, public_key, private_key):
        """Set ECC keys from dict"""
        self.ecc_public_key = json.dumps(public_key)
        self.ecc_private_key = json.dumps(private_key)
