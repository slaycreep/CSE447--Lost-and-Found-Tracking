"""
User Key Management Model
Stores RSA and ECC keypairs for each user with encryption and versioning
"""
from app import db
import json


class UserKeys(db.Model):
    """
    Stores current encryption keys for each user
    Private keys are stored encrypted in the database
    Public keys are stored plaintext (since they're public)
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)
    
    # RSA Keys (2048-bit)
    # Public key: stored as plaintext JSON (it's public)
    rsa_public_key = db.Column(db.Text, nullable=False)  # JSON: {"n": ..., "e": ...}
    # New: encrypted private key storage
    rsa_private_key_encrypted = db.Column(db.Text, nullable=False)  # Base64-encoded encrypted JSON
    # Old: plaintext private key (DEPRECATED - for backward compatibility only)
    rsa_private_key = db.Column(db.Text, nullable=True)  # JSON (DEPRECATED)
    
    # ECC Keys (P-256)
    # Public key: stored as plaintext JSON (it's public)
    ecc_public_key = db.Column(db.Text, nullable=False)  # JSON: {"type": "ECC-P256", "x": ..., "y": ...}
    # New: encrypted private key storage
    ecc_private_key_encrypted = db.Column(db.Text, nullable=False)  # Base64-encoded encrypted JSON
    # Old: plaintext private key (DEPRECATED - for backward compatibility only)
    ecc_private_key = db.Column(db.Text, nullable=True)  # JSON (DEPRECATED)
    
    # Key metadata for versioning and rotation tracking
    key_version = db.Column(db.Integer, default=1)  # Track key versions for rotation
    created_at = db.Column(db.DateTime, default=db.func.now())
    rotated_at = db.Column(db.DateTime)  # Track when keys were last rotated
    
    # Relationship
    user = db.relationship("User", backref="user_keys", uselist=False)
    
    def get_rsa_public_key(self):
        """Parse and return RSA public key (plaintext)"""
        return json.loads(self.rsa_public_key)
    
    def get_ecc_public_key(self):
        """Parse and return ECC public key (plaintext)"""
        return json.loads(self.ecc_public_key)
    
    def set_rsa_keys(self, public_key, private_key):
        """
        Set RSA keys - public key plaintext, private key must be encrypted separately
        For backward compatibility with registration flow
        """
        self.rsa_public_key = json.dumps(public_key)
        # Private key encryption is handled by KeyManagementService
    
    def set_ecc_keys(self, public_key, private_key):
        """
        Set ECC keys - public key plaintext, private key must be encrypted separately
        For backward compatibility with registration flow
        """
        self.ecc_public_key = json.dumps(public_key)
        # Private key encryption is handled by KeyManagementService


class KeyArchive(db.Model):
    """
    Archive for old keypairs during key rotation
    Keeps encrypted versions of old keys so data encrypted with old keys can still be decrypted
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    
    # Versioned keys (encrypted private keys, plaintext public keys)
    version = db.Column(db.Integer, nullable=False)  # Version number being archived
    
    rsa_public_key = db.Column(db.Text, nullable=False)  # JSON plaintext
    rsa_private_key_encrypted = db.Column(db.Text, nullable=False)  # Encrypted JSON
    
    ecc_public_key = db.Column(db.Text, nullable=False)  # JSON plaintext
    ecc_private_key_encrypted = db.Column(db.Text, nullable=False)  # Encrypted JSON
    
    archived_at = db.Column(db.DateTime, default=db.func.now())
    
    # Composite unique constraint: each user can have only one archive per version
    __table_args__ = (db.UniqueConstraint('user_id', 'version', name='uq_user_version'),)
    
    # Relationship
    user = db.relationship("User", backref="key_archives")
    
    def __repr__(self):
        return f"<KeyArchive user_id={self.user_id} version={self.version}>"
