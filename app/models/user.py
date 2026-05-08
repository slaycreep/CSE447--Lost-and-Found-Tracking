from app import db
from app.models.user_report import UserReport
from app.models.rbac import user_roles

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
    
    # RBAC: User roles (many-to-many relationship)
    roles = db.relationship('Role',
                           secondary=user_roles,
                           backref=db.backref('users', lazy=True),
                           lazy=True)
    
    def get_decrypted_data(self, user_keys_model=None):
        """
        Decrypt user data using their keypairs from KeyManagementService
        Returns dict with decrypted username, email, contact_info
        """
        from app.services.key_management_service import KeyManagementService
        from app.services.data_encryption_service import DataEncryptionService
        
        result = {}
        
        try:
            # Retrieve keys using KeyManagementService (handles decryption automatically)
            keys = KeyManagementService.retrieve_keys(
                user_id=self.id,
                master_password="default-key-encryption"
            )
            ecc_private_key = keys['ecc_private']
            rsa_private_key = keys['rsa_private']  # For backward compatibility with legacy data
            
            # Decrypt username
            if self.name_encrypted:
                result['name'] = DataEncryptionService.decrypt_user_data(
                    self.name_encrypted, 
                    self.name_hmac, 
                    ecc_private_key=ecc_private_key,
                    rsa_private_key=rsa_private_key
                )
            else:
                result['name'] = self.name
            
            # Decrypt email
            if self.email_encrypted:
                result['email'] = DataEncryptionService.decrypt_user_data(
                    self.email_encrypted, 
                    self.email_hmac, 
                    ecc_private_key=ecc_private_key,
                    rsa_private_key=rsa_private_key
                )
            else:
                result['email'] = self.email
            
            # Decrypt contact info using RSA-2048
            if self.contact_info_encrypted:
                result['contact_info'] = DataEncryptionService.decrypt_contact_info_with_rsa(
                    self.contact_info_encrypted, 
                    self.contact_info_hmac, 
                    rsa_private_key=rsa_private_key
                )
            else:
                result['contact_info'] = ""
        
        except Exception as e:
            # Fallback to plaintext if key retrieval fails
            result = {
                "name": self.name,
                "email": self.email,
                "contact_info": getattr(self, 'contact_info_encrypted', None) or ""
            }
        
        return result
    
    # RBAC Methods
    def has_role(self, role_name):
        """
        Check if user has a specific role
        
        Args:
            role_name: Name of the role (e.g., 'admin', 'moderator')
            
        Returns:
            True if user has the role, False otherwise
        """
        return any(role.name == role_name for role in self.roles)
    
    def has_permission(self, permission_codename):
        """
        Check if user has a specific permission (through any of their roles)
        
        Args:
            permission_codename: Codename of the permission (e.g., 'posts_delete')
            
        Returns:
            True if user has the permission, False otherwise
        """
        # Admin users have all permissions
        if self.is_admin:
            return True
        
        # Check if any of user's roles have the permission
        for role in self.roles:
            if role.has_permission(permission_codename):
                return True
        
        return False
    
    def add_role(self, role):
        """Add a role to this user"""
        if role not in self.roles:
            self.roles.append(role)
    
    def remove_role(self, role):
        """Remove a role from this user"""
        if role in self.roles:
            self.roles.remove(role)
    
    def get_permissions(self):
        """
        Get all permissions for this user (from all roles)
        
        Returns:
            Set of permission codenames
        """
        if self.is_admin:
            # Admin has all permissions - return all permission codenames
            from app.models.rbac import Permission
            return {perm.codename for perm in Permission.query.all()}
        
        permissions = set()
        for role in self.roles:
            for permission in role.permissions:
                permissions.add(permission.codename)
        
        return permissions
