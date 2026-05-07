"""
Role-Based Access Control Models
Implements granular permission and role management system
"""
from app import db
from datetime import datetime

# Association table for Role-Permission relationship (many-to-many)
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)
)

# Association table for User-Role relationship (many-to-many)
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('assigned_at', db.DateTime, default=datetime.utcnow)
)


class Permission(db.Model):
    """
    Defines granular permissions in the system
    Examples: view_posts, edit_posts, delete_posts, manage_users, view_reports, etc.
    """
    id = db.Column(db.Integer, primary_key=True)
    
    # Permission identifier (e.g., 'view_posts', 'edit_posts')
    # Format: resource_action (e.g., posts_view, posts_edit, posts_delete)
    codename = db.Column(db.String(100), unique=True, nullable=False)
    
    # Human-readable description
    description = db.Column(db.String(255), nullable=False)
    
    # Permission category for grouping (e.g., 'posts', 'users', 'reports', 'system')
    category = db.Column(db.String(50), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Permission {self.codename}>"


class Role(db.Model):
    """
    Roles group permissions together
    Examples: admin, moderator, user, guest
    """
    id = db.Column(db.Integer, primary_key=True)
    
    # Role name (e.g., 'admin', 'moderator', 'user', 'guest')
    name = db.Column(db.String(100), unique=True, nullable=False)
    
    # Role description
    description = db.Column(db.String(255))
    
    # Permissions assigned to this role (many-to-many)
    permissions = db.relationship('Permission',
                                  secondary=role_permissions,
                                  backref=db.backref('roles', lazy=True),
                                  lazy=True)
    
    # System role flag (protected roles that shouldn't be deleted)
    is_system_role = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def has_permission(self, permission_codename):
        """
        Check if this role has a specific permission
        
        Args:
            permission_codename: The codename of the permission to check
            
        Returns:
            True if role has permission, False otherwise
        """
        return any(perm.codename == permission_codename for perm in self.permissions)
    
    def add_permission(self, permission):
        """Add a permission to this role"""
        if permission not in self.permissions:
            self.permissions.append(permission)
    
    def remove_permission(self, permission):
        """Remove a permission from this role"""
        if permission in self.permissions:
            self.permissions.remove(permission)
    
    def __repr__(self):
        return f"<Role {self.name}>"
