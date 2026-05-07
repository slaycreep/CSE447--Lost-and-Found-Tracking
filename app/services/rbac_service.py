"""
RBAC Service Layer
Handles role, permission, and access control operations
"""
from app import db
from app.models.rbac import Permission, Role
from app.models.user import User


class RBACService:
    """
    Service for managing Role-Based Access Control
    Handles permission creation, role management, and access verification
    """
    
    # Define all available permissions in the system
    DEFAULT_PERMISSIONS = {
        'posts': [
            ('posts_view', 'View posts'),
            ('posts_create', 'Create new posts'),
            ('posts_edit', 'Edit own posts'),
            ('posts_edit_any', 'Edit any posts'),
            ('posts_delete', 'Delete own posts'),
            ('posts_delete_any', 'Delete any posts'),
        ],
        'profiles': [
            ('profiles_view', 'View user profiles'),
            ('profiles_edit', 'Edit own profile'),
            ('profiles_edit_any', 'Edit any profile'),
        ],
        'reports': [
            ('reports_view', 'View reports'),
            ('reports_create', 'Create reports'),
            ('reports_view_any', 'View all reports'),
            ('reports_resolve', 'Resolve reports'),
        ],
        'verification': [
            ('verification_view', 'View verification claims'),
            ('verification_claim', 'Submit verification claims'),
            ('verification_approve', 'Approve verification claims'),
        ],
        'users': [
            ('users_view', 'View users'),
            ('users_view_any', 'View all users'),
            ('users_ban', 'Ban users'),
            ('users_unban', 'Unban users'),
        ],
        'chat': [
            ('chat_send', 'Send messages'),
            ('chat_view', 'View messages'),
        ],
        'admin': [
            ('admin_access', 'Access admin panel'),
            ('admin_manage_posts', 'Manage posts'),
            ('admin_manage_reports', 'Manage reports'),
            ('admin_manage_users', 'Manage users'),
        ]
    }
    
    # Define default roles (SIMPLIFIED: Admin and User only)
    DEFAULT_ROLES = {
        'admin': {
            'description': 'Administrator with full access',
            'permissions': ['posts_view', 'posts_create', 'posts_edit_any', 'posts_delete_any',
                          'profiles_view', 'profiles_edit_any',
                          'reports_view', 'reports_resolve',
                          'verification_view', 'verification_approve',
                          'users_view_any', 'users_ban', 'users_unban',
                          'chat_send', 'chat_view',
                          'admin_access', 'admin_manage_posts', 'admin_manage_reports', 'admin_manage_users'],
            'is_system': True
        },
        'user': {
            'description': 'Regular user with standard access',
            'permissions': ['posts_view', 'posts_create', 'posts_edit', 'posts_delete',
                          'profiles_view', 'profiles_edit',
                          'reports_create',
                          'verification_view', 'verification_claim',
                          'users_view',
                          'chat_send', 'chat_view'],
            'is_system': True
        }
    }
    
    @staticmethod
    def init_rbac():
        """
        Initialize RBAC system with default permissions and roles
        Call this once to set up the system
        """
        # Create all permissions
        for category, permissions in RBACService.DEFAULT_PERMISSIONS.items():
            for codename, description in permissions:
                if not Permission.query.filter_by(codename=codename).first():
                    perm = Permission(
                        codename=codename,
                        description=description,
                        category=category
                    )
                    db.session.add(perm)
        
        db.session.commit()
        
        # Create all default roles
        for role_name, role_config in RBACService.DEFAULT_ROLES.items():
            if not Role.query.filter_by(name=role_name).first():
                role = Role(
                    name=role_name,
                    description=role_config['description'],
                    is_system_role=role_config['is_system']
                )
                
                # Add permissions to role
                for perm_codename in role_config['permissions']:
                    perm = Permission.query.filter_by(codename=perm_codename).first()
                    if perm:
                        role.add_permission(perm)
                
                db.session.add(role)
        
        db.session.commit()
    
    @staticmethod
    def create_permission(codename, description, category):
        """Create a new permission"""
        if Permission.query.filter_by(codename=codename).first():
            raise ValueError(f"Permission {codename} already exists")
        
        perm = Permission(
            codename=codename,
            description=description,
            category=category
        )
        db.session.add(perm)
        db.session.commit()
        return perm
    
    @staticmethod
    def create_role(name, description, permissions=None):
        """
        Create a new role
        
        Args:
            name: Role name
            description: Role description
            permissions: List of permission codenames
        """
        if Role.query.filter_by(name=name).first():
            raise ValueError(f"Role {name} already exists")
        
        role = Role(name=name, description=description)
        
        if permissions:
            for perm_codename in permissions:
                perm = Permission.query.filter_by(codename=perm_codename).first()
                if perm:
                    role.add_permission(perm)
        
        db.session.add(role)
        db.session.commit()
        return role
    
    @staticmethod
    def assign_role_to_user(user_id, role_name):
        """Assign a role to a user"""
        user = User.query.get_or_404(user_id)
        role = Role.query.filter_by(name=role_name).first()
        
        if not role:
            raise ValueError(f"Role {role_name} does not exist")
        
        user.add_role(role)
        db.session.commit()
        
        return user
    
    @staticmethod
    def remove_role_from_user(user_id, role_name):
        """Remove a role from a user"""
        user = User.query.get_or_404(user_id)
        role = Role.query.filter_by(name=role_name).first()
        
        if not role:
            raise ValueError(f"Role {role_name} does not exist")
        
        user.remove_role(role)
        db.session.commit()
        
        return user
    
    @staticmethod
    def user_has_permission(user_id, permission_codename):
        """Check if user has a specific permission"""
        user = User.query.get_or_404(user_id)
        return user.has_permission(permission_codename)
    
    @staticmethod
    def user_has_role(user_id, role_name):
        """Check if user has a specific role"""
        user = User.query.get_or_404(user_id)
        return user.has_role(role_name)
    
    @staticmethod
    def get_user_permissions(user_id):
        """Get all permissions for a user"""
        user = User.query.get_or_404(user_id)
        return user.get_permissions()
    
    @staticmethod
    def get_user_roles(user_id):
        """Get all roles for a user"""
        user = User.query.get_or_404(user_id)
        return [role.name for role in user.roles]
