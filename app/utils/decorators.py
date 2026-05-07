from functools import wraps
from flask import session, redirect, url_for, flash
from app.models.user import User

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to continue.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin access required.", "danger")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function

def user_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login to continue.", "warning")
            return redirect(url_for("auth.login"))
        if session.get("is_admin"):
            flash("This feature is only available for regular users.", "warning")
            return redirect(url_for("dashboard.dashboard"))
        return f(*args, **kwargs)
    return decorated_function


# RBAC Permission Decorators

def permission_required(permission_codename):
    """
    Decorator to require a specific permission
    
    Usage:
        @app.route('/delete-post/<int:post_id>')
        @permission_required('posts_delete_any')
        def delete_post(post_id):
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login to continue.", "warning")
                return redirect(url_for("auth.login"))
            
            user = User.query.get(session["user_id"])
            if not user:
                flash("User not found.", "danger")
                return redirect(url_for("auth.login"))
            
            if not user.has_permission(permission_codename):
                flash(f"You do not have permission to {permission_codename}.", "danger")
                return redirect(url_for("dashboard.dashboard"))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def role_required(role_name):
    """
    Decorator to require a specific role
    
    Usage:
        @app.route('/admin/manage')
        @role_required('admin')
        def manage():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login to continue.", "warning")
                return redirect(url_for("auth.login"))
            
            user = User.query.get(session["user_id"])
            if not user:
                flash("User not found.", "danger")
                return redirect(url_for("auth.login"))
            
            if not user.has_role(role_name):
                flash(f"You must be a {role_name} to access this.", "danger")
                return redirect(url_for("dashboard.dashboard"))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def any_permission_required(*permission_codenames):
    """
    Decorator to require any one of multiple permissions
    
    Usage:
        @app.route('/edit-post/<int:post_id>')
        @any_permission_required('posts_edit', 'posts_edit_any')
        def edit_post(post_id):
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login to continue.", "warning")
                return redirect(url_for("auth.login"))
            
            user = User.query.get(session["user_id"])
            if not user:
                flash("User not found.", "danger")
                return redirect(url_for("auth.login"))
            
            if not any(user.has_permission(perm) for perm in permission_codenames):
                flash("You do not have permission to access this.", "danger")
                return redirect(url_for("dashboard.dashboard"))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
