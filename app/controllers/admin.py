from flask import Blueprint, render_template, flash, redirect, url_for, request, jsonify
from app.services.admin_service import AdminService
from app.services.user_service import UserService
from app.services.post_service import PostService
from app.services.key_management_service import KeyManagementService
from app.utils.decorators import admin_required, permission_required

admin_bp = Blueprint('admin', __name__)
admin_service = AdminService()
user_service = UserService()
post_service = PostService()

@admin_bp.route("/dashboard")
@permission_required('admin_access')
def admin_dashboard():
    stats = admin_service.get_dashboard_stats()
    recent_reports = admin_service.get_recent_reports()
    # recent_users = admin_service.get_recent_users()

    return render_template('admin/dashboard.html',
                         stats=stats,
                         recent_reports=recent_reports)

@admin_bp.route("/users")
@permission_required('admin_manage_users')
def manage_users():
    from app.models.rbac import Role
    users = admin_service.get_all_users()  # Changed from user_service to admin_service
    roles = Role.query.all()
    return render_template('admin/users.html', users=users, roles=roles)

@admin_bp.route("/reports")
@permission_required('admin_manage_reports')
def manage_reports():
    fraud_reports = admin_service.get_recent_reports(limit=None)  # Get all reports
    return render_template('admin/manage_reports.html', fraud_reports=fraud_reports)

@admin_bp.route("/user/<int:user_id>/toggle-ban", methods=['POST'])
@permission_required('users_ban')
def toggle_user_ban(user_id):
    success = admin_service.toggle_user_ban(user_id)  # Use direct toggle method
    if success:
        flash("User ban status toggled successfully", "success")
    else:
        flash("Failed to update user ban status", "danger")
    return redirect(url_for('admin.manage_users'))

@admin_bp.route("/user/<int:user_id>/assign-role", methods=['POST'])
@permission_required('admin_manage_users')
def assign_user_role(user_id):
    """Assign or change a user's role"""
    from app.models.user import User
    from app.models.rbac import Role
    from app import db
    
    role_name = request.form.get('role')
    
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "danger")
        return redirect(url_for('admin.manage_users'))
    
    if role_name:
        role = Role.query.filter_by(name=role_name).first()
        if role:
            # Clear existing roles and assign new one
            user.roles.clear()
            user.add_role(role)
            db.session.commit()
            flash(f"User role changed to {role_name}", "success")
        else:
            flash("Role not found", "danger")
    else:
        flash("No role selected", "danger")
    
    return redirect(url_for('admin.manage_users'))

@admin_bp.route("/user/<int:user_id>/toggle-admin", methods=['POST'])
@permission_required('admin_manage_users')
def toggle_admin_status(user_id):
    """Toggle admin status for a user"""
    from app.models.user import User
    from app.models.rbac import Role
    from app import db
    
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "danger")
        return redirect(url_for('admin.manage_users'))
    
    # Toggle admin status
    user.is_admin = not user.is_admin
    
    if user.is_admin:
        # If making admin, clear roles (admin has all permissions)
        user.roles.clear()
    else:
        # If removing admin, assign user role
        user_role = Role.query.filter_by(name='user').first()
        user.roles.clear()
        if user_role:
            user.add_role(user_role)
    
    db.session.commit()
    
    status = "promoted to" if user.is_admin else "demoted from"
    flash(f"User {status} admin", "success")
    return redirect(url_for('admin.manage_users'))

@admin_bp.route("/fraud-report/<int:report_id>/resolve", methods=['POST'])
@permission_required('reports_resolve')
def resolve_fraud_report(report_id):
    action = request.form.get('action')
    admin_service.resolve_report(report_id, action)
    flash("Fraud report resolved successfully", "success")
    return redirect(url_for('admin.manage_reports'))

@admin_bp.route("/post/<int:post_id>/edit", methods=['GET', 'POST'])
@admin_required
def edit_post(post_id):
    if request.method == 'POST':
        try:
            post_data = {
                'item_name': request.form.get('item_name'),
                'description': request.form.get('description'),
                'category_name': request.form.get('category'),
                'location': request.form.get('location'),
                'contact_method': request.form.get('contact_method'),
                'type': request.form.get('type'),
                'lOrF_date': request.form.get('lost_found_date'),  # Fixed field name
                'images': request.files.getlist('images')
            }
            post = post_service.get_by_id(post_id)  # Get post first
            post_service.update(post, post_data)  # Use correct update method
            flash("Post updated successfully", "success")
            return redirect(url_for('admin.manage_posts'))
        except Exception as e:
            flash(f"Error updating post: {str(e)}", "danger")
    post = post_service.get_by_id(post_id)  # Use correct get method
    return render_template('admin/edit_post.html', post=post)

@admin_bp.route("/post/<int:post_id>/delete", methods=['POST'])
@admin_required
def delete_post(post_id):
    post = post_service.get_by_id(post_id)  # Get post first
    post_service.delete(post)  # Use correct delete method
    flash("Post deleted successfully", "success")
    return redirect(url_for('admin.manage_posts'))

@admin_bp.route("/posts")
@admin_required
def manage_posts():
    filters = {
        'category': request.args.get('category', ''),
        'type': request.args.get('type', ''),
        'date_from': request.args.get('date_from', ''),
        'date_to': request.args.get('date_to', ''),
        'location': request.args.get('location', '')
    }
    posts = post_service.search_posts("", filters)  # Changed to use proper search method
    return render_template('admin/manage_posts.html', posts=posts, filters=filters)

# ======================
# Key Management Endpoints
# ======================

@admin_bp.route("/user/<int:user_id>/keys", methods=['GET'])
@permission_required('admin_access')
def view_user_keys(user_id):
    """View encryption key versions for a user (including archived keys)"""
    from app.models.user import User
    
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "danger")
        return redirect(url_for('admin.manage_users'))
    
    try:
        key_versions = KeyManagementService.list_key_versions(user_id)
        current_version = KeyManagementService.get_key_version(user_id)
        return render_template('admin/user_keys.html', 
                             user=user, 
                             key_versions=key_versions,
                             current_version=current_version)
    except Exception as e:
        flash(f"Error retrieving key information: {str(e)}", "danger")
        return redirect(url_for('admin.manage_users'))

@admin_bp.route("/user/<int:user_id>/keys/rotate", methods=['POST'])
@permission_required('admin_access')
def rotate_user_keys(user_id):
    """Rotate encryption keys for a user (generates new keypair, archives old)"""
    from app.models.user import User
    
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "danger")
        return redirect(url_for('admin.manage_users'))
    
    try:
        result = KeyManagementService.rotate_keys(user_id)
        new_version = result['new_keys']['key_version']
        archived_version = result['archived_version']
        
        flash(f"Keys rotated successfully! "
              f"New version: {new_version}, Archived version: {archived_version}", "success")
        return redirect(url_for('admin.view_user_keys', user_id=user_id))
    except Exception as e:
        flash(f"Error rotating keys: {str(e)}", "danger")
        return redirect(url_for('admin.manage_users'))

@admin_bp.route("/api/user/<int:user_id>/keys/info", methods=['GET'])
@permission_required('admin_access')
def api_get_user_keys_info(user_id):
    """API endpoint to get current key version and info (JSON response)"""
    from app.models.user import User
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        current_version = KeyManagementService.get_key_version(user_id)
        all_versions = KeyManagementService.list_key_versions(user_id)
        
        return jsonify({
            'user_id': user_id,
            'user_email': user.email_encrypted[:20] + '***',  # Partial display
            'current_version': current_version,
            'total_versions': len(all_versions),
            'versions': all_versions
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/api/user/<int:user_id>/keys/rotate", methods=['POST'])
@permission_required('admin_access')
def api_rotate_user_keys(user_id):
    """API endpoint to rotate keys (JSON response for AJAX requests)"""
    from app.models.user import User
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        result = KeyManagementService.rotate_keys(user_id)
        return jsonify({
            'success': True,
            'message': 'Keys rotated successfully',
            'new_version': result['new_keys']['key_version'],
            'archived_version': result['archived_version']
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
