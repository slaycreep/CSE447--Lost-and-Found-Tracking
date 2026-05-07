from flask import Blueprint, request, session, redirect, url_for, flash, render_template
from app.services.auth_service import AuthService
from app.services.two_factor_auth_service import TwoFactorAuthService
from app.services.session_security_service import SessionSecurityService
from app.utils.decorators import login_required

auth_bp = Blueprint('auth', __name__)
auth_service = AuthService()

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))
    
    if request.method == "POST":
        try:
            # Validate CSRF token
            csrf_from_form = request.form.get("csrf_token")
            if csrf_from_form and not SessionSecurityService.validate_csrf_token(csrf_from_form):
                fresh_token = SessionSecurityService.generate_csrf_token()
                flash("Security validation failed. Please try again.", "danger")
                return render_template("login.html", csrf_token=fresh_token)
            
            email = request.form.get("email")
            
            # Check if IP is locked out due to too many failed attempts
            if SessionSecurityService.is_login_locked(email):
                remaining = SessionSecurityService.get_lockout_time_remaining(email)
                fresh_token = SessionSecurityService.generate_csrf_token()
                flash(f"Too many failed attempts. Try again in {remaining} seconds.", "danger")
                return render_template("login.html", csrf_token=fresh_token)
            
            password = request.form.get("password")
            
            # Factor 1: Verify email and password
            success, user, verification_code_id = TwoFactorAuthService.start_authentication(
                email,
                password
            )
            
            if success:
                # Clear failed login attempts
                SessionSecurityService.clear_failed_login(email)
                
                # ENSURE SESSION PERSISTS
                session.permanent = True
                
                # Store verification code ID in session for next step
                session["verification_code_id"] = verification_code_id
                session["temp_user_id"] = user.id
                session["temp_user_name"] = user.name
                session.modified = True  # Ensure session is saved
                
                flash("Password verified. Please enter the code sent to your email.", "info")
                return redirect(url_for("auth.verify_otp"))
            else:
                # Track failed login attempt
                SessionSecurityService.track_failed_login(email)
                error_msg = verification_code_id if isinstance(verification_code_id, str) else "Invalid email or password"
                flash(error_msg, "danger")
        except ValueError as e:
            flash(str(e), "danger")
    
    # Generate fresh CSRF token for GET or after errors
    csrf_token = SessionSecurityService.generate_csrf_token()
    return render_template("login.html", csrf_token=csrf_token)

@auth_bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    # Check if user is in the middle of 2FA
    if "verification_code_id" not in session:
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for("auth.login"))
    
    if request.method == "POST":
        try:
            # Validate CSRF token
            csrf_from_form = request.form.get("csrf_token")
            if csrf_from_form and not SessionSecurityService.validate_csrf_token(csrf_from_form):
                flash("Security validation failed. Please try again.", "danger")
                temp_user_name = session.get("temp_user_name", "User")
                fresh_token = SessionSecurityService.generate_csrf_token()
                return render_template("verify_otp.html", user_name=temp_user_name, csrf_token=fresh_token)
            
            verification_code_id = session.get("verification_code_id")
            otp_code = request.form.get("otp_code")
            
            # Factor 2: Verify OTP code
            success, user, message = TwoFactorAuthService.verify_second_factor(
                verification_code_id,
                otp_code
            )
            
            if success:
                # Both factors verified - initialize secure session with SessionSecurityService
                SessionSecurityService.init_session(user.id, user.email, user.name, user.is_admin)
                
                # Clean up temporary session data
                session.pop("verification_code_id", None)
                session.pop("temp_user_id", None)
                session.pop("temp_user_name", None)
                
                flash(f"Welcome back, {user.name}!", "success")
                return redirect(url_for("dashboard.dashboard"))
            else:
                flash(message, "danger")
        except ValueError as e:
            flash(str(e), "danger")
    
    # Generate fresh CSRF token for GET or after errors
    csrf_token = SessionSecurityService.generate_csrf_token()
    temp_user_name = session.get("temp_user_name", "User")
    return render_template("verify_otp.html", user_name=temp_user_name, csrf_token=csrf_token)

@auth_bp.route("/request-new-code", methods=["POST"])
def request_new_code():
    """Request a new OTP code (user lost/didn't receive code)"""
    if "temp_user_id" not in session:
        return redirect(url_for("auth.login"))
    
    try:
        user_id = session.get("temp_user_id")
        success, verification_code_id, message = TwoFactorAuthService.request_new_code(user_id)
        
        if success:
            session["verification_code_id"] = verification_code_id
            flash(message, "success")
        else:
            flash(message, "danger")
    except ValueError as e:
        flash(str(e), "danger")
    
    return redirect(url_for("auth.verify_otp"))

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))
    
    if request.method == "POST":
        try:
            # Validate CSRF token
            csrf_from_form = request.form.get("csrf_token")
            if csrf_from_form and not SessionSecurityService.validate_csrf_token(csrf_from_form):
                fresh_token = SessionSecurityService.generate_csrf_token()
                flash("Security validation failed. Please try again.", "danger")
                return render_template("register.html", csrf_token=fresh_token)
            
            user = auth_service.register(
                request.form.get("name"),
                request.form.get("email"),
                request.form.get("password"),
                request.form.get("contact_info")
            )
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("auth.login"))
        except ValueError as e:
            flash(str(e), "danger")
    
    # Generate fresh CSRF token for GET or after errors
    csrf_token = SessionSecurityService.generate_csrf_token()
    return render_template("register.html", csrf_token=csrf_token)

@auth_bp.route("/logout")
def logout():
    # Get user name before clearing session
    user_name = session.get("user_name", "User")
    
    # Destroy the session FIRST (completely clear it)
    SessionSecurityService.destroy_session()
    
    # Now flash the goodbye message (will be stored in cleared session)
    flash(f"Goodbye, {user_name}! You have been logged out.", "info")
    
    return redirect(url_for("auth.login"))

@auth_bp.route("/home")
def root():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    return redirect(url_for("dashboard.dashboard"))

@auth_bp.route("/")  # Should be /auth/ in full URL
def home():
    if "user_id" not in session:
        return redirect(url_for("auth.login")) 
    return redirect(url_for("dashboard.dashboard"))

@auth_bp.route("/debug/otp-codes")
def debug_otp_codes():
    """
    Development endpoint to view all pending OTP codes (for testing)
    Only available in debug mode
    """
    from flask import current_app
    from app.models.verification_code import VerificationCode
    from app.models.user import User
    from datetime import datetime
    
    if not current_app.debug:
        return "Not available in production", 403
    
    pending_codes = VerificationCode.query.filter_by(is_verified=False).all()
    
    otp_info = []
    for code in pending_codes:
        user = User.query.get(code.user_id)
        is_expired = code.is_expired()
        otp_info.append({
            'user_email': user.email if user else 'Unknown',
            'code_id': code.id,
            'plain_code': code.plain_code_dev,  # Development mode only
            'attempts': code.attempts,
            'max_attempts': code.max_attempts,
            'created_at': code.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'expires_at': code.expires_at.strftime('%Y-%m-%d %H:%M:%S'),
            'is_expired': is_expired
        })
    
    return render_template('debug_otp_codes.html', otp_info=otp_info)
