from flask import Blueprint, request, session, redirect, url_for, flash, render_template
from app.services.auth_service import AuthService
from app.services.two_factor_auth_service import TwoFactorAuthService
from app.utils.decorators import login_required

auth_bp = Blueprint('auth', __name__)
auth_service = AuthService()

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))
        
    if request.method == "POST":
        try:
            email = request.form.get("email")
            password = request.form.get("password")
            
            # Factor 1: Verify email and password
            success, user, verification_code_id = TwoFactorAuthService.start_authentication(
                email,
                password
            )
            
            if success:
                # Store verification code ID in session for next step
                session["verification_code_id"] = verification_code_id
                session["temp_user_id"] = user.id
                session["temp_user_name"] = user.name
                flash("Password verified. Please enter the code sent to your email.", "info")
                return redirect(url_for("auth.verify_otp"))
            else:
                flash(verification_code_id, "danger")  # verification_code_id contains error message
        except ValueError as e:
            flash(str(e), "danger")
    return render_template("login.html")

@auth_bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    # Check if user is in the middle of 2FA
    if "verification_code_id" not in session:
        return redirect(url_for("auth.login"))
    
    if request.method == "POST":
        try:
            verification_code_id = session.get("verification_code_id")
            otp_code = request.form.get("otp_code")
            
            # Factor 2: Verify OTP code
            success, user, message = TwoFactorAuthService.verify_second_factor(
                verification_code_id,
                otp_code
            )
            
            if success:
                # Both factors verified - log user in
                session.pop("verification_code_id", None)
                session.pop("temp_user_id", None)
                session.pop("temp_user_name", None)
                
                # Set authenticated session
                session["user_id"] = user.id
                session["user_name"] = user.name
                session["is_admin"] = user.is_admin
                
                flash(f"Welcome back, {user.name}!", "success")
                return redirect(url_for("dashboard.dashboard"))
            else:
                flash(message, "danger")
        except ValueError as e:
            flash(str(e), "danger")
    
    temp_user_name = session.get("temp_user_name", "User")
    return render_template("verify_otp.html", user_name=temp_user_name)

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
    return render_template("register.html")

@auth_bp.route("/logout")
@login_required
def logout():
    user_name = session.get("user_name", "User")
    auth_service.logout_user()
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
