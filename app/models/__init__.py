"""Import all models to register them with the database."""
from app.models.user import User
from app.models.user_keys import UserKeys
from app.models.post import Post
from app.models.notification import Notification
from app.models.chat import Chat
from app.models.user_report import UserReport
from app.models.verificationClaim import VerificationClaim
from app.models.verification_code import VerificationCode
from app.models.rbac import Permission, Role

__all__ = [
    'User',
    'UserKeys',
    'Post',
    'Notification',
    'Chat',
    'UserReport',
    'VerificationClaim',
    'VerificationCode',
    'Permission',
    'Role',
]
