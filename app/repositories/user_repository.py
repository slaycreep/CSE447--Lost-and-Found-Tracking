from app.models.user import User
from app.models.user_keys import UserKeys
from app.services.data_encryption_service import DataEncryptionService
from app.utils.encryption_algorithms import RSAEncryption, ECCEncryption
from app import db
from sqlalchemy import func

class UserRepository:
    @staticmethod
    def get_by_id(user_id):
        return User.query.get(user_id)

    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()

    @staticmethod
    def create(name, email, password, contact_info):
        """
        Create user with encrypted data and generated keypairs
        """
        # Generate RSA and ECC keypairs
        rsa_public, rsa_private = RSAEncryption.generate_key_pair()
        ecc_public, ecc_private = ECCEncryption.generate_key_pair()
        
        # Encrypt user data using RSA
        name_encrypted, name_hmac = DataEncryptionService.encrypt_user_data(
            name, rsa_public, ecc_public
        )
        email_encrypted, email_hmac = DataEncryptionService.encrypt_user_data(
            email, rsa_public, ecc_public
        )
        contact_encrypted, contact_hmac = DataEncryptionService.encrypt_user_data(
            contact_info or "", rsa_public, ecc_public
        )
        
        # Hash password with salt
        password_salt, password_hash = DataEncryptionService.hash_password(password)
        
        # Create user with encrypted data
        user = User(
            name=name,  # Keep for compatibility, but use encrypted versions
            email=email,  # Keep for compatibility
            password="",  # Not used - using password_hash and password_salt instead
            name_encrypted=name_encrypted,
            email_encrypted=email_encrypted,
            contact_info_encrypted=contact_encrypted,
            name_hmac=name_hmac,
            email_hmac=email_hmac,
            contact_info_hmac=contact_hmac,
            password_hash=password_hash,
            password_salt=password_salt
        )
        db.session.add(user)
        db.session.flush()  # Get user.id
        
        # Create UserKeys record
        user_keys = UserKeys(user_id=user.id)
        user_keys.set_rsa_keys(rsa_public, rsa_private)
        user_keys.set_ecc_keys(ecc_public, ecc_private)
        db.session.add(user_keys)
        
        db.session.commit()
        return user

    @staticmethod
    def update(user):
        db.session.commit()
        return user

    def get_top_contributors(self, limit):
        return db.session.query(User)\
        .filter(User.contribution > 0)\
        .order_by(User.contribution.desc())\
        .limit(5).all()

    def count_all(self):
        return User.query.count()

    def count_active(self):
        return User.query.filter_by(is_banned=False).count()

    def count_admins(self):
        return User.query.filter_by(is_admin=True).count()

    def toggle_ban_status(self, user_id):
        user = self.get_by_id(user_id)
        if user:
            user.is_banned = not user.is_banned
            db.session.commit()
            return True
        return False

    def update_ban_status(self, user_id, ban_status):
        user = self.get_by_id(user_id)
        if user:
            user.is_banned = ban_status
            db.session.commit()
            return True
        return False

    def get_recent(self, limit):
        ## user creation logic not set in the model
        pass

    def get_all(self):
        return User.query.all()
