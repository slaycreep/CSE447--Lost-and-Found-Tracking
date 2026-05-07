from app.repositories.user_repository import UserRepository
from app.services.key_management_service import KeyManagementService
from app.services.data_encryption_service import DataEncryptionService


class UserService:
    def __init__(self):
        self.user_repository = UserRepository()

    def get_by_id(self, user_id):
        return self.user_repository.get_by_id(user_id)

    def get_by_email(self, email):
        return self.user_repository.get_by_email(email)

    def get_all_users(self):
        return self.user_repository.get_all()

    def get_profile_decrypted(self, user_id):
        """
        Get user profile with decrypted data
        Returns dict with name, email, contact_info (decrypted)
        """
        user = self.get_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        return user.get_decrypted_data()

    def update_profile(self, user_id, data):
        """
        Update user profile with automatic encryption of sensitive fields
        Expects: name, email, contact_info
        Uses custom RSA encryption from scratch
        """
        user = self.get_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        try:
            # Retrieve user's RSA public key for encryption
            keys = KeyManagementService.retrieve_keys(
                user_id=user_id,
                master_password="default-key-encryption"
            )
            rsa_public_key = keys['rsa_public']
            
            # Encrypt each field if provided
            if data.get('name'):
                user.name = data['name']
                name_enc, name_hmac = DataEncryptionService.encrypt_user_data(
                    data['name'], rsa_public_key, keys['ecc_public']
                )
                user.name_encrypted = name_enc
                user.name_hmac = name_hmac
            
            if data.get('email'):
                user.email = data['email']
                email_enc, email_hmac = DataEncryptionService.encrypt_user_data(
                    data['email'], rsa_public_key, keys['ecc_public']
                )
                user.email_encrypted = email_enc
                user.email_hmac = email_hmac
            
            if data.get('contact_info'):
                contact_enc, contact_hmac = DataEncryptionService.encrypt_user_data(
                    data['contact_info'], rsa_public_key, keys['ecc_public']
                )
                user.contact_info_encrypted = contact_enc
                user.contact_info_hmac = contact_hmac
            
        except Exception as e:
            # If encryption fails, raise error
            raise ValueError(f"Error updating profile: {str(e)}")
        
        return self.user_repository.update(user)

    def update_user(self, user_id, data):
        user = self.get_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        for key, value in data.items():
            setattr(user, key, value)

        return self.user_repository.update(user)

    def get_notifications(self, user_id):
        # TODO: Implement notifications system
        return []
