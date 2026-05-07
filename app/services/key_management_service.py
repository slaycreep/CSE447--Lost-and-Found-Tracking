"""
Key Management Service
Handles key generation, storage (encrypted), distribution, and rotation
Implements secure key lifecycle management for RSA and ECC keypairs
"""
import base64
import json
from datetime import datetime, timedelta
from app import db
from app.models.user_keys import UserKeys, KeyArchive
from app.utils.encryption_algorithms import RSAEncryption, ECCEncryption, PasswordHashing


class KeyManagementService:
    """
    Service to manage encryption keys for users.
    Responsibilities:
    - Generate RSA (2048-bit) and ECC (P-256) keypairs
    - Store keys securely (private keys encrypted in DB)
    - Retrieve keys on demand with decryption
    - Manage key rotation with version tracking
    - Archive old keys for backward compatibility
    """
    
    # Master key derivation for encrypting private keys in DB
    # In production, this should come from environment variable or key management service
    MASTER_KEY_SALT = b"cse447-lost-found-key-management"
    
    @staticmethod
    def generate_keypairs():
        """
        Generate fresh RSA and ECC keypairs
        Returns: (rsa_public, rsa_private, ecc_public, ecc_private)
        """
        # Generate 2048-bit RSA keypair
        rsa_public, rsa_private = RSAEncryption.generate_key_pair()
        
        # Generate P-256 ECC keypair
        ecc_public, ecc_private = ECCEncryption.generate_key_pair()
        
        return rsa_public, rsa_private, ecc_public, ecc_private
    
    @staticmethod
    def _derive_key_encryption_key(user_id, master_password):
        """
        Derive a key encryption key (KEK) from user ID and master password
        Uses PBKDF2 to derive KEK deterministically
        
        Args:
            user_id: User's database ID
            master_password: Master password for key derivation (from environment or config)
        
        Returns:
            KEK as bytes (32 bytes for AES-256)
        """
        import base64
        
        # Create salt from user_id and master salt (base64 encoded for PasswordHashing)
        salt_bytes = KeyManagementService.MASTER_KEY_SALT + str(user_id).encode('utf-8')
        salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
        
        # Derive KEK using PBKDF2 with fixed salt
        # Pass salt as base64 string format that PasswordHashing expects
        kek_b64 = PasswordHashing.hash_password(master_password, salt=salt_b64)
        
        # Decode base64 to get 32 bytes
        kek = base64.b64decode(kek_b64)
        
        return kek
    
    @staticmethod
    def _encrypt_private_key(private_key_dict, encryption_key):
        """
        Encrypt a private key dictionary using XOR stream cipher
        (Since we're implementing from scratch and can't use AES)
        
        Args:
            private_key_dict: Private key as dictionary
            encryption_key: Encryption key bytes (32 bytes)
        
        Returns:
            Encrypted data as base64 string
        """
        # Convert private key dict to JSON
        json_data = json.dumps(private_key_dict).encode('utf-8')
        
        # Simple XOR encryption with key expansion
        encrypted = bytearray()
        key_index = 0
        
        for byte in json_data:
            # Expand the key by XORing with itself shifted
            combined_key = encryption_key[key_index % len(encryption_key)]
            encrypted.append(byte ^ combined_key)
            key_index += 1
        
        # Return as base64 for storage
        return base64.b64encode(bytes(encrypted)).decode('utf-8')
    
    @staticmethod
    def _decrypt_private_key(encrypted_data_b64, encryption_key):
        """
        Decrypt a private key that was encrypted with _encrypt_private_key
        
        Args:
            encrypted_data_b64: Encrypted data as base64 string
            encryption_key: Encryption key bytes (32 bytes)
        
        Returns:
            Private key as dictionary
        """
        # Decode from base64
        encrypted = base64.b64decode(encrypted_data_b64.encode('utf-8'))
        
        # Simple XOR decryption (same as encryption since XOR is symmetric)
        decrypted = bytearray()
        key_index = 0
        
        for byte in encrypted:
            combined_key = encryption_key[key_index % len(encryption_key)]
            decrypted.append(byte ^ combined_key)
            key_index += 1
        
        # Parse JSON back to dict
        return json.loads(decrypted.decode('utf-8'))
    
    @staticmethod
    def store_keys(user_id, rsa_public, rsa_private, ecc_public, ecc_private, master_password="default-key-encryption"):
        """
        Store user's keypairs securely in database
        Private keys are encrypted before storage
        
        Args:
            user_id: User's database ID
            rsa_public: RSA public key dict
            rsa_private: RSA private key dict
            ecc_public: ECC public key dict
            ecc_private: ECC private key dict
            master_password: Master password for key derivation
        
        Returns:
            UserKeys object
        """
        # Derive key encryption key for this user
        kek = KeyManagementService._derive_key_encryption_key(user_id, master_password)
        
        # Encrypt private keys
        rsa_private_encrypted = KeyManagementService._encrypt_private_key(rsa_private, kek)
        ecc_private_encrypted = KeyManagementService._encrypt_private_key(ecc_private, kek)
        
        # Store public keys as plaintext JSON (they're public anyway)
        # Store private keys encrypted
        user_keys = UserKeys(
            user_id=user_id,
            rsa_public_key=json.dumps(rsa_public),
            rsa_private_key_encrypted=rsa_private_encrypted,
            ecc_public_key=json.dumps(ecc_public),
            ecc_private_key_encrypted=ecc_private_encrypted,
            key_version=1,
            created_at=datetime.utcnow()
        )
        
        db.session.add(user_keys)
        db.session.commit()
        
        return user_keys
    
    @staticmethod
    def retrieve_keys(user_id, master_password="default-key-encryption"):
        """
        Retrieve and decrypt user's current keypairs
        Supports both encrypted (new) and plaintext (legacy) private key formats
        
        Args:
            user_id: User's database ID
            master_password: Master password for key decryption
        
        Returns:
            Dict with 'rsa_public', 'rsa_private', 'ecc_public', 'ecc_private'
        """
        user_keys = UserKeys.query.filter_by(user_id=user_id).order_by(UserKeys.key_version.desc()).first()
        
        if not user_keys:
            raise ValueError(f"No keys found for user {user_id}")
        
        # Derive key encryption key
        kek = KeyManagementService._derive_key_encryption_key(user_id, master_password)
        
        # Decrypt RSA private key (support both encrypted and plaintext formats)
        if user_keys.rsa_private_key_encrypted:
            rsa_private = KeyManagementService._decrypt_private_key(
                user_keys.rsa_private_key_encrypted,
                kek
            )
        elif hasattr(user_keys, 'rsa_private_key_old') and user_keys.rsa_private_key_old:
            # Fallback to old plaintext format (for migration)
            rsa_private = json.loads(user_keys.rsa_private_key_old)
        else:
            raise ValueError(f"No RSA private key found for user {user_id}")
        
        # Decrypt ECC private key (support both encrypted and plaintext formats)
        if user_keys.ecc_private_key_encrypted:
            ecc_private = KeyManagementService._decrypt_private_key(
                user_keys.ecc_private_key_encrypted,
                kek
            )
        elif hasattr(user_keys, 'ecc_private_key_old') and user_keys.ecc_private_key_old:
            # Fallback to old plaintext format (for migration)
            ecc_private = json.loads(user_keys.ecc_private_key_old)
        else:
            raise ValueError(f"No ECC private key found for user {user_id}")
        
        return {
            'rsa_public': json.loads(user_keys.rsa_public_key),
            'rsa_private': rsa_private,
            'ecc_public': json.loads(user_keys.ecc_public_key),
            'ecc_private': ecc_private,
            'key_version': user_keys.key_version
        }
    
    @staticmethod
    def rotate_keys(user_id, master_password="default-key-encryption"):
        """
        Rotate user's keypairs - generate new keys and archive old ones
        This allows reading data encrypted with old keys while using new keys going forward
        
        Args:
            user_id: User's database ID
            master_password: Master password for key encryption
        
        Returns:
            Dict with 'new_keys' and 'archived_version'
        """
        # Get current keys
        current_keys = UserKeys.query.filter_by(user_id=user_id).order_by(UserKeys.key_version.desc()).first()
        
        if not current_keys:
            raise ValueError(f"No keys found for user {user_id}")
        
        current_version = current_keys.key_version
        
        # Archive current keys
        old_key_archive = KeyArchive(
            user_id=user_id,
            version=current_version,
            rsa_public_key=current_keys.rsa_public_key,
            rsa_private_key_encrypted=current_keys.rsa_private_key_encrypted,
            ecc_public_key=current_keys.ecc_public_key,
            ecc_private_key_encrypted=current_keys.ecc_private_key_encrypted,
            archived_at=datetime.utcnow()
        )
        db.session.add(old_key_archive)
        
        # Generate new keypairs
        rsa_public, rsa_private, ecc_public, ecc_private = KeyManagementService.generate_keypairs()
        
        # Derive encryption key for new keys
        kek = KeyManagementService._derive_key_encryption_key(user_id, master_password)
        
        # Encrypt new private keys
        rsa_private_encrypted = KeyManagementService._encrypt_private_key(rsa_private, kek)
        ecc_private_encrypted = KeyManagementService._encrypt_private_key(ecc_private, kek)
        
        # Update existing UserKeys record with new keys (increment version)
        current_keys.rsa_public_key = json.dumps(rsa_public)
        current_keys.rsa_private_key_encrypted = rsa_private_encrypted
        current_keys.ecc_public_key = json.dumps(ecc_public)
        current_keys.ecc_private_key_encrypted = ecc_private_encrypted
        current_keys.key_version = current_version + 1
        current_keys.rotated_at = datetime.utcnow()
        
        db.session.commit()
        
        return {
            'new_keys': {
                'rsa_public': rsa_public,
                'ecc_public': ecc_public,
                'key_version': current_version + 1
            },
            'archived_version': current_version
        }
    
    @staticmethod
    def get_key_version(user_id):
        """
        Get current key version for a user
        
        Args:
            user_id: User's database ID
        
        Returns:
            Current key version number
        """
        user_keys = UserKeys.query.filter_by(user_id=user_id).order_by(UserKeys.key_version.desc()).first()
        
        if not user_keys:
            return None
        
        return user_keys.key_version
    
    @staticmethod
    def retrieve_archived_keys(user_id, version, master_password="default-key-encryption"):
        """
        Retrieve archived keypairs for a specific version
        Used to decrypt data encrypted with old keys
        
        Args:
            user_id: User's database ID
            version: Key version to retrieve
            master_password: Master password for key decryption
        
        Returns:
            Dict with 'rsa_public', 'rsa_private', 'ecc_public', 'ecc_private'
        """
        key_archive = KeyArchive.query.filter_by(
            user_id=user_id,
            version=version
        ).first()
        
        if not key_archive:
            raise ValueError(f"No archived keys found for user {user_id} version {version}")
        
        # Derive key encryption key
        kek = KeyManagementService._derive_key_encryption_key(user_id, master_password)
        
        # Decrypt archived private keys
        rsa_private = KeyManagementService._decrypt_private_key(
            key_archive.rsa_private_key_encrypted,
            kek
        )
        ecc_private = KeyManagementService._decrypt_private_key(
            key_archive.ecc_private_key_encrypted,
            kek
        )
        
        return {
            'rsa_public': json.loads(key_archive.rsa_public_key),
            'rsa_private': rsa_private,
            'ecc_public': json.loads(key_archive.ecc_public_key),
            'ecc_private': ecc_private,
            'key_version': version
        }
    
    @staticmethod
    def list_key_versions(user_id):
        """
        List all key versions (current + archived) for a user
        
        Args:
            user_id: User's database ID
        
        Returns:
            List of dicts with version info and timestamps
        """
        # Get current keys
        current = UserKeys.query.filter_by(user_id=user_id).first()
        versions = []
        
        if current:
            versions.append({
                'version': current.key_version,
                'created_at': current.created_at,
                'rotated_at': current.rotated_at,
                'status': 'current'
            })
        
        # Get archived keys
        archived = KeyArchive.query.filter_by(user_id=user_id).order_by(KeyArchive.version.desc()).all()
        for archive in archived:
            versions.append({
                'version': archive.version,
                'created_at': archive.archived_at,
                'rotated_at': archive.archived_at,
                'status': 'archived'
            })
        
        return sorted(versions, key=lambda x: x['version'], reverse=True)
