"""
Data Encryption Service
Handles encryption/decryption of user data using their keypairs
"""
import base64
import json
from app.utils.encryption_algorithms import (
    RSAEncryption, ECCEncryption, HMACIntegrity, PasswordHashing
)


class DataEncryptionService:
    """Service to encrypt/decrypt user and post data"""
    
    @staticmethod
    def encrypt_user_data(plaintext, rsa_public_key, ecc_public_key):
        """
        Encrypt user data using RSA
        Also creates HMAC tag for integrity verification
        Returns: (ciphertext_b64, hmac_tag_b64)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Encrypt using RSA
        ciphertext = RSAEncryption.encrypt(plaintext, rsa_public_key)
        
        # Create HMAC for integrity verification using the RSA public key material
        # The HMAC key is derived from the RSA modulus so it can be verified later
        hmac_key = HMACIntegrity._compute_hmac_raw(
            rsa_public_key["n"].to_bytes(256, 'big'),
            b'HMAC-KEY'
        )
        hmac_tag = HMACIntegrity.create_mac(ciphertext.encode('utf-8'), hmac_key)
        
        # Return both ciphertext and HMAC tag
        return ciphertext, hmac_tag
    
    @staticmethod
    def decrypt_user_data(ciphertext, hmac_tag, rsa_private_key, verify_integrity=True):
        """
        Decrypt user data using RSA
        Verifies HMAC integrity if verify_integrity=True
        Returns: plaintext
        """
        # Derive HMAC key from private key's modulus for verification
        hmac_key = HMACIntegrity._compute_hmac_raw(
            rsa_private_key["n"].to_bytes(256, 'big'),
            b'HMAC-KEY'
        )
        
        # Verify HMAC if requested
        if verify_integrity:
            expected_hmac = hmac_tag
            computed_hmac = HMACIntegrity.create_mac(ciphertext.encode('utf-8'), hmac_key)
            if not HMACIntegrity._constant_time_compare(
                computed_hmac.encode('utf-8'),
                expected_hmac.encode('utf-8')
            ):
                raise ValueError("HMAC verification failed - data integrity compromised")
        
        # Decrypt using RSA
        plaintext = RSAEncryption.decrypt(ciphertext, rsa_private_key)
        
        return plaintext
    
    @staticmethod
    def encrypt_post_data(plaintext, ecc_public_key):
        """
        Encrypt post data using ECC
        Returns: (ciphertext_b64, hmac_tag_b64)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Encrypt using ECC
        ciphertext = ECCEncryption.encrypt(plaintext, ecc_public_key)
        
        # Create HMAC for integrity using the ECC public key material
        # The HMAC key is derived from the ECC public key X coordinate so it can be verified later
        hmac_key = HMACIntegrity._compute_hmac_raw(
            ecc_public_key["x"].to_bytes(32, 'big'),
            b'HMAC-KEY'
        )
        hmac_tag = HMACIntegrity.create_mac(ciphertext.encode('utf-8'), hmac_key)
        
        return ciphertext, hmac_tag
    
    @staticmethod
    def decrypt_post_data(ciphertext, hmac_tag, ecc_private_key, verify_integrity=True):
        """
        Decrypt post data using ECC
        Verifies HMAC integrity if verify_integrity=True
        Returns: plaintext
        """
        # Derive HMAC key from the public key coordinates stored in the private key dict
        # The ECC private key dict includes x and y coordinates of the public key
        hmac_key = HMACIntegrity._compute_hmac_raw(
            ecc_private_key["x"].to_bytes(32, 'big'),
            b'HMAC-KEY'
        )
        
        # Verify HMAC if requested
        if verify_integrity:
            expected_hmac = hmac_tag
            computed_hmac = HMACIntegrity.create_mac(ciphertext.encode('utf-8'), hmac_key)
            if not HMACIntegrity._constant_time_compare(
                computed_hmac.encode('utf-8'),
                expected_hmac.encode('utf-8')
            ):
                raise ValueError("HMAC verification failed - post data compromised")
        
        # Decrypt using ECC
        plaintext = ECCEncryption.decrypt(ciphertext, ecc_private_key)
        
        return plaintext
    
    @staticmethod
    def hash_password(password, salt=None):
        """Hash and salt password using PBKDF2"""
        return PasswordHashing.hash_password(password, salt)
    
    @staticmethod
    def verify_password(password, salt, hash_value):
        """Verify password against hash"""
        return PasswordHashing.verify_password(password, salt, hash_value)
