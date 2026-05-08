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
        Encrypt user data using ECC (no message size limit)
        Also creates HMAC tag for integrity verification
        Returns: (ciphertext_b64, hmac_tag_b64)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Encrypt using ECC (handles arbitrary message sizes)
        ciphertext = ECCEncryption.encrypt(plaintext, ecc_public_key)
        
        # Create HMAC for integrity verification using the ECC public key material
        # The HMAC key is derived from the ECC public key X coordinate
        hmac_key = HMACIntegrity._compute_hmac_raw(
            ecc_public_key["x"].to_bytes(32, 'big'),
            b'HMAC-KEY'
        )
        hmac_tag = HMACIntegrity.create_mac(ciphertext.encode('utf-8'), hmac_key)
        
        # Return both ciphertext and HMAC tag
        return ciphertext, hmac_tag
    
    @staticmethod
    def decrypt_user_data(ciphertext, hmac_tag, ecc_private_key=None, rsa_private_key=None, verify_integrity=True):
        """
        Decrypt user data using ECC private key (new) or RSA (legacy backward compatibility)
        Tries ECC first, falls back to RSA for old encrypted data
        Verifies HMAC integrity if verify_integrity=True
        Returns: plaintext
        """
        ecc_error = None
        rsa_error = None
        
        # Try ECC decryption first (new system) if ECC key is provided
        if ecc_private_key:
            try:
                # Derive HMAC key from ECC private key's public key coordinates
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
                        raise ValueError("HMAC verification failed - data may be RSA encrypted")
                
                # Decrypt using ECC
                plaintext = ECCEncryption.decrypt(ciphertext, ecc_private_key)
                return plaintext
            except Exception as e:
                ecc_error = e
                # Fall through to try RSA
        
        # Try RSA decryption (legacy data) if RSA key is provided and ECC failed
        if rsa_private_key:
            try:
                # Derive HMAC key from RSA private key's modulus (legacy)
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
                
                # Decrypt using RSA (legacy)
                plaintext = RSAEncryption.decrypt(ciphertext, rsa_private_key)
                # Log that we're using legacy RSA decryption for this data
                import sys
                print(f"[MIGRATION] Decrypted user data using legacy RSA - should be re-encrypted to ECC", file=sys.stderr)
                return plaintext
            except Exception as e:
                rsa_error = e
        
        # If both failed, report the most likely error
        if ecc_error and rsa_error:
            raise ValueError(f"Failed to decrypt with both ECC ({str(ecc_error)}) and RSA ({str(rsa_error)})")
        elif ecc_error:
            raise ecc_error
        elif rsa_error:
            raise rsa_error
        else:
            raise ValueError("Either ecc_private_key or rsa_private_key must be provided")
    
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
    def encrypt_contact_info_with_rsa(plaintext, rsa_public_key):
        """
        Encrypt contact information using RSA-2048 with OAEP-SHA256
        Contact info is encrypted separately using RSA for demonstration of both algorithms
        Returns: (ciphertext_b64, hmac_tag_b64)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Encrypt using RSA (handles fixed message sizes up to ~214 bytes with OAEP)
        ciphertext = RSAEncryption.encrypt(plaintext, rsa_public_key)
        
        # Create HMAC for integrity verification using the RSA public key material
        # The HMAC key is derived from the RSA modulus
        hmac_key = HMACIntegrity._compute_hmac_raw(
            rsa_public_key["n"].to_bytes(256, 'big'),
            b'HMAC-KEY-RSA'
        )
        hmac_tag = HMACIntegrity.create_mac(ciphertext.encode('utf-8'), hmac_key)
        
        return ciphertext, hmac_tag
    
    @staticmethod
    def decrypt_contact_info_with_rsa(ciphertext, hmac_tag, rsa_private_key, verify_integrity=True):
        """
        Decrypt contact information encrypted with RSA-2048
        Verifies HMAC integrity if verify_integrity=True
        Returns: plaintext
        """
        # Derive HMAC key from RSA private key's modulus
        hmac_key = HMACIntegrity._compute_hmac_raw(
            rsa_private_key["n"].to_bytes(256, 'big'),
            b'HMAC-KEY-RSA'
        )
        
        # Verify HMAC if requested
        if verify_integrity:
            expected_hmac = hmac_tag
            computed_hmac = HMACIntegrity.create_mac(ciphertext.encode('utf-8'), hmac_key)
            if not HMACIntegrity._constant_time_compare(
                computed_hmac.encode('utf-8'),
                expected_hmac.encode('utf-8')
            ):
                raise ValueError("HMAC verification failed - contact info data compromised")
        
        # Decrypt using RSA
        plaintext = RSAEncryption.decrypt(ciphertext, rsa_private_key)
        
        return plaintext
    
    @staticmethod
    def hash_password(password, salt=None):
        """Hash and salt password using PBKDF2"""
        return PasswordHashing.hash_password(password, salt)
    
    @staticmethod
    def verify_password(password, salt, hash_value):
        """Verify password against hash"""
        return PasswordHashing.verify_password(password, salt, hash_value)
