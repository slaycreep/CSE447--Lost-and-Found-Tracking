#!/usr/bin/env python3
"""
Migration script: Convert user data from RSA encryption to ECC encryption
Run this after updating to the new ECC-based encryption system

Usage:
    python3 migrate_user_data_rsa_to_ecc.py
"""

import sys
from app import app, db
from app.models.user import User
from app.services.data_encryption_service import DataEncryptionService
from app.services.key_management_service import KeyManagementService
from app.utils.encryption_algorithms import HMACIntegrity, RSAEncryption, ECCEncryption

def migrate_user_data_to_ecc():
    """
    Migrate all user data from old RSA encryption to new ECC encryption
    """
    with app.app_context():
        users = User.query.all()
        total_users = len(users)
        migrated = 0
        skipped = 0
        errors = 0
        
        print(f"\n{'='*70}")
        print(f"MIGRATING USER DATA: RSA → ECC")
        print(f"{'='*70}")
        print(f"Total users to process: {total_users}\n")
        
        for idx, user in enumerate(users, 1):
            try:
                # Retrieve the user's keys
                keys = KeyManagementService.retrieve_keys(
                    user_id=user.id,
                    master_password="default-key-encryption"
                )
                ecc_public_key = keys['ecc_public']
                rsa_private_key = keys['rsa_private']
                
                # Try to detect if data is old (RSA) format
                needs_migration = False
                
                # Check if data needs migration - try RSA-specific decryption
                if user.name_encrypted and user.name_hmac:
                    try:
                        # Try decrypting with RSA HMAC only (no ECC HMAC verification)
                        hmac_key_rsa = HMACIntegrity._compute_hmac_raw(
                            rsa_private_key["n"].to_bytes(256, 'big'),
                            b'HMAC-KEY'
                        )
                        computed_hmac = HMACIntegrity.create_mac(user.name_encrypted.encode('utf-8'), hmac_key_rsa)
                        if HMACIntegrity._constant_time_compare(
                            computed_hmac.encode('utf-8'),
                            user.name_hmac.encode('utf-8')
                        ):
                            # RSA HMAC matched - this is old format
                            needs_migration = True
                    except:
                        pass
                
                if not needs_migration:
                    skipped += 1
                    print(f"[{idx}/{total_users}] User {user.id} ({user.email}): ALREADY ECC ✓")
                    continue
                
                # Migrate the data - decrypt and re-encrypt with ECC
                print(f"[{idx}/{total_users}] User {user.id} ({user.email}): MIGRATING...", end=" ")
                
                # Decrypt all fields using RSA directly (not the fallback system)
                if user.name_encrypted and user.name_hmac:
                    try:
                        decrypted_name = RSAEncryption.decrypt(user.name_encrypted, rsa_private_key)
                    except Exception as e:
                        print(f"\n  [WARN] Could not decrypt name: {str(e)}", file=sys.stderr)
                        decrypted_name = user.name
                else:
                    decrypted_name = user.name
                
                if user.email_encrypted and user.email_hmac:
                    try:
                        decrypted_email = RSAEncryption.decrypt(user.email_encrypted, rsa_private_key)
                    except Exception as e:
                        print(f"  [WARN] Could not decrypt email: {str(e)}", file=sys.stderr)
                        decrypted_email = user.email
                else:
                    decrypted_email = user.email
                
                if user.contact_info_encrypted and user.contact_info_hmac:
                    try:
                        decrypted_contact = RSAEncryption.decrypt(user.contact_info_encrypted, rsa_private_key)
                    except Exception as e:
                        print(f"  [WARN] Could not decrypt contact: {str(e)}", file=sys.stderr)
                        decrypted_contact = ""
                else:
                    decrypted_contact = ""
                
                # Re-encrypt with ECC (new method)
                rsa_public_key = keys['rsa_public']  # For compatibility, even though we use ECC
                
                name_encrypted, name_hmac = DataEncryptionService.encrypt_user_data(
                    decrypted_name, rsa_public_key, ecc_public_key
                )
                email_encrypted, email_hmac = DataEncryptionService.encrypt_user_data(
                    decrypted_email, rsa_public_key, ecc_public_key
                )
                contact_encrypted, contact_hmac = DataEncryptionService.encrypt_user_data(
                    decrypted_contact, rsa_public_key, ecc_public_key
                )
                
                # Update database with new ECC-encrypted data
                user.name_encrypted = name_encrypted
                user.name_hmac = name_hmac
                user.email_encrypted = email_encrypted
                user.email_hmac = email_hmac
                user.contact_info_encrypted = contact_encrypted
                user.contact_info_hmac = contact_hmac
                
                db.session.commit()
                
                migrated += 1
                print("✓ MIGRATED")
                
            except Exception as e:
                errors += 1
                print(f"✗ ERROR: {str(e)}")
                print(f"  [DEBUG] User ID: {user.id}, Name encrypted: {bool(user.name_encrypted)}, Email encrypted: {bool(user.email_encrypted)}", file=sys.stderr)
                db.session.rollback()
        
        print(f"\n{'='*70}")
        print(f"MIGRATION COMPLETE")
        print(f"{'='*70}")
        print(f"✓ Migrated:  {migrated}")
        print(f"⊘ Skipped:   {skipped} (already ECC)")
        print(f"✗ Errors:    {errors}")
        print(f"Total:       {migrated + skipped + errors}/{total_users}")
        print(f"{'='*70}\n")

if __name__ == "__main__":
    migrate_user_data_to_ecc()
