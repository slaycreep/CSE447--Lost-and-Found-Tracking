#!/usr/bin/env python3
"""
Migration script: Convert contact info from ECC encryption to RSA-2048 encryption
Run this after updating DataEncryptionService with RSA contact info methods

Usage:
    python3 migrate_contact_info_ecc_to_rsa.py
"""

import sys
from app import app, db
from app.models.user import User
from app.services.data_encryption_service import DataEncryptionService
from app.services.key_management_service import KeyManagementService
from app.utils.encryption_algorithms import HMACIntegrity, ECCEncryption, RSAEncryption

def migrate_contact_info_to_rsa():
    """
    Migrate all contact info from ECC encryption to RSA-2048 encryption
    This assumes contact info is currently encrypted with ECC using HMAC key derived from ECC public key
    """
    with app.app_context():
        users = User.query.all()
        total_users = len(users)
        migrated = 0
        skipped = 0
        errors = 0
        
        print(f"\n{'='*70}")
        print(f"MIGRATING CONTACT INFO: ECC → RSA-2048")
        print(f"{'='*70}")
        print(f"Total users to process: {total_users}\n")
        
        for idx, user in enumerate(users, 1):
            try:
                # Skip if no contact info to migrate
                if not user.contact_info_encrypted or not user.contact_info_hmac:
                    skipped += 1
                    print(f"[{idx}/{total_users}] User {user.id} ({user.email}): NO CONTACT INFO (SKIPPED)")
                    continue
                
                # Retrieve the user's keys
                keys = KeyManagementService.retrieve_keys(
                    user_id=user.id,
                    master_password="default-key-encryption"
                )
                ecc_private_key = keys['ecc_private']
                rsa_public_key = keys['rsa_public']
                rsa_private_key = keys['rsa_private']
                
                print(f"[{idx}/{total_users}] User {user.id} ({user.email}): MIGRATING...", end=" ")
                
                # Decrypt contact info using ECC (current format)
                try:
                    decrypted_contact = DataEncryptionService.decrypt_post_data(
                        user.contact_info_encrypted,
                        user.contact_info_hmac,
                        ecc_private_key=ecc_private_key,
                        verify_integrity=True
                    )
                except Exception as e:
                    print(f"\n  [ERROR] Could not decrypt contact info: {str(e)}", file=sys.stderr)
                    errors += 1
                    continue
                
                # Re-encrypt with RSA-2048
                try:
                    new_contact_encrypted, new_contact_hmac = DataEncryptionService.encrypt_contact_info_with_rsa(
                        decrypted_contact,
                        rsa_public_key
                    )
                except Exception as e:
                    print(f"\n  [ERROR] Could not encrypt with RSA: {str(e)}", file=sys.stderr)
                    errors += 1
                    continue
                
                # Update the user record
                user.contact_info_encrypted = new_contact_encrypted
                user.contact_info_hmac = new_contact_hmac
                
                db.session.commit()
                migrated += 1
                print(f"✓ (ECC→RSA)")
                
            except Exception as e:
                print(f"\n  [UNEXPECTED ERROR] User {user.id}: {str(e)}", file=sys.stderr)
                errors += 1
                db.session.rollback()
        
        # Summary
        print(f"\n{'='*70}")
        print(f"MIGRATION SUMMARY")
        print(f"{'='*70}")
        print(f"✓ Successfully migrated: {migrated}/{total_users}")
        print(f"⊘ Skipped (no data):     {skipped}/{total_users}")
        print(f"✗ Errors:                {errors}/{total_users}")
        print(f"{'='*70}\n")
        
        if errors == 0:
            print("✓ Migration completed successfully!")
        else:
            print(f"⚠ Migration completed with {errors} error(s). Review the logs above.")
            sys.exit(1)

if __name__ == "__main__":
    try:
        migrate_contact_info_to_rsa()
    except Exception as e:
        print(f"\n✗ FATAL ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)
