#!/usr/bin/env python3
"""
Migrate old XOR-encrypted user data to new RSA encryption
This script:
1. Finds users with XOR-encrypted data
2. Uses the plaintext fields to re-encrypt with RSA
3. Clears the old XOR-encrypted fields
Run: python3 migrate_user_xor_to_rsa.py
"""
import sys
sys.path.insert(0, '/Users/ayeshaparpiaabontee/Desktop/Lost-FoundTracking-Project')

from app import app, db
from app.models.user import User
from app.services.key_management_service import KeyManagementService
from app.services.data_encryption_service import DataEncryptionService
import json

with app.app_context():
    users = User.query.all()
    
    if not users:
        print("✅ No users to migrate")
        sys.exit(0)
    
    print(f"\n🔄 Migrating {len(users)} users from XOR → RSA encryption...")
    print("="*80)
    
    migrated = 0
    already_rsa = 0
    skipped = 0
    failed = 0
    
    for user in users:
        try:
            print(f"👤 User {user.id} ({user.name}):", end=" ")
            
            # Skip users without encrypted data
            if not user.name_encrypted and not user.email_encrypted:
                print("⏭️  No encrypted data (skip)")
                skipped += 1
                continue
            
            # Try to decrypt old XOR-encrypted data
            # If it fails, it's already RSA-encrypted
            try:
                # Check if it's valid RSA ciphertext by trying to parse
                json.loads(user.name_encrypted) if user.name_encrypted else None
                print("⏭️  Already RSA-encrypted (skip)")
                already_rsa += 1
                continue
            except:
                # Not JSON = probably old XOR format
                pass
            
            # Get user's keys
            keys = KeyManagementService.retrieve_keys(
                user_id=user.id,
                master_password="default-key-encryption"
            )
            rsa_public_key = keys['rsa_public']
            ecc_public_key = keys['ecc_public']
            
            # Re-encrypt plaintext fields with RSA
            migrated_fields = []
            
            if user.name:
                name_enc, name_hmac = DataEncryptionService.encrypt_user_data(
                    user.name, rsa_public_key, ecc_public_key
                )
                user.name_encrypted = name_enc
                user.name_hmac = name_hmac
                migrated_fields.append("name")
            
            if user.email:
                email_enc, email_hmac = DataEncryptionService.encrypt_user_data(
                    user.email, rsa_public_key, ecc_public_key
                )
                user.email_encrypted = email_enc
                user.email_hmac = email_hmac
                migrated_fields.append("email")
            
            db.session.commit()
            print(f"✅ Migrated ({', '.join(migrated_fields)})")
            migrated += 1
            
        except Exception as e:
            print(f"❌ Error: {str(e)[:50]}")
            failed += 1
            db.session.rollback()
    
    print("\n" + "="*80)
    print(f"✅ Migrated: {migrated}")
    print(f"⏭️  Already RSA: {already_rsa}")
    print(f"⏭️  Skipped (no data): {skipped}")
    print(f"❌ Failed: {failed}")
    print("="*80 + "\n")
    
    if migrated > 0:
        print("✅ User data migration complete!")
        print("   All users now use RSA asymmetric encryption (no more XOR)")
    else:
        print("ℹ️  No users needed migration (already RSA or no encrypted data)")
