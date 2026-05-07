#!/usr/bin/env python3
from app import app, db
from app.models.user import User
from app.models.user_keys import UserKeys

with app.app_context():
    user = User.query.filter_by(email='ayeshaabontee@gmail.com').first()
    if user:
        print('[USER FOUND]')
        print('=' * 60)
        print('=== USER DATA (ENCRYPTED IN DB) ===')
        print(f'ID: {user.id}')
        print(f'Email field: {user.email}')
        print(f'Name encrypted: {user.name_encrypted[:60]}...')
        print(f'Email encrypted: {user.email_encrypted[:60]}...')
        print()
        
        keys = UserKeys.query.filter_by(user_id=user.id).first()
        if keys:
            print('=== KEY DATA (ENCRYPTED IN DB) ===')
            print(f'Key version: {keys.key_version}')
            print(f'RSA public key N bits: {keys.get_rsa_public_key()["n"].bit_length()}')
            print(f'RSA private encrypted: {keys.rsa_private_key_encrypted[:60]}...')
            print(f'ECC private encrypted: {keys.ecc_private_key_encrypted[:60]}...')
            print()
            
            print('=== DECRYPTION TEST ===')
            decrypted = user.get_decrypted_data()
            print(f'[OK] Name (decrypted): {decrypted["name"]}')
            print(f'[OK] Email (decrypted): {decrypted["email"]}')
            print(f'[OK] Contact (decrypted): {decrypted["contact_info"]}')
        else:
            print('[ERROR] No keys found for this user')
    else:
        print('[NOT FOUND] User not found with email: ayeshaabontee@gmail.com')
        print('\nAvailable users:')
        users = User.query.all()
        for u in users[-5:]:
            print(f'  - ID {u.id}: {u.email}')
