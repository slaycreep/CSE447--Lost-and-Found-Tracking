from app import db, socketio
from datetime import datetime

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Legacy plaintext message (DEPRECATED - kept for backward compatibility)
    message = db.Column(db.Text, nullable=True)
    
    # Encrypted message fields
    message_encrypted = db.Column(db.Text, nullable=True)  # Base64-encoded ECC-encrypted message
    message_hmac = db.Column(db.String(256), nullable=True)  # HMAC tag for integrity verification
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_chats')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_chats')

    @classmethod
    def mark_messages_read(cls, post_id, user_id):
        """Class method to mark messages as read and emit the update"""
        messages = cls.query.filter_by(
            post_id=post_id,
            receiver_id=user_id,
            is_read=False
        ).all()

        if messages:
            for message in messages:
                message.is_read = True
            db.session.commit()

            # Emit to all clients in the room
            socketio.emit('messages_read', {
                'post_id': post_id,
                'reader_id': user_id,
                'room': f'post_{post_id}'
            })

        return len(messages)
    
    def get_decrypted_message(self):
        """
        Decrypt message using receiver's ECC private key
        Returns decrypted message text or plaintext message for backward compatibility
        """
        from app.services.key_management_service import KeyManagementService
        from app.services.data_encryption_service import DataEncryptionService
        
        try:
            # If encrypted, decrypt using receiver's private key
            if self.message_encrypted and self.message_hmac:
                keys = KeyManagementService.retrieve_keys(
                    user_id=self.receiver_id,
                    master_password="default-key-encryption"
                )
                ecc_private_key = keys['ecc_private']
                
                # Decrypt message
                decrypted = DataEncryptionService.decrypt_post_data(
                    self.message_encrypted,
                    self.message_hmac,
                    ecc_private_key
                )
                return decrypted
            # Fallback to plaintext message for backward compatibility
            elif self.message:
                return self.message
            else:
                return "[Message unavailable]"
        except Exception as e:
            # Log error and return fallback
            print(f"Error decrypting message {self.id}: {str(e)}")
            return self.message if self.message else "[Message unavailable]"

