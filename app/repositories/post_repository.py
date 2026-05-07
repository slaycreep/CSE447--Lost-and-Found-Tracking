from app.models.post import Post
from app import db
from sqlalchemy import or_, and_
from datetime import datetime
from app.services.key_management_service import KeyManagementService
from app.services.data_encryption_service import DataEncryptionService


class PostRepository:
    @staticmethod
    def _decrypt_post(post):
        """
        Decrypt post data using user's ECC keypair
        Attaches decrypted data as properties to the post object
        """
        if not post:
            return post
        
        try:
            decrypted = post.get_decrypted_data()
            # Attach decrypted data to post object
            post._decrypted_description = decrypted.get('description', post.description)
            post._decrypted_item_name = decrypted.get('item_name', post.item_name)
            post._decrypted_location = decrypted.get('location', post.location)
            post._decrypted_contact_method = decrypted.get('contact_method', post.contact_method)
        except Exception as e:
            # If decryption fails, use plaintext
            post._decrypted_description = post.description
            post._decrypted_item_name = post.item_name
            post._decrypted_location = post.location
            post._decrypted_contact_method = post.contact_method
        
        return post
    
    def get_by_type(self, type_name):
        posts = (
            Post.query.filter_by(type=type_name).order_by(Post.post_date.desc()).all()
        )
        return [self._decrypt_post(post) for post in posts]

    def get_by_id(self, post_id):
        post = Post.query.get_or_404(post_id)
        return self._decrypt_post(post)

    def create(self, data):
        """
        Create post with automatic encryption of sensitive fields
        Expects: description, item_name, location, contact_method in data
        """
        user_id = data.get('user_id')
        
        # Get user's ECC public key for encryption
        try:
            keys = KeyManagementService.retrieve_keys(
                user_id=user_id,
                master_password="default-key-encryption"
            )
            ecc_public_key = keys['ecc_public']
            
            # Encrypt sensitive post fields
            if data.get('description'):
                desc_enc, desc_hmac = DataEncryptionService.encrypt_post_data(
                    data['description'], ecc_public_key
                )
                data['description_encrypted'] = desc_enc
                data['description_hmac'] = desc_hmac
            
            if data.get('item_name'):
                item_enc, item_hmac = DataEncryptionService.encrypt_post_data(
                    data['item_name'], ecc_public_key
                )
                data['item_name_encrypted'] = item_enc
                data['item_name_hmac'] = item_hmac
            
            if data.get('location'):
                loc_enc, loc_hmac = DataEncryptionService.encrypt_post_data(
                    data['location'], ecc_public_key
                )
                data['location_encrypted'] = loc_enc
                data['location_hmac'] = loc_hmac
            
            if data.get('contact_method'):
                contact_enc, contact_hmac = DataEncryptionService.encrypt_post_data(
                    data['contact_method'], ecc_public_key
                )
                data['contact_method_encrypted'] = contact_enc
                data['contact_method_hmac'] = contact_hmac
        
        except Exception as e:
            # If encryption fails, store as plaintext (fallback)
            pass
        
        post = Post(**data)
        db.session.add(post)
        db.session.commit()
        return self._decrypt_post(post)

    def update(self, post):
        db.session.commit()
        return self._decrypt_post(post)

    def delete(self, post):
        db.session.delete(post)
        db.session.commit()

    def get_by_user_id(self, user_id):
        posts = Post.query.filter_by(user_id=user_id).all()
        return [self._decrypt_post(post) for post in posts]

    def get_recent(self, limit):
        posts = Post.query.order_by(Post.post_date.desc()).limit(limit).all()
        return [self._decrypt_post(post) for post in posts]

    def get_by_type_and_user(self, type_name, user_id):
        posts = (
            Post.query.filter_by(type=type_name, user_id=user_id)
            .order_by(Post.post_date.desc())
            .all()
        )
        return [self._decrypt_post(post) for post in posts]

    def search(self, query, filters=None):
        """
        Search posts with advanced filtering
        """
        search = f"%{query}%"
        base_query = Post.query.filter(
            or_(
                Post.item_name.ilike(search),
                Post.description.ilike(search),
                Post.category_name.ilike(search),
                Post.location.ilike(search),
            )
        )

        if filters:
            if filters.get("type"):
                base_query = base_query.filter(Post.type == filters["type"])

            if filters.get("category"):
                base_query = base_query.filter(
                    Post.category_name == filters["category"]
                )

            if filters.get("location"):
                location_search = f"%{filters['location']}%"
                base_query = base_query.filter(Post.location.ilike(location_search))

            if filters.get("date_from"):
                try:
                    date_from = datetime.strptime(filters["date_from"], "%Y-%m-%d")
                    base_query = base_query.filter(Post.lOrF_date >= date_from)
                except ValueError:
                    pass

            if filters.get("date_to"):
                try:
                    date_to = datetime.strptime(filters["date_to"], "%Y-%m-%d")
                    base_query = base_query.filter(Post.lOrF_date <= date_to)
                except ValueError:
                    pass

        print("SQL Query:", str(base_query))  # Debug print
        results = base_query.order_by(Post.post_date.desc()).all()
        print("Results count:", len(results))  # Debug print
        return [self._decrypt_post(post) for post in results]

    def count_user_posts(self, user_id, type_name=None):
        query = Post.query.filter_by(user_id=user_id)
        if type_name:
            query = query.filter_by(type=type_name)
        return query.count()

    def count_all(self):
        return Post.query.count()

    def update_status(self, post_id, new_status):
        post = self.get_by_id(post_id)
        if post:
            post.status = new_status
            db.session.commit()
            return True
        return False

    def delete_by_id(self, post_id):
        post = self.get_by_id(post_id)
        if post:
            db.session.delete(post)
            db.session.commit()
            return True
        return False
