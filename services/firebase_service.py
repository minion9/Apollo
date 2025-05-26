from google.cloud import firestore
from google.cloud import storage
from google.oauth2 import service_account
import datetime
import uuid
from dotenv import load_dotenv
import os
import json
import re

load_dotenv()

class FirebaseService:
    def __init__(self):
        # Get Firebase credentials from environment variables
        project_id = os.getenv('FIREBASE_PROJECT_ID')
        
        # Read individual credentials from environment variables
        credentials_dict = {
            "type": "service_account",
            "project_id": project_id,
            "private_key_id": os.getenv('FIREBASE_PRIVATE_KEY_ID'),
            "private_key": os.getenv('FIREBASE_PRIVATE_KEY').replace('\\n', '\n'),
            "client_email": os.getenv('FIREBASE_CLIENT_EMAIL'),
            "client_id": os.getenv('FIREBASE_CLIENT_ID'),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": os.getenv('FIREBASE_CLIENT_CERT_URL')
        }
        
        # Create credentials object from the dictionary
        try:
            credentials = service_account.Credentials.from_service_account_info(credentials_dict)
        except Exception as e:
            print(f"Error creating credentials from environment variables: {e}")
            # Fall back to service account file if available
            service_account_file = os.getenv('GOOGLE_APPLICATION_CREDENTIAL')
            if service_account_file and os.path.exists(service_account_file):
                try:
                    credentials = service_account.Credentials.from_service_account_file(service_account_file)
                    print("Using service account file for authentication")
                except Exception as e:
                    print(f"Error loading service account file: {e}")
                    credentials = None
            else:
                credentials = None
                print("No valid credentials available")
        
        # Initialize Firestore with credentials
        self.db = firestore.Client(
            project=project_id,
            credentials=credentials
        )
        
        # Initialize Storage with credentials
        self.storage = storage.Client(
            project=project_id,
            credentials=credentials
        )
        
        self.users_ref = self.db.collection('users')
        
        # Get bucket name from environment variable
        bucket_name = os.getenv('FIREBASE_STORAGE_BUCKET')
        self.bucket = self.storage.bucket(bucket_name)
    
    def _convert_firestore_dates(self, user_data):
        """Convert Firestore datetime objects to proper format for API responses"""
        if user_data and isinstance(user_data, dict):
            # Handle DOB conversion - always return as YYYY-MM-DD string
            if 'dob' in user_data and user_data['dob']:
                dob = user_data['dob']
                try:
                    if isinstance(dob, datetime.datetime):
                        user_data['dob'] = dob.date().isoformat()
                    elif isinstance(dob, datetime.date):
                        user_data['dob'] = dob.isoformat()
                    elif isinstance(dob, str):
                        # Validate the date string format
                        datetime.datetime.strptime(dob, '%Y-%m-%d')
                        # If valid, keep as is
                except (ValueError, TypeError):
                    # If invalid format, remove the field
                    user_data['dob'] = None
            
            # Handle other datetime fields
            datetime_fields = ['createdAt', 'updatedAt', 'lastLogin']
            for field in datetime_fields:
                if field in user_data and user_data[field]:
                    if hasattr(user_data[field], 'isoformat'):
                        user_data[field] = user_data[field].isoformat()
        
        return user_data
        
    def get_user_by_email(self, email):
        query = self.users_ref.where('email', '==', email).limit(1)
        users = query.stream()
        for user in users:
            user_data = user.to_dict() | {'id': user.id}
            return self._convert_firestore_dates(user_data)
        return None
        
    def get_user_by_username(self, username):
        query = self.users_ref.where('username', '==', username).limit(1)
        users = query.stream()
        for user in users:
            user_data = user.to_dict() | {'id': user.id}
            return self._convert_firestore_dates(user_data)
        return None
        
    def get_user_by_id(self, user_id):
        user_ref = self.users_ref.document(user_id)
        user = user_ref.get()
        if user.exists:
            user_data = user.to_dict() | {'id': user.id}
            return self._convert_firestore_dates(user_data)
        return None
        
    def create_user(self, user_data):
        # Handle DOB conversion before saving
        if 'dob' in user_data and user_data['dob']:
            dob_value = user_data['dob']
            if isinstance(dob_value, str):
                try:
                    # Parse string date to datetime object
                    if 'T' in dob_value:
                        parsed_date = datetime.datetime.fromisoformat(dob_value.replace('Z', '+00:00'))
                    else:
                        parsed_date = datetime.datetime.strptime(dob_value, '%Y-%m-%d')
                    
                    # Store as date only
                    user_data['dob'] = parsed_date.date()
                except (ValueError, TypeError):
                    # If parsing fails, remove the DOB field
                    del user_data['dob']
        
        # Ensure timestamps are datetime objects
        if 'createdAt' not in user_data:
            user_data['createdAt'] = datetime.datetime.utcnow()
        if 'updatedAt' not in user_data:
            user_data['updatedAt'] = datetime.datetime.utcnow()
        
        # Create a new user document with auto-generated ID
        new_user_ref = self.users_ref.document()
        new_user_ref.set(user_data)
        return new_user_ref.id
        
    def update_user(self, user_id, update_data):
        # Handle date conversions in update data
        processed_data = update_data.copy()
        
        # Handle DOB if present - store as YYYY-MM-DD string
        if 'dob' in processed_data and processed_data['dob']:
            dob_value = processed_data['dob']
            try:
                if isinstance(dob_value, datetime.date):
                    processed_data['dob'] = dob_value.isoformat()
                elif isinstance(dob_value, datetime.datetime):
                    processed_data['dob'] = dob_value.date().isoformat()
                elif isinstance(dob_value, str):
                    # Parse and validate the date string
                    if 'T' in dob_value:
                        # Remove time component if present
                        date_obj = datetime.datetime.fromisoformat(dob_value.replace('Z', '+00:00'))
                        processed_data['dob'] = date_obj.date().isoformat()
                    else:
                        # Validate the date format
                        datetime.datetime.strptime(dob_value, '%Y-%m-%d')
                        # If valid, keep as is
                        processed_data['dob'] = dob_value
            except (ValueError, TypeError) as e:
                print(f"Error processing DOB: {e}")
                # If parsing fails, remove the DOB field
                del processed_data['dob']
        
        # Handle other datetime fields
        if 'updatedAt' in processed_data:
            processed_data['updatedAt'] = datetime.datetime.utcnow()
        
        # Update the document
        user_ref = self.users_ref.document(user_id)
        user_ref.update(processed_data)
        return True
        
    def update_login_history(self, user_id, login_data):
        user_ref = self.users_ref.document(user_id)
        user = user_ref.get()
        if user.exists:
            user_data = user.to_dict()
            login_history = user_data.get('loginHistory', [])
            login_history.append(login_data)
            user_ref.update({
                'loginHistory': login_history,
                'lastLogin': datetime.datetime.utcnow()
            })
            return True
        return False
        
    def upload_avatar(self, user_id, file_stream, content_type):
        # Create a unique blob name for the user's avatar
        blob_name = f"avatars/{user_id}/{uuid.uuid4()}"
        blob = self.bucket.blob(blob_name)
        
        # Upload the file
        blob.upload_from_file(file_stream, content_type=content_type)
        
        # Make the blob publicly accessible
        blob.make_public()
        
        return blob.public_url
    
    def delete_avatar(self, user_id):
        """Delete all avatar files for a specific user from storage"""
        # List all avatar blobs for the user
        prefix = f"avatars/{user_id}/"
        blobs = self.bucket.list_blobs(prefix=prefix)
        
        # Delete each blob
        for blob in blobs:
            blob.delete()
        
        return True
    
    def delete_user(self, user_id):
        """Delete a user and all associated data"""
        # Delete from Firestore
        user_ref = self.users_ref.document(user_id)
        
        # Delete any other collections or documents related to this user
        # Example: Delete posts by this user
        # posts_ref = self.db.collection('posts').where('authorId', '==', user_id)
        # self._delete_collection(posts_ref, 100)
        
        # Finally delete the user document
        user_ref.delete()
        
        return True
    
    def _delete_collection(self, collection_ref, batch_size):
        """Helper method to delete a collection and all its documents"""
        docs = collection_ref.limit(batch_size).stream()
        deleted = 0
        
        for doc in docs:
            doc.reference.delete()
            deleted += 1
            
        if deleted >= batch_size:
            return self._delete_collection(collection_ref, batch_size)
    
    def delete_login_history_entry(self, user_id, login_id):
        """Delete a specific login history entry for a user"""
        user_ref = self.users_ref.document(user_id)
        user = user_ref.get()
        
        if not user.exists:
            return False
        
        user_data = user.to_dict()
        login_history = user_data.get('loginHistory', [])
        
        # Find and remove the specific login entry
        for i, entry in enumerate(login_history):
            if entry.get('id') == login_id:
                login_history.pop(i)
                user_ref.update({'loginHistory': login_history})
                return True
        
        return False
    
    def get_all_users(self, current_user):
        """Get all users - basic implementation"""
        users = []
        docs = self.users_ref.stream()
        
        for doc in docs:
            user_data = doc.to_dict()
            user_data = self._convert_firestore_dates(user_data | {'id': doc.id})
            users.append(user_data)
            
        return users
    
    def get_users_paginated(self, current_user, limit=10, skip=0, sort_by='createdAt', 
                           sort_direction='desc', filters=None, search_term=None, 
                           search_fields=None, tags=None):
        """
        Get users with pagination, sorting, filtering, and search capabilities
        
        Args:
            current_user: The user making the request
            limit: Maximum number of results to return
            skip: Number of results to skip (for pagination)
            sort_by: Field to sort by
            sort_direction: Direction to sort ('asc' or 'desc')
            filters: Dictionary of field:value pairs to filter by
            search_term: Term to search for
            search_fields: List of fields to search in
            tags: List of tags to filter by
            
        Returns:
            Tuple of (users_list, total_count)
        """
        # Start with base query
        query = self.users_ref
        
        # Apply filters if provided
        if filters:
            for field, value in filters.items():
                query = query.where(field, '==', value)
        
        # Apply tag filtering if provided
        if tags and len(tags) > 0:
            query = query.where('tags', 'array_contains_any', tags)
        
        # Get the total count before pagination
        # Note: Firestore doesn't support COUNT queries, so we need to fetch all documents
        # that match the filter criteria and count them
        # This can be optimized with a counter document in production
        total_docs = list(query.stream())
        total_count = len(total_docs)
        
        # Apply sorting
        if sort_by:
            direction = firestore.Query.DESCENDING if sort_direction == 'desc' else firestore.Query.ASCENDING
            query = query.order_by(sort_by, direction=direction)
        
        # Apply pagination
        # Since Firestore doesn't directly support offset/skip, we need to get all documents
        # and then slice them
        # This is not efficient for large collections and should be improved in production
        # using cursor-based pagination with startAfter()
        all_docs = list(query.stream())
        paginated_docs = all_docs[skip:skip+limit]
        
        # Process the results
        users = []
        
        # If search is requested
        if search_term and search_fields:
            # Convert search term to lowercase for case-insensitive search
            search_term = search_term.lower()
            
            # Iterate through the paginated documents
            for doc in paginated_docs:
                user_data = doc.to_dict()
                user_data['id'] = doc.id
                user_data = self._convert_firestore_dates(user_data)
                
                # Check if any of the search fields contain the search term
                matches_search = False
                for field in search_fields:
                    if field in user_data:
                        field_value = str(user_data[field]).lower()
                        if search_term in field_value:
                            matches_search = True
                            break
                
                # Add user to results if it matches the search
                if matches_search:
                    users.append(user_data)
        else:
            # If no search requested, add all paginated users
            for doc in paginated_docs:
                user_data = doc.to_dict()
                user_data = self._convert_firestore_dates(user_data | {'id': doc.id})
                users.append(user_data)
        
        return users, total_count
        
    def check_database_health(self):
        try:
            # Try to query a small amount of data to check DB connection
            self.db.collection('health_check').document('status').get()
            return True
        except Exception as e:
            print(f"Database health check failed: {str(e)}")
            return False
        
    def check_storage_health(self):
        try:
            # List blobs to check storage connection
            blobs = list(self.bucket.list_blobs(max_results=1))
            # If we get here, connection is working even if no blobs exist
            return True
        except Exception as e:
            print(f"Storage health check failed: {str(e)}")
            return False

# Singleton pattern for Firebase service
firebase_service = FirebaseService()