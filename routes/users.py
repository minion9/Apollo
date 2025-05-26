from flask import request, jsonify
from werkzeug.security import generate_password_hash
from routes.auth import token_required
from services.firebase_service import firebase_service
from middleware.middleware import Middleware
from utils.password_utils import create_password_hash_and_salt, verify_password
import os
from datetime import datetime
from functools import wraps
from flask_caching import Cache
import re

# Initialize Flask-Caching
cache = Cache(config={'CACHE_TYPE': 'simple'})  # For production, use 'redis' or other backend

# Get cors origins from environment
def user_routes(app):
    # Initialize cache with app
    cache.init_app(app)
    
    # Helper function to generate cache key based on user
    def make_cache_key(*args, **kwargs):
        # Get current user from kwargs
        current_user = kwargs.get('current_user', {})
        # Create unique key based on user id and route path
        return f"user:{current_user.get('id', 'anonymous')}:{request.path}"
        
    @app.route('/api/users/', methods=['POST'])
    @Middleware.request_logger
    def create_user():
        # Clear user cache on creation
        cache.delete_memoized(get_all_users)
        
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No input data provided'}), 400
        
        # Required fields
        required_fields = ['firstName', 'lastName', 'username', 'email', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'message': f'Missing required field: {field}'}), 400
        
        # Check if username or email already exists
        if firebase_service.get_user_by_username(data['username']):
            return jsonify({'message': 'Username already exists'}), 409
        
        if firebase_service.get_user_by_email(data['email']):
            return jsonify({'message': 'Email already exists'}), 409
        
        # Create user object with required fields
        new_user = {
            'firstName': data['firstName'],
            'lastName': data['lastName'],
            'username': data['username'],
            'email': data['email'].lower(),
            'password': generate_password_hash(data['password']),
            'role': 'user',  # Default role
            'status': 'active',  # Default status
            'createdAt': datetime.utcnow().isoformat(),
            'updatedAt': datetime.utcnow().isoformat(),
            'lastLogin': None,
            'avatarUrl': None,
            'tags': [],
            'loginHistory': []
        }
        
        # Optional fields
        if 'phoneNumber' in data:
            new_user['phoneNumber'] = data['phoneNumber']
            
        if 'dob' in data:
            new_user['dob'] = data['dob']
            
        # Address fields
        if 'address' in data:
            new_user['address'] = {
                'street': data['address'].get('street'),
                'city': data['address'].get('city'),
                'state': data['address'].get('state'),
                'zipcode': data['address'].get('zipcode'),
                'country': data['address'].get('country')
            }
            
        # Settings fields with defaults
        new_user['settings'] = {
            'language': data.get('settings', {}).get('language', 'en'),
            'theme': data.get('settings', {}).get('theme', 'light'),
            'notifications': {
                'email': data.get('settings', {}).get('notifications', {}).get('email', True),
                'sms': data.get('settings', {}).get('notifications', {}).get('sms', False),
                'push': data.get('settings', {}).get('notifications', {}).get('push', True)
            }
        }
        
        # Create user in database
        user_id = firebase_service.create_user(new_user)
        
        return jsonify({
            'message': 'User created successfully',
            'userId': user_id
        }), 201

    @app.route('/api/users/', methods=['GET'])
    @token_required
    @Middleware.request_logger
    @cache.memoize(timeout=300)  # Cache for 5 minutes
    def get_current_user(current_user):
        # Return the current user's info with consistent fields
        return jsonify({
            'user': {
                'id': current_user['id'],
                'firstName': current_user['firstName'],
                'lastName': current_user['lastName'],
                'username': current_user['username'],
                'email': current_user['email'],
                'phoneNumber': current_user.get('phoneNumber'),
                'role': current_user.get('role', 'user'),
                'status': current_user.get('status', 'active'),
                'createdAt': current_user.get('createdAt'),
                'updatedAt': current_user.get('updatedAt'),
                'lastLogin': current_user.get('lastLogin'),
                'avatarUrl': current_user.get('avatarUrl'),
                'dob': current_user.get('dob'),
                'tags': current_user.get('tags', []),
                'address': current_user.get('address', {}),
                'settings': current_user.get('settings', {
                    'language': 'en',
                    'theme': 'light',
                    'notifications': {
                        'email': True,
                        'sms': False,
                        'push': True
                    }
                }),
                'loginHistory': current_user.get('loginHistory', [])
            }
        }), 200

    @app.route('/api/users/all', methods=['GET'])
    @token_required
    @Middleware.request_logger
    @Middleware.rate_limiter(limit=50, per=60)  # Rate limit admin endpoints more strictly
    @cache.cached(timeout=60, key_prefix=lambda: f"users_all_{request.args.to_dict()}")  # Cache with query params for 60 seconds
    def get_all_users(current_user):
        # Check permissions (only admins can access all users)
        if current_user['role'] != 'admin':
            return jsonify({'message': 'Unauthorized access. Admin privileges required.'}), 403
        
        # Parse pagination parameters
        limit = request.args.get('limit', default=10, type=int)
        skip = request.args.get('skip', default=0, type=int)
        
        # Parse sorting parameters
        sort_by = request.args.get('sortBy', default='createdAt', type=str)
        sort_direction = request.args.get('sortDirection', default='desc', type=str)
        
        # Parse filtering parameters
        filters = {}
        for param in ['role', 'firstName', 'lastName', 'email', 'status']:
            if param in request.args:
                filters[param] = request.args.get(param)
        
        # Parse search parameters
        search_term = request.args.get('search', default=None, type=str)
        search_fields = request.args.get('searchFields', default='firstName,lastName,email,username', type=str).split(',')
        
        # Parse tags filter
        tags = request.args.getlist('tags')
        
        # Get users from database with pagination, sorting, filtering, and search
        users, total_count = firebase_service.get_users_paginated(
            current_user=current_user,
            limit=limit,
            skip=skip,
            sort_by=sort_by,
            sort_direction=sort_direction,
            filters=filters,
            search_term=search_term,
            search_fields=search_fields,
            tags=tags
        )
        
        # Format response data with consistent fields
        formatted_users = []
        for user in users:
            formatted_users.append({
                'id': user['id'],
                'firstName': user['firstName'],
                'lastName': user['lastName'],
                'username': user['username'],
                'email': user['email'],
                'phoneNumber': user.get('phoneNumber'),
                'role': user.get('role', 'user'),
                'status': user.get('status', 'active'),
                'createdAt': user.get('createdAt'),
                'updatedAt': user.get('updatedAt'),
                'lastLogin': user.get('lastLogin'),
                'avatarUrl': user.get('avatarUrl'),
                'tags': user.get('tags', []),
                'dob': user.get('dob')
                # Note: We exclude address, settings, and loginHistory for the list view
            })
        
        return jsonify({
            'users': formatted_users,
            'total': total_count,
            'limit': limit,
            'skip': skip
        }), 200

    @app.route('/api/users/<user_id>', methods=['GET'])
    @token_required
    @Middleware.request_logger
    @cache.memoize(timeout=300)  # Cache for 5 minutes
    def get_user(current_user, user_id):
        # Check permissions (only admins or the user themselves)
        if current_user['role'] != 'admin' and current_user['id'] != user_id:
            return jsonify({'message': 'Unauthorized access'}), 403
        
        # Get user from database
        user = firebase_service.get_user_by_id(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Return user info with consistent fields
        return jsonify({
            'user': {
                'id': user['id'],
                'firstName': user['firstName'],
                'lastName': user['lastName'],
                'username': user['username'],
                'email': user['email'],
                'phoneNumber': user.get('phoneNumber'),
                'role': user.get('role', 'user'),
                'status': user.get('status', 'active'),
                'createdAt': user.get('createdAt'),
                'updatedAt': user.get('updatedAt'),
                'lastLogin': user.get('lastLogin'),
                'avatarUrl': user.get('avatarUrl'),
                'tags': user.get('tags', []),
                'dob': user.get('dob'),
                'address': user.get('address', {}),
                'settings': user.get('settings', {
                    'language': 'en',
                    'theme': 'light',
                    'notifications': {
                        'email': True,
                        'sms': False,
                        'push': True
                    }
                }),
                'loginHistory': user.get('loginHistory', [])
            }
        }), 200

    @app.route('/api/users/<user_id>', methods=['PUT'])
    @token_required
    @Middleware.request_logger
    def update_user(current_user, user_id):
        """
        Update user profile information including credentials (password, email, username).
        
        Allows users to update their own information or admins to update any user.
        Supports updating standard profile fields, credentials, and admin-specific fields.
        
        Args:
            current_user (dict): The authenticated user making the request
            user_id (str): The ID of the user to update
        
        Returns:
            Response: JSON response with update status
        """
        try:
            # Validate user exists before proceeding
            user_to_update = firebase_service.get_user_by_id(user_id)
            if not user_to_update:
                return jsonify({'message': 'User not found'}), 404
                
            # Check permissions (only admins or the user themselves)
            if current_user['role'] != 'admin' and current_user['id'] != user_id:
                return jsonify({'message': 'Unauthorized access'}), 403
            
            # Parse and validate input data
            data = request.get_json()
            if not data or not isinstance(data, dict):
                return jsonify({'message': 'No valid input data provided'}), 400
            
            # Clear all related cache for this user
            cache.delete_memoized(get_user, current_user, user_id)
            cache.delete_memoized(get_current_user, current_user)
            cache.delete_memoized(get_all_users)
            
            # Standard fields that can be updated by any user for themselves
            allowed_fields = ['firstName', 'lastName', 'phoneNumber', 'dob', 'address']
            
            # Admin can update additional fields
            if current_user['role'] == 'admin':
                allowed_fields.extend(['role', 'tags', 'status'])
            
            # Create update dictionary with only allowed fields
            update_data = {k: v for k, v in data.items() if k in allowed_fields and v is not None}
            
            # Handle DOB conversion to datetime object
            if 'dob' in update_data:
                dob_value = update_data['dob']
                if dob_value:
                    try:
                        # Handle different date formats
                        if isinstance(dob_value, str):
                            # Try to parse ISO format first (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)
                            if 'T' in dob_value:
                                parsed_date = datetime.fromisoformat(dob_value.replace('Z', '+00:00'))
                            else:
                                # Parse date-only format
                                parsed_date = datetime.strptime(dob_value, '%Y-%m-%d')
                            
                            # Store as date only (without time)
                            update_data['dob'] = parsed_date.date()
                        elif isinstance(dob_value, dict) and '_seconds' in dob_value:
                            # Handle Firestore timestamp format
                            timestamp = datetime.fromtimestamp(dob_value['_seconds'])
                            update_data['dob'] = timestamp.date()
                        else:
                            return jsonify({'message': 'Invalid date format for DOB'}), 400
                    except (ValueError, TypeError) as e:
                        return jsonify({'message': f'Invalid date format for DOB: {str(e)}'}), 400
            
            # Handle password update with current password verification
            if 'password' in data:
                password = data.get('password')
                if not password or not isinstance(password, str):
                    return jsonify({'message': 'Password cannot be empty'}), 400
                    
                if len(password) < 8:
                    return jsonify({'message': 'Password must be at least 8 characters long'}), 400
                    
                # Check for password strength using regex like in JS example
                if not re.match(r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)", password):
                    return jsonify({'message': 'Password must contain uppercase, lowercase letters and at least one number'}), 400
                
                # Check if current password is provided
                current_password = data.get('currentPassword')
                if not current_password:
                    return jsonify({'message': 'Current password is required to change password'}), 400
                
                # Verify current password using the password_utils function
                if not verify_password(
                    current_password, 
                    user_to_update.get('passwordHash', ''), 
                    user_to_update.get('passwordSalt', '')
                ):
                    return jsonify({'message': 'Invalid current password'}), 403
                
                # Generate new password hash and salt using the password_utils function
                password_hash, password_salt = create_password_hash_and_salt(password)
                
                # Store both hash and salt
                update_data['passwordHash'] = password_hash
                update_data['passwordSalt'] = password_salt
                
                # Remove the plain passwords from update data
                if 'password' in update_data:
                    del update_data['password']
                if 'currentPassword' in update_data:
                    del update_data['currentPassword']
            
            # Handle email update
            if 'email' in data:
                email = data.get('email')
                if not email or not isinstance(email, str):
                    return jsonify({'message': 'Email cannot be empty'}), 400
                    
                # Use the same email validation regex as the JS version
                if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
                    return jsonify({'message': 'Invalid email format'}), 400
                    
                # Normalize email (lowercase)
                email = email.lower().strip()
                
                # Check if email already exists (for other users)
                existing_user = firebase_service.get_user_by_email(email)
                if existing_user and existing_user['id'] != user_id:
                    return jsonify({'message': 'Email already in use'}), 409
                    
                update_data['email'] = email
            
            # Handle username update
            if 'username' in data:
                username = data.get('username')
                if not username or not isinstance(username, str):
                    return jsonify({'message': 'Username cannot be empty'}), 400
                    
                # Use the same username validation regex as the JS version
                if not re.match(r"^[a-zA-Z0-9_.]{3,30}$", username):
                    return jsonify({'message': 'Username must be 3-30 characters and contain only letters, numbers, underscores, and periods'}), 400
                    
                # Check if username already exists (for other users)
                existing_user = firebase_service.get_user_by_username(username)
                if existing_user and existing_user['id'] != user_id:
                    return jsonify({'message': 'Username already in use'}), 409
                    
                update_data['username'] = username
            
            # Always update the updatedAt timestamp
            update_data['updatedAt'] = datetime.utcnow().isoformat()
            
            # Update user in Firestore
            if update_data:
                firebase_service.update_user(user_id, update_data)
                
                # Return updated fields in the response for client-side state management
                response_data = {
                    'message': 'User updated successfully',
                    'updatedFields': list(update_data.keys())
                }
                
                # If the fields need to be returned for localStorage update on client side
                # We can include them in the response
                if current_user['id'] == user_id:
                    # Only return safe fields that can be stored in localStorage
                    safe_fields = ['firstName', 'lastName', 'phoneNumber', 'dob', 'address', 
                                'email', 'username', 'role', 'status', 'tags']
                    user_updates = {k: v for k, v in update_data.items() if k in safe_fields}
                    
                    # Convert date objects to ISO format for JSON serialization
                    if 'dob' in user_updates and user_updates['dob']:
                        if hasattr(user_updates['dob'], 'isoformat'):
                            user_updates['dob'] = user_updates['dob'].isoformat()
                    
                    if user_updates:
                        response_data['userData'] = user_updates
                
                return jsonify(response_data), 200
            else:
                return jsonify({'message': 'No valid fields to update'}), 400
                
        except Exception as e:
            app.logger.error(f"Error updating user {user_id}: {str(e)}")
            return jsonify({'message': f'An error occurred while updating user: {str(e)}'}), 500

    @app.route('/api/users/<user_id>', methods=['DELETE'])
    @token_required
    @Middleware.request_logger
    def delete_user(current_user, user_id):
        # Clear all related cache for this user
        cache.delete_memoized(get_user, current_user, user_id)
        cache.delete_memoized(get_current_user, current_user)
        cache.delete_memoized(get_all_users)
        cache.delete_memoized(get_login_history, current_user, user_id)
        
        # Check permissions (only admins or the user themselves)
        if current_user['role'] != 'admin' and current_user['id'] != user_id:
            return jsonify({'message': 'Unauthorized access'}), 403
        
        # Get user to check if they exist and to get the avatar URL
        user = firebase_service.get_user_by_id(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Delete avatar from storage if it exists
        avatar_url = user.get('avatarUrl')
        if avatar_url:
            firebase_service.delete_avatar(user_id)
        
        # Delete user and all associated data
        firebase_service.delete_user(user_id)
        
        return jsonify({
            'message': 'User and associated data deleted successfully',
            'userId': user_id
        }), 200

    @app.route('/api/users/<user_id>/avatar', methods=['POST'])
    @token_required
    @Middleware.request_logger
    def update_avatar(current_user, user_id):
        # Clear all related cache for this user
        cache.delete_memoized(get_user, current_user, user_id)
        cache.delete_memoized(get_current_user, current_user)
        cache.delete_memoized(get_all_users)
        
        # Check permissions (only the user themselves or admin)
        if current_user['role'] != 'admin' and current_user['id'] != user_id:
            return jsonify({'message': 'Unauthorized access'}), 403
        
        # Check if a file was uploaded
        if 'avatar' not in request.files:
            return jsonify({'message': 'No file provided'}), 400
        
        file = request.files['avatar']
        
        # Validate file
        if file.filename == '':
            return jsonify({'message': 'No file selected'}), 400
        
        # Check file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
        if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            return jsonify({'message': 'File type not allowed'}), 400
        
        # Upload to Firebase Storage
        content_type = file.content_type or 'image/jpeg'  # Default to jpeg if content type not provided
        avatar_url = firebase_service.upload_avatar(user_id, file, content_type)
        
        # Update user with new avatar URL and updatedAt timestamp
        firebase_service.update_user(user_id, {
            'avatarUrl': avatar_url,
            'updatedAt': datetime.utcnow().isoformat()
        })
        
        return jsonify({
            'message': 'Avatar updated successfully',
            'avatarUrl': avatar_url,
            'userId': user_id
        }), 200

    @app.route('/api/users/<user_id>/avatar', methods=['DELETE'])
    @token_required
    @Middleware.request_logger
    def delete_avatar(current_user, user_id):
        # Clear all related cache for this user
        cache.delete_memoized(get_user, current_user, user_id)
        cache.delete_memoized(get_current_user, current_user)
        cache.delete_memoized(get_all_users)
        
        # Check permissions (only the user themselves or admin)
        if current_user['role'] != 'admin' and current_user['id'] != user_id:
            return jsonify({'message': 'Unauthorized access'}), 403
        
        # Get user to check if they have an avatar
        user = firebase_service.get_user_by_id(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Check if the user has an avatar to delete
        if not user.get('avatarUrl'):
            return jsonify({'message': 'User does not have an avatar'}), 400
        
        # Delete avatar from storage
        firebase_service.delete_avatar(user_id)
        
        # Update user to remove avatar URL and update updatedAt timestamp
        firebase_service.update_user(user_id, {
            'avatarUrl': None,
            'updatedAt': datetime.utcnow().isoformat()
        })
        
        return jsonify({
            'message': 'Avatar deleted successfully',
            'userId': user_id
        }), 200


    @app.route('/api/users/<user_id>/login-history', methods=['GET'])
    @token_required
    @Middleware.request_logger
    @cache.memoize(timeout=300)  # Cache for 5 minutes
    def get_login_history(current_user, user_id):
        # Check permissions (only the user themselves or admin)
        if current_user['role'] != 'admin' and current_user['id'] != user_id:
            return jsonify({'message': 'Unauthorized access'}), 403
        
        # Get user from database
        user = firebase_service.get_user_by_id(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Return login history
        login_history = user.get('loginHistory', [])
        
        return jsonify({
            'userId': user_id,
            'loginHistory': login_history,
            'total': len(login_history)
        }), 200
    
    @app.route('/api/users/<user_id>/login-history/<login_id>', methods=['DELETE'])
    @token_required
    @Middleware.request_logger
    def delete_login_history_entry(current_user, user_id, login_id):
        # Clear login history cache
        cache.delete_memoized(get_login_history, current_user, user_id)
        
        # Check permissions (only the user themselves or admin)
        if current_user['role'] != 'admin' and current_user['id'] != user_id:
            return jsonify({'message': 'Unauthorized access'}), 403
        
        # Get user from database
        user = firebase_service.get_user_by_id(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        # Get login history
        login_history = user.get('loginHistory', [])
        
        # Find and remove the specific login entry
        login_id_str = str(login_id)
        updated_history = [entry for entry in login_history if str(entry.get('id', '')) != login_id_str]
         
        # If lengths are same, entry wasn't found
        if len(updated_history) == len(login_history):
            return jsonify({'message': 'Login history entry not found'}), 404
        
        # Update user with new login history
        firebase_service.update_user(user_id, {
            'loginHistory': updated_history,
            'updatedAt': datetime.utcnow().isoformat()
        })
        
        return jsonify({
            'message': 'Login history entry deleted successfully',
            'userId': user_id,
            'loginId': login_id
        }), 200

    @app.route('/api/users/status/<user_id>', methods=['PATCH'])
    @token_required
    @Middleware.request_logger
    def update_user_status(current_user, user_id):
        # Clear all related caches
        cache.delete_memoized(get_user, current_user, user_id)
        cache.delete_memoized(get_all_users)
        
        # Only admins can update status
        if current_user['role'] != 'admin':
            return jsonify({'message': 'Unauthorized access. Admin privileges required.'}), 403
            
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'message': 'Status field is required'}), 400
            
        # Validate status
        allowed_statuses = ['active', 'inactive', 'suspended', 'pending']
        if data['status'] not in allowed_statuses:
            return jsonify({'message': f'Status must be one of: {", ".join(allowed_statuses)}'}), 400
            
        # Update user status and updatedAt timestamp
        firebase_service.update_user(user_id, {
            'status': data['status'],
            'updatedAt': datetime.utcnow().isoformat()
        })
        
        return jsonify({
            'message': f'User status updated to {data["status"]}',
            'userId': user_id,
            'status': data['status']
        }), 200

    @app.route('/api/users/settings/<user_id>', methods=['PATCH'])
    @token_required
    @Middleware.request_logger
    def update_user_settings(current_user, user_id):
        # Clear user caches
        cache.delete_memoized(get_user, current_user, user_id)
        cache.delete_memoized(get_current_user, current_user)
        
        # Check permissions (only the user themselves or admin)
        if current_user['role'] != 'admin' and current_user['id'] != user_id:
            return jsonify({'message': 'Unauthorized access'}), 403
            
        data = request.get_json()
        if not data or 'settings' not in data:
            return jsonify({'message': 'Settings field is required'}), 400
            
        # Get current user settings
        user = firebase_service.get_user_by_id(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        current_settings = user.get('settings', {
            'language': 'en',
            'theme': 'light',
            'notifications': {
                'email': True,
                'sms': False,
                'push': True
            }
        })
        
        # Update settings
        new_settings = {**current_settings}  # Create a copy of current settings
        
        # Update language if provided
        if 'language' in data['settings']:
            new_settings['language'] = data['settings']['language']
            
        # Update theme if provided
        if 'theme' in data['settings']:
            new_settings['theme'] = data['settings']['theme']
            
        # Update notifications if provided
        if 'notifications' in data['settings']:
            if not 'notifications' in new_settings:
                new_settings['notifications'] = {}
                
            for key in ['email', 'sms', 'push']:
                if key in data['settings']['notifications']:
                    new_settings['notifications'][key] = data['settings']['notifications'][key]
        
        # Update user settings and updatedAt timestamp
        firebase_service.update_user(user_id, {
            'settings': new_settings,
            'updatedAt': datetime.utcnow().isoformat()
        })
        
        return jsonify({
            'message': 'User settings updated successfully',
            'userId': user_id,
            'settings': new_settings
        }), 200