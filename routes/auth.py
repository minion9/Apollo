from flask import request, jsonify, current_app
from utils.password_utils import create_password_hash_and_salt, verify_password
import jwt
import datetime
import uuid
import re
import pytz
import os
from functools import wraps
from services.firebase_service import firebase_service
from utils.device_info import get_device_info

JWT_EXPIRY = '1h'

# JWT configuration
def get_jwt_secret_key():
    """Get JWT secret key from environment or app config with development fallback warning"""
    secret_key = os.environ.get('JWT_SECRET_KEY', '58e97caabc792091683869795ed84a2b308817be3ab1f959d57fff8925a18cac9e654c48ca1a14093da1cc592ebd99bf0e44747b9e4b0e69dd50024175aee1b8')
    
    # Check if using default key in non-development environment
    if secret_key == 'development-secret-key' and not os.environ.get('FLASK_ENV') == 'development':
        current_app.logger.warning("WARNING: Using default JWT secret key in non-development environment!")
    
    return secret_key
    

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if token is in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'success': False, 'message': 'Token is missing!'}), 401
        
        try:
            # Decode the token
            data = jwt.decode(token, get_jwt_secret_key(), algorithms=["HS256"])
            current_user = firebase_service.get_user_by_id(data['id'])  # Using 'id' instead of 'user_id' to match JS
            
            if not current_user:
                return jsonify({'success': False, 'message': 'User no longer exists!'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token!'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

def get_ist():
    """Get current time in IST timezone (matching JS implementation)"""
    return datetime.datetime.now(pytz.timezone('Asia/Kolkata'))

def get_token_expiry():
    """Calculate token expiry based on JWT_EXPIRY setting"""
    expiry = JWT_EXPIRY.strip()
    if expiry.endswith('h'):
        hours = int(expiry[:-1])
        return datetime.datetime.now() + datetime.timedelta(hours=hours)
    elif expiry.endswith('m'):
        minutes = int(expiry[:-1])
        return datetime.datetime.now() + datetime.timedelta(minutes=minutes)
    elif expiry.endswith('d'):
        days = int(expiry[:-1])
        return datetime.datetime.now() + datetime.timedelta(days=days)
    else:
        # Default to 1 hour if format is not recognized
        return datetime.datetime.now() + datetime.timedelta(hours=1)

def auth_routes(app):
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No input data provided'}), 400
        
        # Validate required fields
        required_fields = ['firstName', 'lastName', 'username', 'email', 'password']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
        
        # Email validation
        if not re.match(r"[^@]+@[^@]+\.[^@]+", data['email']):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        # Check if user already exists
        if firebase_service.get_user_by_email(data['email']):
            return jsonify({'success': False, 'message': 'User with this email already exists'}), 409
        
        if firebase_service.get_user_by_username(data['username']):
            return jsonify({'success': False, 'message': 'Username is already taken'}), 409
        
        # Get device information
        device_info = get_device_info(request)
        
        password_hash, password_salt = create_password_hash_and_salt(data['password'])
        
        # Create user object
        now = get_ist()  # Use IST timezone
        now_iso = now.isoformat()

        # Default settings
        default_settings = {
            'language': 'en',
            'theme': 'light',
            'notifications': {
                'email': True,
                'sms': False,
                'push': True
            }
        }
        
        new_user = {
            "firstName": data['firstName'],
            "lastName": data['lastName'],
            "username": data['username'],
            "email": data['email'].lower(),
            "passwordHash": password_hash,
            "passwordSalt": password_salt,
            "phoneNumber": data.get('phoneNumber'),
            "role": data.get('role', 'user'),  # Default to 'user' if not provided
            "status": 'active',  # Default status
            "createdAt": now_iso,
            "updatedAt": now_iso,
            "lastLogin": now_iso,
            "avatarUrl": None,
            "dob": data.get('dob'),
            "tags": [],
            "settings": data.get('settings', default_settings),
            "address": data.get('address', {}),
            "loginHistory": [
                {
                    "id": str(uuid.uuid4()),
                    "timestamp": now_iso,
                    "method": "registration",
                    "device": device_info["device"],
                    "os": device_info["os"],
                    "browser": device_info["browser"]
                }
            ]
        }
        
        # Save user to Firestore
        user_id = firebase_service.create_user(new_user)
        
        # Generate JWT token
        token = jwt.encode({
            'id': user_id,  # Changed from 'user_id' to 'id' to match JS
            'email': data['email'],  # Added email in token
            'role': new_user['role'],    # Added role in token
            'exp': get_token_expiry()
        }, get_jwt_secret_key())
        
        # Create response object (matching the user route structure)
        user_response = {
            'id': user_id,
            'firstName': new_user['firstName'],
            'lastName': new_user['lastName'],
            'username': new_user['username'],
            'email': new_user['email'],
            'phoneNumber': new_user.get('phoneNumber'),
            'role': new_user.get('role', 'user'),
            'status': new_user.get('status', 'active'),
            'createdAt': new_user.get('createdAt'),
            'updatedAt': new_user.get('updatedAt'),
            'lastLogin': new_user.get('lastLogin'),
            'avatarUrl': new_user.get('avatarUrl'),
            'dob': new_user.get('dob'),
            'tags': new_user.get('tags', []),
            'address': new_user.get('address', {}),
            'settings': new_user.get('settings', default_settings),
            'loginHistory': new_user.get('loginHistory', [])
        }
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'data': {
                'token': token,
                'user': user_response
            }
        }), 201

    @app.route('/api/auth/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'success': False, 'message': 'No input data provided'}), 400
            
            # Check for login identifier (email or username) and password
            login_identifier = data.get('email') or data.get('username')
            password = data.get('password')
            
            if not login_identifier or not password:
                return jsonify({
                    'success': False, 
                    'message': 'Login identifier (email or username) and password are required'
                }), 400
            
            # Find user by email or username
            user = None
            login_method= 'email' if '@' in login_identifier else 'username'
            if '@' in login_identifier:  # Looks like an email
                user = firebase_service.get_user_by_email(login_identifier)
            else:  # Treat as username
                user = firebase_service.get_user_by_username(login_identifier)
            
            if not user:
                return jsonify({
                    'success': False, 
                    'message': 'Invalid credentials'
                }), 401
            
            # Check if user is active
            if user.get('status') != 'active':
                return jsonify({
                    'success': False, 
                    'message': f'Account is {user.get("status")}. Please contact support.'
                }), 403
            
            # Check password using the verify_password function
            if not verify_password(password, user['passwordHash'], user['passwordSalt']):
                return jsonify({
                    'success': False, 
                    'message': 'Invalid credentials'
                }), 401
            
            # Get device information
            device_info = get_device_info(request)
            
            # Update login history
            now = get_ist()  # Use IST timezone
            now_iso = now.isoformat()
            
            login_data = {
                "id": str(uuid.uuid4()),
                "timestamp": now_iso,
                "method": f"credentials - {login_method}",
                "device": device_info["device"],
                "os": device_info["os"],
                "browser": device_info["browser"]
            }
            
            # Add login info to history and update last login
            firebase_service.update_user(user['id'], {
                'lastLogin': now_iso,
                'updatedAt': now_iso,
                'loginHistory': user.get('loginHistory', []) + [login_data]
            })
            
            # Generate JWT token
            token = jwt.encode({
                'id': user['id'],
                'email': user['email'],
                'role': user['role'],
                'exp': get_token_expiry()
            }, get_jwt_secret_key())
            
            # Create response object (matching the user route structure)
            user_response = {
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
                'lastLogin': now_iso,  # Use updated lastLogin time
                'avatarUrl': user.get('avatarUrl'),
                'dob': user.get('dob'),
                'tags': user.get('tags', []),
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
                'loginHistory': user.get('loginHistory', []) + [login_data]
            }
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'data': {
                    'token': token,
                    'user': user_response
                }
            }), 200
        
        except Exception as e:
            print(f"Error during login: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'Server error during login'
            }), 500

    @app.route('/api/auth/token-refresh', methods=['POST'])
    @token_required
    def refresh_token(current_user):
        # Generate a new token
        token = jwt.encode({
            'id': current_user['id'],
            'email': current_user['email'],
            'role': current_user['role'],
            'exp': get_token_expiry()
        }, get_jwt_secret_key())
        
        return jsonify({
            'success': True,
            'message': 'Token refreshed',
            'data': {
                'token': token
            }
        }), 200

    @app.route('/api/auth/check-token', methods=['GET'])
    @token_required
    def check_token(current_user):
        """Endpoint to validate a token and return basic user info"""
        # Create response object (matching the user route structure)
        user_response = {
            'id': current_user['id'],
            'firstName': current_user['firstName'],
            'lastName': current_user['lastName'],
            'email': current_user['email'],
            'username': current_user.get('username'),
            'phoneNumber': current_user.get('phoneNumber'),
            'role': current_user.get('role', 'user'),
            'status': current_user.get('status', 'active'),
            'avatarUrl': current_user.get('avatarUrl'),
            'createdAt': current_user.get('createdAt'),
            'updatedAt': current_user.get('updatedAt'),
            'lastLogin': current_user.get('lastLogin'),
            'tags': current_user.get('tags', [])
        }
        
        return jsonify({
            'success': True,
            'message': 'Token is valid',
            'data': {
                'user': user_response
            }
        }), 200

    # @app.route('/api/auth/reset-password-request', methods=['POST'])
    # def reset_password_request():
    #     data = request.get_json()
        
    #     if not data or not data.get('email'):
    #         return jsonify({'success': False, 'message': 'Email is required'}), 400
            
    #     email = data['email']
    #     user = firebase_service.get_user_by_email(email)
        
    #     if not user:
    #         # For security reasons, still return success even if user doesn't exist
    #         return jsonify({'success': True, 'message': 'If the email exists, a reset link has been sent'}), 200
            
    #     # Generate reset token
    #     reset_token = str(uuid.uuid4())
    #     expire_time = datetime.datetime.now() + datetime.timedelta(hours=1)
        
    #     # Store token in user record
    #     firebase_service.update_user(user['id'], {
    #         'passwordReset': {
    #             'token': reset_token,
    #             'expires': expire_time.isoformat(),
    #             'used': False
    #         },
    #         'updatedAt': datetime.datetime.now().isoformat()
    #     })
        
    #     # In a real app, send email with reset link here
    #     # For this example, we'll just return a success message
        
    #     return jsonify({'success': True, 'message': 'If the email exists, a reset link has been sent'}), 200

    # @app.route('/api/auth/reset-password', methods=['POST'])
    # def reset_password():
    #     data = request.get_json()
        
    #     if not data or not data.get('token') or not data.get('password'):
    #         return jsonify({'success': False, 'message': 'Token and new password are required'}), 400
            
    #     reset_token = data['token']
    #     new_password = data['password']
        
    #     # Find user with this reset token
    #     user = firebase_service.get_user_by_reset_token(reset_token)
        
    #     if not user:
    #         return jsonify({'success': False, 'message': 'Invalid or expired token'}), 400
            
    #     # Check if token is expired or used
    #     reset_data = user.get('passwordReset', {})
    #     if not reset_data or reset_data.get('used') or \
    #        datetime.datetime.fromisoformat(reset_data.get('expires')) < datetime.datetime.now():
    #         return jsonify({'success': False, 'message': 'Invalid or expired token'}), 400
            
    #     # Create new password hash and salt
    #     from utils.password_utils import create_password_hash_and_salt
    #     password_hash, password_salt = create_password_hash_and_salt(new_password)
        
    #     # Update user with new password and mark token as used
    #     firebase_service.update_user(user['id'], {
    #         'passwordHash': password_hash,
    #         'passwordSalt': password_salt,
    #         'passwordReset.used': True,
    #         'updatedAt': datetime.datetime.now().isoformat()
    #     })
        
    #     return jsonify({'success': True, 'message': 'Password has been reset successfully'}), 200