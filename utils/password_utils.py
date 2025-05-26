import hashlib
import os
import secrets
import base64

def create_password_hash_and_salt(password):
    """
    Creates a hash and salt for the provided password.
    Implements the same algorithm as the JS function:
    
    const hashPassword = (password) => {
      const salt = crypto.randomBytes(16).toString("hex");
      const hash = crypto
        .pbkdf2Sync(password, salt, 1000, 64, "sha512")
        .toString("hex");
      return { hash, salt };
    };
    
    Args:
        password (str): The password to hash
        
    Returns:
        tuple: (password_hash, password_salt)
    """
    # Generate a secure random salt - 16 bytes (same as JS crypto.randomBytes(16))
    salt = os.urandom(16).hex()
    
    # Hash the password with the salt using PBKDF2 with SHA-512
    # Using the same parameters as JS: 1000 iterations, 64 bytes output
    hash_obj = hashlib.pbkdf2_hmac(
        'sha512',                  # Hash algorithm (sha512 to match JS)
        password.encode('utf-8'),  # Convert password to bytes
        salt.encode('utf-8'),      # Convert salt to bytes
        1000,                      # Number of iterations (1000 to match JS)
        dklen=64                   # Length of the derived key (64 bytes to match JS)
    )
    
    # Convert the binary hash to hexadecimal
    password_hash = hash_obj.hex()
    
    return password_hash, salt

def verify_password(provided_password, stored_hash, stored_salt):
    """
    Verifies a password against a stored hash and salt.
    
    Args:
        provided_password (str): The password to verify
        stored_hash (str): The previously stored password hash
        stored_salt (str): The previously stored salt
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    # Hash the provided password with the stored salt
    hash_obj = hashlib.pbkdf2_hmac(
        'sha512',                        # Hash algorithm (sha512 to match JS)
        provided_password.encode('utf-8'),  # Convert password to bytes
        stored_salt.encode('utf-8'),        # Convert salt to bytes
        1000,                            # Number of iterations (1000 to match JS)
        dklen=64                         # Length of the derived key (64 bytes to match JS)
    )
    
    # Convert the binary hash to hexadecimal
    calculated_hash = hash_obj.hex()
    
    # Compare the calculated hash with the stored hash
    return secrets.compare_digest(calculated_hash, stored_hash)

def generate_api_key(length=32):
    """
    Generates a secure random API key.
    
    Args:
        length (int): Length of the API key in bytes
        
    Returns:
        str: A base64-encoded API key
    """
    # Generate random bytes
    random_bytes = os.urandom(length)
    
    # Convert to URL-safe base64 string and remove padding
    api_key = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
    
    return api_key

def hash_api_key(api_key):
    """
    Creates a hash of an API key for secure storage.
    
    Args:
        api_key (str): The API key to hash
        
    Returns:
        str: The hashed API key
    """
    # Hash the API key with SHA-256
    hash_obj = hashlib.sha256(api_key.encode('utf-8'))
    
    # Convert to hexadecimal
    hashed_key = hash_obj.hexdigest()
    
    return hashed_key

