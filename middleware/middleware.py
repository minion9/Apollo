from flask import jsonify, request, g
from functools import wraps
import time
import logging
import os

logger = logging.getLogger(__name__)

class Middleware:
    """Class for Flask middleware functions"""
    
    @staticmethod
    def init_app(app):
        """Initialize all middleware for the Flask app"""
        # Configure logging level from environment
        log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
        numeric_level = getattr(logging, log_level, logging.INFO)
        logger.setLevel(numeric_level)
        
        # Request logger middleware
        @app.before_request
        def before_request():
            # Store the start time in g.start for calculating request duration
            g.start_time = time.time()
            # Log incoming request
            logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")
            
        @app.after_request
        def after_request(response):
            # Calculate request duration
            if hasattr(g, 'start_time'):
                duration = time.time() - g.start_time
                # Add custom headers
                response.headers['X-Response-Time'] = str(round(duration * 1000)) + 'ms'
                # Log outgoing response
                logger.info(f"Response: {response.status_code} - {round(duration * 1000)}ms")
            
            # Add security headers (but preserve existing CORS headers)
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            if not app.debug:
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
            # IMPORTANT: Don't override CORS headers that may have been set earlier
            # The CORS middleware should run AFTER this middleware
            
            return response
        
        # Register error handlers with CORS support
        @app.errorhandler(400)
        def bad_request(error):
            response = jsonify({'success': False, 'message': 'Bad request'})
            return response, 400
            
        @app.errorhandler(401)
        def unauthorized(error):
            response = jsonify({'success': False, 'message': 'Unauthorized'})
            return response, 401
            
        @app.errorhandler(403)
        def forbidden(error):
            response = jsonify({'success': False, 'message': 'Forbidden'})
            return response, 403
            
        @app.errorhandler(404)
        def not_found(error):
            response = jsonify({'success': False, 'message': 'Resource not found'})
            return response, 404
            
        @app.errorhandler(405)
        def method_not_allowed(error):
            response = jsonify({'success': False, 'message': 'Method not allowed'})
            return response, 405
            
        @app.errorhandler(500)
        def server_error(error):
            logger.error(f"Server error: {str(error)}")
            response = jsonify({'success': False, 'message': 'Internal server error'})
            return response, 500

    @staticmethod
    def request_logger(f):
        """Decorator to log request details"""
        @wraps(f)
        def decorated(*args, **kwargs):
            # Log the request details
            logger.info(f"Detailed request: {request.method} {request.path}")
            logger.debug(f"Request headers: {dict(request.headers)}")
            if request.is_json:
                # Log JSON body but remove sensitive fields
                body = request.get_json()
                if isinstance(body, dict):
                    safe_body = {k: '***' if k.lower() in ('password', 'token', 'secret', 'key') else v 
                                for k, v in body.items()}
                    logger.debug(f"Request JSON: {safe_body}")
            
            # Process the request
            response = f(*args, **kwargs)
            return response
        
        return decorated
    
    @staticmethod
    def rate_limiter(limit=100, per=60):
        """Basic rate limiter decorator
        
        Args:
            limit: Number of requests allowed
            per: Time period in seconds
        """
        # Use a simple in-memory store for demo purposes
        # In production, use Redis or similar
        storage = {}
        
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                # Get client IP
                client_ip = request.remote_addr
                
                # Get current timestamp
                now = time.time()
                
                # Clean up old records
                for ip in list(storage.keys()):
                    if now - storage[ip]['start'] > per:
                        del storage[ip]
                
                # Check if client exists in storage
                if client_ip not in storage:
                    storage[client_ip] = {
                        'count': 1,
                        'start': now
                    }
                else:
                    # Increment request count
                    storage[client_ip]['count'] += 1
                
                # Check if limit exceeded
                if storage[client_ip]['count'] > limit:
                    response = jsonify({
                        'success': False,
                        'message': 'Rate limit exceeded'
                    })
                    return response, 429
                
                # Process the request
                return f(*args, **kwargs)
            
            return decorated
        
        return decorator