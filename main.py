from flask import Flask
from flask_cors import CORS
from flask_caching import Cache
from middleware.middleware import Middleware
from routes.users import user_routes
from routes.auth import auth_routes
from routes.health import health_routes
import os
import logging

# Initialize cache
cache = Cache()

# Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.StreamHandler()
#     ]
# )

PORT = int(os.environ.get("PORT", 8080))  # Cloud Run typically uses 8080
ENV = os.environ.get("ENV", "development").lower()

def create_app():
    app = Flask(__name__)
    CORS(app)
    # Always run in production mode for Cloud Run
    app.logger.info("Application running in production environment")

    # Initialize middleware
    Middleware.init_app(app)

    # Configure Flask-Caching
    cache_type = os.environ.get('CACHE_TYPE', 'SimpleCache')
    cache_timeout = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', 300))
    
    app.config['CACHE_TYPE'] = cache_type
    app.config['CACHE_DEFAULT_TIMEOUT'] = cache_timeout
    cache.init_app(app)
    
    app.logger.info(f"Cache initialized with type: {cache_type}, default timeout: {cache_timeout}s")


    
    # Register routes
    auth_routes(app)
    user_routes(app)
    health_routes(app)
   
    return app

if __name__ == '__main__':
    app = create_app()
    
    print(f"Server running on port {PORT}")
    print(f"Cache type: {app.config['CACHE_TYPE']}, timeout: {app.config['CACHE_DEFAULT_TIMEOUT']}s")
    debug_mode = ENV == "development"

    # Always run without debug mode for production
    app.run(host='0.0.0.0', port=PORT, debug=debug_mode)