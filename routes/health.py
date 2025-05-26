from flask import jsonify, current_app
import os
import platform
import psutil
from services.firebase_service import firebase_service
from middleware.middleware import Middleware
import datetime
import pytz

def health_routes(app):
    @app.route('/health', methods=['GET'])
    @Middleware.request_logger  # Add request logging
    @Middleware.rate_limiter(limit=60, per=60)  # Limit to 60 requests per minute
    def check_health():
        """
        Check overall system health including database connections,
        memory usage, CPU load, and disk space
        """
        # Check database connection
        db_status = firebase_service.check_database_health()
       
        # Check storage connection
        storage_status = firebase_service.check_storage_health()
       
        # System information
        system_info = {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent
        }
       
        # Overall status
        status = "healthy" if db_status and storage_status else "unhealthy"
       
        response = {
            "status": status,
            "database": "connected" if db_status else "disconnected",
            "storage": "connected" if storage_status else "disconnected",
            "system": system_info,
            "timestamp": datetime.datetime.now(pytz.timezone('Asia/Kolkata')).isoformat()
        }
       
        # Add version info if available
        if os.environ.get("APP_VERSION"):
            response["version"] = os.environ.get("APP_VERSION")
       
        return jsonify(response), 200 if status == "healthy" else 503

    @app.route('/health/ping', methods=['GET'])
    @Middleware.rate_limiter(limit=120, per=60)  # Higher limit for ping
    def ping():
        """Simple ping endpoint for load balancers"""
        return jsonify({
            "status": "ok",
            "message": "pong"
        }), 200