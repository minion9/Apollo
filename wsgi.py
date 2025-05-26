"""
WSGI entry point for Gunicorn
"""
import os
from main import create_app  # Import from your main app file

# Create the Flask application instance
app = create_app()

if __name__ == "__main__":
    # This is only used when running directly, not with Gunicorn
    port = int(os.environ.get("PORT", 6980))
    app.run(host='0.0.0.0', port=port, debug=False)