import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', 6980)}"
backlog = 2048

# Worker processes
workers = int(os.environ.get('GUNICORN_WORKERS', 4))
worker_class = "gthread"
threads = int(os.environ.get('GUNICORN_THREADS', 2))
worker_connections = 1000
timeout = int(os.environ.get('GUNICORN_TIMEOUT', 120))
keepalive = 5

# Worker temp directory (use shared memory for better performance)
worker_tmp_dir = "/dev/shm"

# Restart workers after this many requests, to prevent memory leaks
max_requests = int(os.environ.get('GUNICORN_MAX_REQUESTS', 1000))
max_requests_jitter = 100

# Load application code before the worker processes are forked
preload_app = True

# Logging
accesslog = "-"  # Log to stdout
errorlog = "-"   # Log to stderr
loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'flask-app'

# Server mechanics
daemon = False
pidfile = None
user = None
group = None

# For better performance in containerized environments
forwarded_allow_ips = '*'
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}