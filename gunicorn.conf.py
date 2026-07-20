"""Gunicorn production config."""
import multiprocessing
import os

bind = '127.0.0.1:5001'
workers = int(os.environ.get('GUNICORN_WORKERS', min(4, multiprocessing.cpu_count() * 2 + 1)))
threads = int(os.environ.get('GUNICORN_THREADS', 2))
timeout = 60
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = os.path.join(os.path.dirname(__file__), 'logs', 'gunicorn_access.log')
errorlog = os.path.join(os.path.dirname(__file__), 'logs', 'gunicorn_error.log')
loglevel = os.environ.get('GUNICORN_LOGLEVEL', 'info')

# Security
limit_request_line = 8190
limit_request_fields = 100

preload_app = True
