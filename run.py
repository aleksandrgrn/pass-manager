"""Entry point for development. Use gunicorn for production."""
import logging
import os
from logging.handlers import RotatingFileHandler

from app import create_app

config_name = os.environ.get('FLASK_CONFIG', 'development')
app = create_app(config_name)


if __name__ == '__main__':
    # Setup file logging
    logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(logs_dir, exist_ok=True)

    handler = RotatingFileHandler(
        os.path.join(logs_dir, 'pass_manager.log'),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Pass Manager startup (dev)')

    app.run(host='127.0.0.1', port=5001, debug=(config_name == 'development'))
