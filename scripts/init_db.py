"""Initialize the database: create all tables.

Usage:
    python scripts/init_db.py
"""
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db


def main():
    config_name = os.environ.get('FLASK_CONFIG', 'development')
    app = create_app(config_name)
    with app.app_context():
        db.create_all()
        instance_db = os.path.join(app.instance_path, 'pass_manager.db')
        print(f'✓ Tables created ({app.config["SQLALCHEMY_DATABASE_URI"]})')
        print(f'  SQLite file: {instance_db}')


if __name__ == '__main__':
    main()
