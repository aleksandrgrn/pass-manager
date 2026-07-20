"""Create or reset the local fallback admin user.

Reads credentials from .env (LOCAL_ADMIN_USERNAME / LOCAL_ADMIN_PASSWORD)
or accepts them interactively.

Usage:
    python scripts/seed_admin.py
    python scripts/seed_admin.py --username admin --password 'your-password'
"""
import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db
from app.models import User


def main():
    parser = argparse.ArgumentParser(description='Create local admin user')
    parser.add_argument('--username', default=os.environ.get('LOCAL_ADMIN_USERNAME', 'admin'))
    parser.add_argument('--password', default=os.environ.get('LOCAL_ADMIN_PASSWORD'))
    parser.add_argument('--role', default='pass-admin', choices=['pass-admin', 'pass-lead', 'pass-user'])
    args = parser.parse_args()

    password = args.password
    if not password:
        password = getpass.getpass(f'Password for {args.username}: ')
        confirm = getpass.getpass('Confirm password: ')
        if password != confirm:
            print('✗ Passwords do not match')
            sys.exit(1)

    if not password:
        print('✗ Empty password not allowed')
        sys.exit(1)

    app = create_app(os.environ.get('FLASK_CONFIG', 'development'))
    with app.app_context():
        existing = User.query.filter_by(username=args.username, is_local=True).first()
        if existing:
            existing.set_password(password)
            existing.role = args.role
            existing.is_active = True
            db.session.commit()
            print(f'✓ Local admin «{args.username}» updated (role={args.role})')
        else:
            user = User(
                username=args.username,
                role=args.role,
                is_local=True,
                is_active=True,
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            print(f'✓ Local admin «{args.username}» created (role={args.role})')


if __name__ == '__main__':
    main()
