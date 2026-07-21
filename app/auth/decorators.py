"""RBAC decorators."""
from functools import wraps

from flask import abort
from flask_login import current_user


def role_required(*roles: str):
    """Декоратор: разрешает доступ только пользователям с указанными ролями.

    Если пользователь не аутентифицирован — Flask-Login редиректит на login.
    Если аутентифицирован, но роль не входит в список — 403.

    Usage:
        @servers_bp.route('/<id>/delete', methods=['POST'])
        @login_required
        @role_required('pass-admin', 'pass-lead')
        def delete(server_id): ...
    """
    required = set(roles)

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in required:
                abort(403, description='Недостаточно прав для этого действия')
            return fn(*args, **kwargs)
        return wrapper
    return decorator
