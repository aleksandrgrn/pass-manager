from flask import Flask
from flask_migrate import Migrate

from app.config import config
from app.extensions import db, login_manager, csrf


_INSECURE_SECRET_KEYS = frozenset({
    '',
    'change-me',
    'change-me-to-random-64-char-hex-string',
    'test-secret-key-not-for-production',
    'test',
    'secret',
})


def _validate_prod_secrets(app: Flask) -> None:
    """Fail-fast проверка критичных секретов в non-debug окружениях.

    B1/F-005: SECRET_KEY не должен быть placeholder или коротким.
    B8/F-013: ENCRYPTION_KEY должен быть задан (не no-op шифрование).
    B9/F-014: SESSION_COOKIE_SECURE должен быть True в проде.

    В DEBUG/TESTING режиме проверка пропускается.
    """
    if app.debug or app.config.get('TESTING'):
        return

    sk = app.config.get('SECRET_KEY', '')
    if sk in _INSECURE_SECRET_KEYS or len(sk) < 32:
        raise RuntimeError(
            'SECRET_KEY не задан или слабый (placeholder/короткий). '
            'Сгенерируйте: python -c "import secrets; print(secrets.token_hex(32))"'
        )

    from app.security import is_no_op_mode
    with app.app_context():
        if is_no_op_mode():
            raise RuntimeError(
                'ENCRYPTION_KEY не задан: шифрование секретов выключено. '
                'Сгенерируйте: '
                'python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            )

    if not app.config.get('SESSION_COOKIE_SECURE', False):
        raise RuntimeError(
            'SESSION_COOKIE_SECURE должен быть True в non-debug окружении'
        )


def create_app(config_name=None):
    """Application factory."""
    if config_name is None:
        config_name = 'default'

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Ensure instance directory exists
    import os
    os.makedirs(os.path.join(app.instance_path), exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    Migrate(app, db)

    # B1/B8/B9/F-005/F-013/F-014: validate production secrets (fail-closed
    # on misconfiguration). В DEBUG/TESTING проверка пропускается.
    _validate_prod_secrets(app)

    # B4/B11: ProxyFix — nginx передаёт X-Forwarded-For; без него
    # request.remote_addr всегда 127.0.0.1 → in-memory rate-limit глобальный
    # (DoS на login).
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Register blueprints
    from app.auth.views import auth_bp
    from app.servers.views import servers_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(servers_bp, url_prefix='/servers')

    # Root redirect to servers list
    from flask import redirect, url_for
    @app.route('/')
    def index():
        return redirect(url_for('servers.list_servers'))

    # Error handlers
    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        from flask import render_template
        return render_template('errors/500.html'), 500

    return app
