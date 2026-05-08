from flask import Flask
from flask_migrate import Migrate

from app.config import config
from app.extensions import db, login_manager, csrf


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
