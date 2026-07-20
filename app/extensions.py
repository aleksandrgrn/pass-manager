from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask import redirect, url_for

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

login_manager.login_view = 'auth.login'
login_manager.login_message = 'Требуется авторизация для доступа к этой странице.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    from app.models import User
    return db.session.get(User, int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to login page."""
    return redirect(url_for('auth.login'))
