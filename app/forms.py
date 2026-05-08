from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, SelectField, HiddenField
from wtforms.validators import DataRequired, Optional, IPAddress


class ServerForm(FlaskForm):
    """Form for creating/editing servers."""
    name = StringField('Название', validators=[DataRequired(message='Название обязательно')])
    password = StringField('Пароль', validators=[Optional()])
    ip_address = StringField('IP-адрес', validators=[Optional()])
    provider = StringField('Провайдер', validators=[Optional()])
    provider_login = StringField('Логин провайдера', validators=[Optional()])
    provider_password = StringField('Пароль провайдера', validators=[Optional()])
    notes = TextAreaField('Комментарии', validators=[Optional()])
    active = BooleanField('Активен', default=True)
    os = StringField('ОС', validators=[Optional()])
    cpu = StringField('CPU', validators=[Optional()])
    ram = StringField('RAM', validators=[Optional()])
    # Services
    has_exim = BooleanField('Exim', default=False)
    has_squid = BooleanField('Squid', default=False)
    has_vpn = BooleanField('VPN', default=False)
    # VPS management
    website = StringField('Website', validators=[Optional()])
    web_login = StringField('Web Login', validators=[Optional()])
    web_pass = StringField('Web Password', validators=[Optional()])
    vps_management_url = StringField('VPS Management URL', validators=[Optional()])
    mgt_login = StringField('Management Login', validators=[Optional()])
    mgt_pass = StringField('Management Password', validators=[Optional()])


class InlineEditForm(FlaskForm):
    """Form for inline HTMX editing of a single field."""
    field = HiddenField('field', validators=[DataRequired()])
    value = StringField('value', validators=[Optional()])
    id = HiddenField('id', validators=[DataRequired()])


class LoginForm(FlaskForm):
    """Local login form (fallback)."""
    username = StringField('Логин', validators=[DataRequired(message='Логин обязателен')])
    password = StringField('Пароль', validators=[DataRequired(message='Пароль обязателен')])
