"""Server-related forms."""
from flask_wtf import FlaskForm
from wtforms import (
    StringField, TextAreaField, BooleanField, HiddenField, FieldList
)
from wtforms.validators import DataRequired, Optional


class ServerForm(FlaskForm):
    """Form for creating/editing a server (full record)."""
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


class ServerFilterForm(FlaskForm):
    """Form for filtering the servers list."""
    q = StringField('Поиск', validators=[Optional()])
    active = BooleanField('Только активные', default=False)


# Whitelist of fields allowed for inline HTMX editing.
# Maps incoming field name → model attribute.
INLINE_EDITABLE_FIELDS = {
    'name': 'name',
    'password': 'password',
    'ip_address': 'ip_address',
    'provider': 'provider',
    'provider_login': 'provider_login',
    'provider_password': 'provider_password',
    'notes': 'notes',
    'os': 'os',
    'cpu': 'cpu',
    'ram': 'ram',
    'website': 'website',
    'web_login': 'web_login',
    'web_pass': 'web_pass',
    'vps_management_url': 'vps_management_url',
    'mgt_login': 'mgt_login',
    'mgt_pass': 'mgt_pass',
}

# Boolean toggle fields (services + active)
INLINE_TOGGLE_FIELDS = {
    'has_exim': 'has_exim',
    'has_squid': 'has_squid',
    'has_vpn': 'has_vpn',
    'active': 'active',
}
