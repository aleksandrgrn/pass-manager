# Pass Manager

Веб-приложение для управления учётными данными серверов (замена старому PHP-одностраничнику `readme/vps2/`).

## Стек

- **Backend:** Flask 3.1 + SQLAlchemy + Flask-Login + Flask-WTF
- **DB:** SQLite
- **Auth:** LDAP (Active Directory) с fallback на локального admin
- **Frontend:** Jinja2 + HTMX + Tailwind CSS (CDN)
- **Production:** Gunicorn + nginx

## Структура

```
pass-manager/
├── app/
│   ├── __init__.py              # Application factory
│   ├── config.py                # Dev/Prod config (читает .env)
│   ├── extensions.py            # db, login_manager, csrf
│   ├── models.py                # User, Server, Domain
│   ├── forms.py                 # LoginForm (общие формы)
│   ├── auth/                    # Авторизация (LDAP + local)
│   │   ├── views.py
│   │   └── ldap_auth.py
│   └── servers/                 # CRUD серверов + HTMX
│       ├── views.py
│       └── forms.py
├── app/templates/               # Jinja2 шаблоны
├── scripts/
│   ├── init_db.py               # Создание таблиц
│   ├── seed_admin.py            # Создание local admin
│   └── migrate_from_mysql.py    # Импорт из legacy MySQL
├── nginx/pass-manager.conf      # Пример nginx-конфига
├── run.py                       # Точка входа (dev)
├── gunicorn.conf.py             # Production config
├── requirements.txt
└── .env.example
```

## Роли RBAC

| Роль        | Кто                          | Что видит                          |
|-------------|------------------------------|------------------------------------|
| `pass-user` | Обычный администратор        | Всё, кроме столбцов паролей        |
| `pass-lead` | Руководитель                 | Всё, включая пароли                |
| `pass-admin`| Супер-администратор          | Всё, включая пароли                |

`pass-user` не может ни просматривать, ни редактировать поля, в названии которых есть `password` или `pass`.

## Быстрый старт (dev)

```bash
# 1. Виртуальное окружение
python3 -m venv venv
source venv/bin/activate

# 2. Зависимости
pip install -r requirements.txt

# 3. Конфиг
cp .env.example .env
# Отредактируйте SECRET_KEY, при необходимости — LDAP_*

# 4. Инициализация БД
python scripts/init_db.py

# 5. Создание local admin
python scripts/seed_admin.py

# 6. Запуск
python run.py
# → http://127.0.0.1:5001
```

## Миграция данных из старой MySQL БД

Поддерживается два режима:

### А) Из .sql дампа (mysqldump)

```bash
python scripts/migrate_from_mysql.py --dump /path/to/vps.sql --reset
```

### Б) Из живой MySQL

```bash
pip install pymysql
export MYSQL_HOST=... MYSQL_USER=... MYSQL_PASSWORD=... MYSQL_DB=vps
python scripts/migrate_from_mysql.py --live --reset
```

Флаг `--dry-run` — вывести действия без записи в БД.

## LDAP-авторизация

В `.env` задайте:

```
LDAP_SERVER=dc01.example.local
LDAP_PORT=389
LDAP_USE_SSL=false
LDAP_BASE_DN=DC=example,DC=local
LDAP_USER_DN=OU=Users
LDAP_BIND_DN=CN=svc-passmanager,OU=ServiceAccounts,DC=example,DC=local
LDAP_BIND_PASSWORD=...
LDAP_USER_SEARCH_FILTER=(sAMAccountName={username})

# Группы → роли
LDAP_GROUP_ADMIN=CN=pass-admin
LDAP_GROUP_LEAD=CN=pass-lead
LDAP_GROUP_USER=CN=pass-user
# При желании можно указать полные DN:
LDAP_GROUP_ADMIN_DN=CN=pass-admin,OU=Groups,DC=example,DC=local
```

Алгоритм:
1. Bind под service account → поиск пользователя по `sAMAccountName`.
2. Bind под найденным DN и паролем пользователя (проверка пароля).
3. Чтение `memberOf` → сравнение с DN/CN-ами групп → выбор роли.
4. Если LDAP недоступен или `LDAP_SERVER` пуст — fallback на local admin из `.env`.

## Production-деплой на b000860

```bash
# 1. Клонировать репозиторий
git clone <repo> /opt/pass-manager
cd /opt/pass-manager

# 2. Окружение
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. .env (production!)
cp .env.example .env
# Заполнить реальными значениями, сгенерировать SECRET_KEY:
python -c "import secrets; print(secrets.token_hex(32))"

# 4. Инициализация и seed
FLASK_CONFIG=production python scripts/init_db.py
FLASK_CONFIG=production python scripts/seed_admin.py

# 5. Миграция данных
FLASK_CONFIG=production python scripts/migrate_from_mysql.py --dump /path/legacy.sql --reset

# 6. systemd unit (пример)
cat > /etc/systemd/system/pass-manager.service <<'EOF'
[Unit]
Description=Pass Manager (gunicorn)
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/pass-manager
EnvironmentFile=/opt/pass-manager/.env
ExecStart=/opt/pass-manager/venv/bin/gunicorn -c gunicorn.conf.py "run:app"
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now pass-manager

# 7. nginx
cp nginx/pass-manager.conf /etc/nginx/sites-available/
ln -s /etc/nginx/sites-available/pass-manager.conf /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

## Интеграция (Фазы B/C)

В планах:
- **Фаза B** — обращение к VPS Manager по API при добавлении сервера
  (генерация SSH-ключей, ротация root-пароля).
- **Фаза C** — запуск Ansible playbooks через `ansible-runner` для установки
  сервисов exim/squid/vpn.

Эти фазы будут добавлены отдельными blueprint-ами (`integration/`, `automation/`)
без переделки Фазы A.

## Безопасность

- Все пароли в SQLite хранятся в открытом виде (как и в legacy) — это осознанное решение
  для первой фазы, поскольку pass-manager уже RBAC-защищён и работает за nginx + LDAP.
- Шифрование на уровне столбцов можно добавить позже (Fernet, как в VPS Manager).
- `.env` **никогда** не коммитить (см. `.gitignore`).
- CSRF-токен встроен во все формы и прокидывается в HTMX-запросы.
