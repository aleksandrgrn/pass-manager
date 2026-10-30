"""GRSA-191: история изменений сервера пишется при любой правке.

Тикет 01: перехватчик before_flush в app/history.py. Проверяем пути записи
(форма, inline, переключатель, домены, создание), секреты без значений и то,
что пустые сохранения и отказы VPS Manager записей не дают.
"""
from __future__ import annotations

from unittest.mock import patch

from cryptography.fernet import Fernet

from app.models import Domain, Server, ServerChange, ServerGroup

E12 = 'app.servers.views.vps_client.update_server_address'


def _changes(db, server_id):
    db.session.expire_all()
    return (ServerChange.query.filter_by(server_id=server_id)
            .order_by(ServerChange.id).all())


def _items(change):
    return {i.field: (i.old_value, i.new_value, i.is_secret) for i in change.items}


def _form(server, **overrides):
    data = {'name': server.name, 'ip_address': server.ip_address or '',
            'provider': server.provider or '', 'provider_login': server.provider_login or '',
            'os': server.os or '', 'ssh_username': server.ssh_username or 'root',
            'active': 'y'}
    if server.has_exim:
        data['has_exim'] = 'y'
    data.update(overrides)
    return data


def _baseline(db, server):
    """Число записей до действия: sample_server уже несёт «заведён» и домены."""
    return len(_changes(db, server.id))


class TestManualPaths:

    def test_form_edit_is_one_change_with_two_items(self, admin_client, admin_user, db,
                                                     sample_server):
        before = _baseline(db, sample_server)
        resp = admin_client.post(f'/servers/{sample_server.id}/edit',
                                 data=_form(sample_server, name='renamed', provider='Other'))
        assert resp.status_code == 302

        changes = _changes(db, sample_server.id)
        assert len(changes) == before + 1
        last = changes[-1]
        assert (last.user_id, last.source) == (admin_user.id, 'manual')
        assert _items(last) == {
            'name': ('vps-test-01', 'renamed', False),
            'provider': ('TestProvider', 'Other', False),
        }

    def test_inline_ip_edit(self, admin_client, db, sample_server):
        before = _baseline(db, sample_server)
        resp = admin_client.post(f'/servers/{sample_server.id}/field',
                                 data={'field': 'ip_address', 'value': '203.0.113.5'},
                                 headers={'HX-Request': 'true'})
        assert resp.status_code == 200
        changes = _changes(db, sample_server.id)
        assert len(changes) == before + 1
        assert _items(changes[-1]) == {'ip_address': ('192.0.2.10', '203.0.113.5', False)}

    def test_toggle_is_human_readable(self, admin_client, db, sample_server):
        resp = admin_client.post(f'/servers/{sample_server.id}/toggle', data={'field': 'active'},
                                 headers={'HX-Request': 'true'})
        assert resp.status_code == 200
        assert _items(_changes(db, sample_server.id)[-1]) == {'active': ('да', 'нет', False)}

    def test_service_flag_via_form(self, admin_client, db, sample_server):
        data = _form(sample_server)
        del data['has_exim']  # снятая галка в форме не приходит
        admin_client.post(f'/servers/{sample_server.id}/edit', data=data)
        assert _items(_changes(db, sample_server.id)[-1]) == {'has_exim': ('вкл', 'выкл', False)}

    def test_group_change_shows_names(self, db, sample_server, default_group):
        other = ServerGroup(name='other-team')
        db.session.add(other)
        db.session.commit()
        sample_server.group_id = other.id
        db.session.commit()
        last = _changes(db, sample_server.id)[-1]
        assert (last.user_id, last.source) == (None, 'script')  # вне запроса
        assert _items(last) == {'group_id': ('test-group', 'other-team', False)}

    def test_group_deletion_recorded_on_its_servers(self, superadmin_client, superadmin_user,
                                                     db, sample_server, default_group):
        resp = superadmin_client.post(f'/access/groups/{default_group.id}/delete')
        assert resp.status_code == 200
        last = _changes(db, sample_server.id)[-1]
        assert db.session.get(Server, sample_server.id).group_id is None
        assert (last.user_id, last.source) == (superadmin_user.id, 'manual')
        assert _items(last) == {'group_id': ('test-group', None, False)}

    def test_crlf_from_browser_textarea_is_not_a_change(self, admin_client, db, sample_server):
        sample_server.notes = 'строка 1\nстрока 2'
        db.session.commit()
        before = _baseline(db, sample_server)
        resp = admin_client.post(f'/servers/{sample_server.id}/edit',
                                 data=_form(sample_server, notes='строка 1\r\nстрока 2'))
        assert resp.status_code == 302
        assert len(_changes(db, sample_server.id)) == before

    def test_domain_added_and_removed(self, admin_client, db, sample_server):
        admin_client.post(f'/servers/{sample_server.id}/domains', data={'domain': 'new.example'},
                          headers={'HX-Request': 'true'})
        assert _items(_changes(db, sample_server.id)[-1]) == {
            'domain_added': (None, 'new.example', False)}

        domain = Domain.query.filter_by(domain='example.com').one()
        admin_client.post(f'/servers/domains/{domain.id}/delete', headers={'HX-Request': 'true'})
        assert _items(_changes(db, sample_server.id)[-1]) == {
            'domain_removed': ('example.com', None, False)}


class TestSecrets:

    def test_resave_same_passwords_with_fernet_writes_nothing(self, app, superadmin_client, db,
                                                             sample_server):
        app.config['ENCRYPTION_KEY'] = Fernet.generate_key().decode()
        sample_server.password = 's3cret-root-pass'  # теперь как Fernet-токен
        sample_server.provider_password = 'prov-pass-123'
        db.session.commit()
        before = _baseline(db, sample_server)

        data = _form(sample_server, password='s3cret-root-pass',
                     provider_password='prov-pass-123')
        resp = superadmin_client.post(f'/servers/{sample_server.id}/edit', data=data)
        assert resp.status_code == 302
        assert sample_server.password_encrypted.startswith('gAAAAA')
        assert len(_changes(db, sample_server.id)) == before

    def test_password_change_is_fact_only(self, app, superadmin_client, db, sample_server):
        app.config['ENCRYPTION_KEY'] = Fernet.generate_key().decode()
        resp = superadmin_client.post(
            f'/servers/{sample_server.id}/edit',
            data=_form(sample_server, password='brand-new-root',
                       provider_password='prov-pass-123'))
        assert resp.status_code == 302
        items = _items(_changes(db, sample_server.id)[-1])
        assert items == {'password_encrypted': (None, None, True)}


class TestNoSpuriousRecords:

    def test_resave_unchanged_form_writes_nothing(self, admin_client, db, sample_server):
        before = _baseline(db, sample_server)
        # Пустые поля формы приходят '' там, где в базе NULL (website, cpu…).
        resp = admin_client.post(f'/servers/{sample_server.id}/edit', data=_form(sample_server))
        assert resp.status_code == 302
        assert len(_changes(db, sample_server.id)) == before

    def test_inline_empty_over_null_writes_nothing(self, admin_client, db, sample_server):
        before = _baseline(db, sample_server)
        admin_client.post(f'/servers/{sample_server.id}/field',
                          data={'field': 'notes', 'value': ''}, headers={'HX-Request': 'true'})
        assert len(_changes(db, sample_server.id)) == before

    def test_e12_refusal_writes_nothing(self, admin_client, db, default_group):
        server = Server(name='connected', ip_address='192.0.2.60', ssh_port=2233,
                        group_id=default_group.id, vps_manager_server_id=42)
        db.session.add(server)
        db.session.commit()
        before = _baseline(db, server)
        with patch(E12, return_value={'success': False, 'message': 'нет'}):
            admin_client.post(f'/servers/{server.id}/field',
                              data={'field': 'ip_address', 'value': '198.51.100.7'},
                              headers={'HX-Request': 'true'})
        assert len(_changes(db, server.id)) == before


def _pipeline_patches(e13=None, add=None):
    from contextlib import ExitStack
    stack = ExitStack()
    p = 'app.services.provisioning.'
    stack.enter_context(patch(p + 'vps_client.rebootstrap_server', return_value=e13))
    stack.enter_context(patch(p + 'vps_client.add_server', return_value=add))
    stack.enter_context(patch(p + 'vps_client.get_access_key',
                              return_value={'success': True, 'private_key': 'PEM'}))
    stack.enter_context(patch(p + '_write_key_file'))
    stack.enter_context(patch(p + 'rotate_root'))
    return stack


class TestPipeline:
    """Тикет 02: автор — запустивший, а не тот, кто опрашивает страницу job."""

    def test_new_machine_by_initiator_while_other_user_polls(
            self, admin_client, superadmin_client, admin_user, db, default_group):
        server = Server(name='vps-moved', ip_address='192.0.2.60', ssh_port=2233,
                        group_id=default_group.id, vps_manager_server_id=42)
        server.password = 'Old-Root'
        db.session.add(server)
        db.session.commit()
        before = _baseline(db, server)

        resp = admin_client.post(f'/servers/{server.id}/new-machine',
                                 data={'ip_address': '198.51.100.7', 'ssh_port': '22',
                                       'password': 'Hoster-New-1'})
        job_id = int(resp.headers['Location'].rsplit('/', 1)[1])
        e13 = {'success': True, 'server': {'ip_address': '198.51.100.7'}, 'redeploy': {}}
        with _pipeline_patches(e13=e13):
            for _ in range(6):  # опрашивает суперадмин, а не инициатор
                superadmin_client.post(f'/provisioning/jobs/{job_id}/step')

        changes = _changes(db, server.id)
        assert len(changes) == before + 1  # все шаги — одна запись
        last = changes[-1]
        assert (last.user_id, last.source, last.job_id) == (admin_user.id, 'new_machine', job_id)
        assert _items(last) == {
            'ip_address': ('192.0.2.60', '198.51.100.7', False),
            'ssh_port': ('2233', '22', False),
            'password_encrypted': (None, None, True),
        }

    def test_onboarding_marks_connection(self, admin_client, admin_user, db, default_group):
        from app.models import ProvisioningJob
        from app.services.provisioning import run_next_step, start_onboarding
        server = Server(name='fresh-conn', ip_address='192.0.2.70', group_id=default_group.id)
        db.session.add(server)
        db.session.commit()
        job = start_onboarding(server, admin_user, 'Hoster-Pass')
        with _pipeline_patches(add={'success': True, 'server_id': 77}):
            for _ in range(6):
                run_next_step(db.session.get(ProvisioningJob, job.id))

        last = _changes(db, server.id)[-1]
        assert (last.user_id, last.source) == (admin_user.id, 'onboarding')
        assert _items(last) == {
            'vps_manager_server_id': ('не подключён', 'подключён (№ 77)', False),
            'password_encrypted': (None, None, True),
        }

    def test_context_does_not_leak_into_later_manual_edit(self, admin_client, admin_user, db,
                                                         sample_server):
        import pytest

        from app.history import change_context
        # Шаг конвейера упал внутри контекста — контекст всё равно снят.
        with pytest.raises(RuntimeError), change_context('new_machine', None, None):
            raise RuntimeError('шаг упал')
        admin_client.post(f'/servers/{sample_server.id}/field',
                          data={'field': 'notes', 'value': 'после конвейера'},
                          headers={'HX-Request': 'true'})
        last = _changes(db, sample_server.id)[-1]
        assert (last.user_id, last.source) == (admin_user.id, 'manual')


class TestCardBlock:
    """Тикет 03: блок «История изменений» в карточке."""

    def _grow_to(self, db, server, total):
        i = 0
        while ServerChange.query.filter_by(server_id=server.id).count() < total:
            server.notes = f'заметка {i}'
            db.session.commit()
            i += 1

    def test_first_page_and_show_more(self, admin_client, db, sample_server):
        self._grow_to(db, sample_server, 25)
        page = admin_client.get(f'/servers/{sample_server.id}').get_data(as_text=True)
        assert page.count('class="h-entry"') == 20
        assert 'Показать ещё 5' in page
        assert 'История изменений' in page and '(25)' in page

        more = admin_client.get(f'/servers/{sample_server.id}/history?offset=20')
        html = more.get_data(as_text=True)
        assert more.status_code == 200
        assert html.count('class="h-entry"') == 5
        assert 'Показать ещё' not in html
        assert 'Сервер заведён' in html  # самая старая запись — последней

    def test_secret_value_never_rendered(self, app, superadmin_client, db, sample_server):
        app.config['ENCRYPTION_KEY'] = Fernet.generate_key().decode()
        superadmin_client.post(f'/servers/{sample_server.id}/edit',
                               data=_form(sample_server, password='Very-Secret-New-Root',
                                          provider_password='prov-pass-123'))
        card = superadmin_client.get(f'/servers/{sample_server.id}')
        start = card.get_data(as_text=True).index('id="history"')
        block = card.get_data(as_text=True)[start:]
        fragment = superadmin_client.get(
            f'/servers/{sample_server.id}/history?offset=0').get_data(as_text=True)
        for html in (block, fragment):
            assert 'Пароль root' in html and 'изменён' in html
            assert 'Very-Secret-New-Root' not in html
            assert 's3cret-root-pass' not in html

    def test_fragment_forbidden_for_foreign_server(self, admin_client, db):
        other = ServerGroup(name='foreign')
        db.session.add(other)
        db.session.commit()
        server = Server(name='foreign-srv', group_id=other.id)
        db.session.add(server)
        db.session.commit()
        card = admin_client.get(f'/servers/{server.id}')
        fragment = admin_client.get(f'/servers/{server.id}/history')
        assert fragment.status_code == card.status_code == 403

    def test_empty_history_message(self, admin_client, db, sample_server):
        ServerChange.query.filter_by(server_id=sample_server.id).delete()
        db.session.commit()
        page = admin_client.get(f'/servers/{sample_server.id}').get_data(as_text=True)
        assert 'Изменений пока нет.' in page


class TestSearch:
    """Тикет 04: поиск по доменам и истории, подпись под найденным по истории."""

    def _moved(self, db, group, old='198.51.100.25', new='203.0.113.77'):
        server = Server(name='msk-mail-01', ip_address=old, group_id=group.id)
        db.session.add(server)
        db.session.commit()
        server.ip_address = new
        db.session.commit()
        return server

    def _hint(self, html, server):
        start = html.find(f'data-hint-for="{server.id}"')
        return None if start < 0 else html[start:html.index('</tr>', start)]

    def test_old_ip_finds_server_with_hint(self, admin_client, db, default_group):
        server = self._moved(db, default_group)
        html = admin_client.get('/servers/?q=198.51.100.2').get_data(as_text=True)
        assert f'id="server-row-{server.id}"' in html
        hint = self._hint(html, server)
        assert hint is not None
        assert 'IP' in hint and '203.0.113.77' in hint
        assert '<mark class="hl">198.51.100.2</mark>5' in hint

    def test_current_ip_finds_without_hint_but_highlighted(self, admin_client, db, default_group):
        server = self._moved(db, default_group)
        html = admin_client.get('/servers/?q=203.0.113').get_data(as_text=True)
        assert f'id="server-row-{server.id}"' in html
        assert self._hint(html, server) is None
        assert '<mark class="hl">203.0.113</mark>.77' in html

    def test_more_matches_counted(self, admin_client, db, default_group):
        server = self._moved(db, default_group)
        server.notes = 'старый адрес 198.51.100.25'
        db.session.commit()
        server.notes = 'переехал'
        db.session.commit()
        hint = self._hint(admin_client.get('/servers/?q=198.51.100.2').get_data(as_text=True),
                          server)
        # последнее совпадение — комментарий, ещё два: старый комментарий… и IP
        assert 'Комментарии' in hint
        assert '+ ещё 2 совпадения в истории' in hint
        assert f'/servers/{server.id}#history' in hint

    def test_domain_finds_server(self, admin_client, sample_server):
        html = admin_client.get('/servers/?q=test.example').get_data(as_text=True)
        assert f'id="server-row-{sample_server.id}"' in html
        assert '<mark class="hl">test.example</mark>.org' in html
        assert self._hint(html, sample_server) is None

    def test_old_password_is_not_searchable(self, superadmin_client, db, sample_server):
        sample_server.password = 'Brand-New-Root'
        db.session.commit()
        html = superadmin_client.get('/servers/?q=s3cret-root').get_data(as_text=True)
        assert f'id="server-row-{sample_server.id}"' not in html

    def test_foreign_server_not_found_by_history(self, admin_client, db):
        other = ServerGroup(name='foreign')
        db.session.add(other)
        db.session.commit()
        server = self._moved(db, other)
        html = admin_client.get('/servers/?q=198.51.100.2').get_data(as_text=True)
        assert f'id="server-row-{server.id}"' not in html

    def test_like_wildcards_are_literal_in_history(self, admin_client, db, default_group):
        server = self._moved(db, default_group)
        html = admin_client.get('/servers/?q=198_51').get_data(as_text=True)
        assert f'id="server-row-{server.id}"' not in html
        html = admin_client.get('/servers/?q=198%25').get_data(as_text=True)
        assert f'id="server-row-{server.id}"' not in html

    def test_inactive_found_by_history(self, admin_client, db, default_group):
        server = self._moved(db, default_group)
        server.active = False
        db.session.commit()
        html = admin_client.get('/servers/?q=198.51.100.2').get_data(as_text=True)
        assert f'id="server-row-{server.id}"' in html

    def test_highlight_escapes_html(self, admin_client, db, default_group):
        server = Server(name='<b>x</b>-srv', group_id=default_group.id)
        db.session.add(server)
        db.session.commit()
        html = admin_client.get('/servers/?q=x').get_data(as_text=True)
        assert '&lt;b&gt;<mark class="hl">x</mark>&lt;/b&gt;-srv' in html


class TestLiveSearch:
    """Тикет 05: форма обновляет результаты HTMX-запросом, не перерисовывая себя."""

    def test_form_swaps_only_results_and_count(self, admin_client, sample_server):
        html = admin_client.get('/servers/?q=vps').get_data(as_text=True)
        start = html.index('<form method="GET"')
        form = html[start:html.index('</form>', start)]
        assert 'hx-select="#servers-results"' in form
        assert 'hx-select-oob="#servers-count"' in form
        assert 'from:#q' in form and 'from:#show_inactive' in form
        assert 'Применить' not in form
        # поле ввода — вне заменяемого блока, иначе терялся бы фокус
        results = html[html.index('id="servers-results"'):]
        assert 'name="q"' not in results
        assert f'id="server-row-{sample_server.id}"' in results
        assert 'id="servers-count"' in html

    def test_sort_links_keep_query(self, admin_client, sample_server):
        html = admin_client.get('/servers/?q=vps').get_data(as_text=True)
        assert '?sort=name&dir=desc&q=vps' in html


class TestOrmPaths:
    """Пути записи через связи и коллекции, autoflush посреди сохранения."""

    def test_group_change_via_relationship(self, db, sample_server):
        other = ServerGroup(name='team-b')
        db.session.add(other)
        db.session.commit()
        sample_server.group = other
        db.session.commit()
        assert _items(_changes(db, sample_server.id)[-1]) == {
            'group_id': ('test-group', 'team-b', False)}
        sample_server.group = None
        db.session.commit()
        assert _items(_changes(db, sample_server.id)[-1]) == {
            'group_id': ('team-b', None, False)}

    def test_group_change_to_unsaved_group_shows_name(self, db, sample_server):
        sample_server.group = ServerGroup(name='brand-new')
        db.session.commit()
        assert _items(_changes(db, sample_server.id)[-1]) == {
            'group_id': ('test-group', 'brand-new', False)}

    def test_unlinked_then_deleted_domain(self, db, sample_server):
        domain = Domain.query.filter_by(domain='example.com').one()
        domain.server = None
        db.session.delete(domain)
        db.session.commit()
        assert _items(_changes(db, sample_server.id)[-1]) == {
            'domain_removed': ('example.com', None, False)}

    def test_domain_removed_via_collection(self, db, sample_server):
        domain = Domain.query.filter_by(domain='example.com').one()
        sample_server.domains.remove(domain)
        db.session.commit()
        assert Domain.query.filter_by(domain='example.com').count() == 0
        assert _items(_changes(db, sample_server.id)[-1]) == {
            'domain_removed': ('example.com', None, False)}

    def test_domain_renamed(self, db, sample_server):
        domain = Domain.query.filter_by(domain='example.com').one()
        domain.domain = 'renamed.example'
        db.session.commit()
        assert _items(_changes(db, sample_server.id)[-1]) == {
            'domain_removed': ('example.com', None, False),
            'domain_added': (None, 'renamed.example', False),
        }

    def test_autoflush_mid_save_is_still_one_record(self, db, sample_server):
        before = _baseline(db, sample_server)
        sample_server.name = 'renamed'
        Server.query.count()  # autoflush
        sample_server.provider = 'Other'
        db.session.commit()
        changes = _changes(db, sample_server.id)
        assert len(changes) == before + 1
        assert _items(changes[-1]) == {'name': ('vps-test-01', 'renamed', False),
                                       'provider': ('TestProvider', 'Other', False)}

    def test_rollback_does_not_leak_open_record(self, db, sample_server):
        sample_server.name = 'temp'
        Server.query.count()  # autoflush — запись открыта
        db.session.rollback()
        sample_server.provider = 'After-Rollback'
        db.session.commit()
        last = _changes(db, sample_server.id)[-1]
        assert _items(last) == {'provider': ('TestProvider', 'After-Rollback', False)}

    def test_secret_newline_variants_are_different(self, app, db, sample_server):
        app.config['ENCRYPTION_KEY'] = Fernet.generate_key().decode()
        sample_server.provider_password = 'abc\r\ndef'
        db.session.commit()
        before = _baseline(db, sample_server)
        sample_server.provider_password = 'abc\ndef'
        db.session.commit()
        changes = _changes(db, sample_server.id)
        assert len(changes) == before + 1
        assert _items(changes[-1]) == {'provider_password_encrypted': (None, None, True)}


class TestLifecycle:

    def test_old_value_of_expired_attribute_is_read_from_db(self, db, sample_server):
        db.session.commit()  # все атрибуты выгружены (expire_on_commit)
        sample_server.ip_address = '198.51.100.1'
        db.session.commit()
        assert _items(_changes(db, sample_server.id)[-1]) == {
            'ip_address': ('192.0.2.10', '198.51.100.1', False)}

    def test_missing_port_counts_as_22(self, db, sample_server):
        assert sample_server.ssh_port is None
        before = _baseline(db, sample_server)
        sample_server.ssh_port = 22  # явная запись того же 22 — не изменение
        db.session.commit()
        assert len(_changes(db, sample_server.id)) == before
        sample_server.ssh_port = 2222
        db.session.commit()
        assert _items(_changes(db, sample_server.id)[-1]) == {'ssh_port': ('22', '2222', False)}

    def test_create_writes_created_record(self, db, default_group):
        server = Server(name='fresh', group_id=default_group.id)
        db.session.add(server)
        db.session.commit()
        changes = _changes(db, server.id)
        assert len(changes) == 1
        assert _items(changes[0]) == {'created': (None, None, False)}

    def test_migration_is_idempotent_and_dry_run_writes_nothing(self, db):
        from sqlalchemy import inspect

        from scripts.migrate_grsa191 import TABLES, migrate
        for table in reversed(TABLES):
            db.metadata.tables[table].drop(db.engine)

        assert migrate(dry_run=True) == list(TABLES)
        assert not set(TABLES) & set(inspect(db.engine).get_table_names())
        assert migrate(dry_run=False) == list(TABLES)
        assert set(TABLES) <= set(inspect(db.engine).get_table_names())
        assert migrate(dry_run=False) == []

    def test_delete_removes_history(self, admin_client, db, sample_server):
        server_id = sample_server.id
        assert _changes(db, server_id)
        resp = admin_client.post(f'/servers/{server_id}/delete')
        assert resp.status_code == 302
        assert ServerChange.query.filter_by(server_id=server_id).count() == 0
