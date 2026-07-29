"""Track C B1.1: модели групп серверов и членства.

Проверяем инварианты схемы, на которые опирается правило видимости:
человек в нескольких группах, сервер в одной, дублей членства нет,
удаление группы не уносит серверы.
"""
from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from app.models import Server, ServerGroup, ServerGroupMembership


def _make_group(db, name: str, can_create_servers: bool = False) -> ServerGroup:
    group = ServerGroup(name=name, can_create_servers=can_create_servers)
    db.session.add(group)
    db.session.commit()
    return group


class TestServerGroup:
    """Группа: имя уникально, возможность заводить серверы по умолчанию выключена."""

    def test_defaults_to_no_server_creation(self, db):
        """Р6: новая группа не может заводить серверы, пока флаг не поставят."""
        group = _make_group(db, 'team-alpha')
        assert group.can_create_servers is False

    def test_name_is_unique(self, db):
        """Две группы с одним именем — ошибка целостности."""
        _make_group(db, 'team-alpha')
        db.session.add(ServerGroup(name='team-alpha'))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


class TestMembership:
    """Членство: человек в нескольких группах, но в каждой — один раз."""

    def test_user_can_belong_to_several_groups(self, db, groupless_admin, superadmin_user):
        """Р3: разработчик, помогающий ИБ, состоит в двух командах."""
        alpha = _make_group(db, 'team-alpha')
        ib = _make_group(db, 'team-beta')
        db.session.add_all([
            ServerGroupMembership(user_id=groupless_admin.id, group_id=alpha.id,
                                  added_by=superadmin_user.id),
            ServerGroupMembership(user_id=groupless_admin.id, group_id=ib.id,
                                  added_by=superadmin_user.id),
        ])
        db.session.commit()

        assert {m.group.name for m in groupless_admin.group_memberships} == {'team-alpha', 'team-beta'}

    def test_duplicate_membership_rejected(self, db, admin_user, superadmin_user):
        """Повторное добавление в ту же группу ловится uq_user_group."""
        alpha = _make_group(db, 'team-alpha')
        db.session.add(ServerGroupMembership(user_id=admin_user.id, group_id=alpha.id,
                                             added_by=superadmin_user.id))
        db.session.commit()

        db.session.add(ServerGroupMembership(user_id=admin_user.id, group_id=alpha.id,
                                             added_by=superadmin_user.id))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


class TestServerGroupLink:
    """Связь сервера с группой и что происходит при удалении группы."""

    def test_server_without_group_is_allowed(self, db):
        """Унаследованные машины приезжают без группы — это нормальное состояние."""
        orphan = Server(name='inherited-01', ip_address='198.51.100.7')
        db.session.add(orphan)
        db.session.commit()

        assert orphan.group_id is None
        assert orphan.group is None

    def test_server_belongs_to_one_group(self, db, sample_server):
        alpha = _make_group(db, 'team-alpha')
        sample_server.group_id = alpha.id
        db.session.commit()

        assert sample_server.group.name == 'team-alpha'
        assert [s.id for s in alpha.servers] == [sample_server.id]

    def test_deleting_group_keeps_servers_and_drops_memberships(
        self, db, sample_server, groupless_admin, superadmin_user
    ):
        """Удаление группы не должно уносить серверы вместе с собой.

        Сервер остаётся, но становится ничьим — его будет видеть только суперадмин.
        Членства при этом удаляются (cascade='all, delete-orphan')."""
        alpha = _make_group(db, 'team-alpha')
        sample_server.group_id = alpha.id
        db.session.add(ServerGroupMembership(user_id=groupless_admin.id, group_id=alpha.id,
                                             added_by=superadmin_user.id))
        db.session.commit()
        server_id = sample_server.id

        db.session.delete(alpha)
        db.session.commit()

        survivor = db.session.get(Server, server_id)
        assert survivor is not None, 'сервер не должен удаляться вместе с группой'
        assert survivor.group_id is None
        assert ServerGroupMembership.query.filter_by(group_id=alpha.id).count() == 0
