import pytest

from mestory_core.permissions import (
    ALL_ROLES,
    DEFAULT_ROLE,
    ROLE_ADMIN,
    ROLE_MODERATOR,
    ROLE_PERMISSIONS,
    ROLE_USER,
    Permission,
    permissions_for_roles,
)


def test_default_role_is_user() -> None:
    """Новая учётка получает самую слабую роль."""
    assert DEFAULT_ROLE == ROLE_USER


def test_every_role_has_a_permission_set() -> None:
    """В карте прав нет роли без описанного набора."""  # noqa: RUF002
    assert set(ALL_ROLES) == set(ROLE_PERMISSIONS)


def test_admin_holds_every_permission() -> None:
    """Админ не ограничен ничем."""
    assert ROLE_PERMISSIONS[ROLE_ADMIN] == frozenset(Permission)


def test_moderator_cannot_delete_or_grant_roles() -> None:
    """Модератор читает и правит, но не удаляет и не раздаёт роли."""
    granted = ROLE_PERMISSIONS[ROLE_MODERATOR]

    assert Permission.USER_DELETE_ANY not in granted
    assert Permission.ROLE_ASSIGN not in granted


def test_unknown_role_grants_nothing() -> None:
    """Роль, которой нет в карте, не расширяет доступ.

    Наборы ролей едят внутри токенов и переживают переименование; неизвестное
    имя обязано не значить ничего.
    """
    assert permissions_for_roles(["ghost"]) == frozenset()


def test_permissions_are_the_union_of_roles() -> None:
    """Несколько ролей складываются объединением."""
    granted = permissions_for_roles([ROLE_USER, ROLE_MODERATOR])

    assert granted == ROLE_PERMISSIONS[ROLE_USER] | ROLE_PERMISSIONS[ROLE_MODERATOR]


@pytest.mark.parametrize("roles", [[], ["ghost", "phantom"]])
def test_empty_or_unknown_role_lists_grant_nothing(roles: list[str]) -> None:
    """Пустой и полностью неизвестный список одинаково не дают прав."""
    assert permissions_for_roles(roles) == frozenset()
