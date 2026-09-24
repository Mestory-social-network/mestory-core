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
    """В карте прав нет роли без описанного набора."""
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

    Наборы ролей едут внутри токенов и переживают переименование; неизвестное
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


def test_known_role_mixed_with_unknown_grants_exactly_the_known_share() -> None:
    """Неизвестное имя рядом с известным не отбирает и не добавляет прав.

    Пропущенный до сих пор случай: покрыт был только список из одних
    неизвестных ролей и список из одних известных, но не их смесь.
    `["user", "ghost"]` обязан давать ровно то же самое, что и `["user"]`
    один — иначе "неизвестное имя не значит ничего" было бы проверено лишь
    наполовину.
    """
    assert permissions_for_roles([ROLE_USER, "ghost"]) == permissions_for_roles(
        [ROLE_USER],
    )


def test_moderator_can_verify_a_business_but_a_user_cannot() -> None:
    """Проверка бизнес-заявки — работа модератора, и право на неё живёт здесь.

    В `profile_service` это проверяется зависимостью `require_permissions`,
    которая выводит права из ролей в токене, — значит имя права обязано быть
    в общем словаре, иначе у одной строки станет два источника правды.
    """
    assert Permission.PROFILE_VERIFY_BUSINESS in permissions_for_roles(
        [ROLE_MODERATOR],
    )
    assert Permission.PROFILE_VERIFY_BUSINESS not in permissions_for_roles(
        [ROLE_USER],
    )


def test_admin_gets_every_permission_including_the_new_one() -> None:
    """У админа права не перечисляются, а берутся целиком из enum.

    Тест держит это свойство: добавленное право не должно требовать правки
    списка админа — иначе однажды его туда забудут внести.
    """
    assert permissions_for_roles([ROLE_ADMIN]) == frozenset(Permission)


def test_every_permission_name_follows_the_agreed_shape() -> None:
    """Имя права — `домен:действие` или `домен:действие:область`.

    Решение о формате записано как закрытое, и без проверки оно держится
    только на внимательности того, кто добавляет следующее право.

    Область необязательна, и это не послабление ради прохождения теста:
    `role:assign` существует с самого начала и области не имеет, потому что
    назначать роли можно только кому угодно — сужать там нечего, и
    `role:assign:any` был бы словом ради симметрии. Проверка всё равно ловит
    то, ради чего написана: пустой сегмент, верхний регистр, отсутствие
    двоеточия вовсе, лишний четвёртый сегмент.
    """
    for permission in Permission:
        parts = permission.value.split(":")
        assert len(parts) in {2, 3}, permission.value
        assert all(part and part.islower() for part in parts), permission.value
