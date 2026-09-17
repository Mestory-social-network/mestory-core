"""Static role and permission definitions."""

import enum
from collections.abc import Iterable

ROLE_USER = "user"
ROLE_MODERATOR = "moderator"
ROLE_ADMIN = "admin"

DEFAULT_ROLE = ROLE_USER
ALL_ROLES: tuple[str, ...] = (ROLE_USER, ROLE_MODERATOR, ROLE_ADMIN)

ROLE_DESCRIPTIONS: dict[str, str] = {
    ROLE_USER: "Regular user, manages only their own account.",
    ROLE_MODERATOR: "Reads and updates any account, cannot delete or grant roles.",
    ROLE_ADMIN: "Full control, including role assignment.",
}


class Permission(enum.StrEnum):
    """Actions that can be granted to a role."""

    USER_READ_SELF = "user:read:self"
    USER_UPDATE_SELF = "user:update:self"
    USER_READ_ANY = "user:read:any"
    USER_UPDATE_ANY = "user:update:any"
    USER_DELETE_ANY = "user:delete:any"
    ROLE_ASSIGN = "role:assign"


ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    ROLE_USER: frozenset(
        {Permission.USER_READ_SELF, Permission.USER_UPDATE_SELF},
    ),
    ROLE_MODERATOR: frozenset(
        {
            Permission.USER_READ_SELF,
            Permission.USER_UPDATE_SELF,
            Permission.USER_READ_ANY,
            Permission.USER_UPDATE_ANY,
        },
    ),
    ROLE_ADMIN: frozenset(Permission),
}


def permissions_for_roles(roles: Iterable[str]) -> frozenset[Permission]:
    """Resolve the union of permissions granted by the given roles.

    Unknown role names contribute nothing: role sets travel inside tokens and
    may outlive a rename, and an unknown name must never widen access.

    :param roles: role names.
    :return: granted permissions.
    """
    granted: set[Permission] = set()
    for role in roles:
        granted |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(granted)
