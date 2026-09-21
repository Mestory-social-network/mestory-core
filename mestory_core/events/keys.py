"""Ключи маршрутизации событий Mestory."""

import enum

EXCHANGE_NAME = "mestory.events"


class RoutingKey(enum.StrEnum):
    """Ключи маршрутизации, под которыми публикуются события.

    Префикс — имя сервиса-источника. Он позволяет потребителю забиндиться
    на всё от одного сервиса одним `auth.#`, ради чего общий topic exchange
    и заводился вместо exchange на сервис.
    """

    USER_REGISTERED = "auth.user.registered"
    USER_VERIFICATION_REQUESTED = "auth.user.verification_requested"
    USER_PASSWORD_RESET_REQUESTED = "auth.user.password_reset_requested"  # noqa: S105
    USER_VERIFIED = "auth.user.verified"
    USER_PASSWORD_RESET = "auth.user.password_reset"  # noqa: S105
    USER_DELETED = "auth.user.deleted"

    PROFILE_CREATED = "profile.created"
    PROFILE_UPDATED = "profile.updated"
    PROFILE_BUSINESS_VERIFIED = "profile.business.verified"
    PROFILE_FOLLOWED = "profile.followed"
    PROFILE_UNFOLLOWED = "profile.unfollowed"
    PROFILE_BLOCKED = "profile.blocked"
    PROFILE_UNBLOCKED = "profile.unblocked"
    PROFILE_DELETED = "profile.deleted"
