"""Типизированные схемы событий — контракт между сервисами."""

import uuid
from datetime import UTC, datetime
from typing import ClassVar

from pydantic import BaseModel, Field

from mestory_core.events.keys import RoutingKey


class Event(BaseModel):
    """Базовое событие.

    `event_id` обязателен, потому что доставка at-least-once: потребитель
    может увидеть одно и то же сообщение дважды и обязан дедуплицировать
    по этому полю.
    """

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    routing_key: ClassVar[RoutingKey]


class UserRegistered(Event):
    """Учётная запись создана."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.USER_REGISTERED

    user_id: uuid.UUID
    email: str


class VerificationRequested(Event):
    """Запрошено подтверждение email."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.USER_VERIFICATION_REQUESTED

    user_id: uuid.UUID
    email: str
    token: str


class UserVerified(Event):
    """Email подтверждён."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.USER_VERIFIED

    user_id: uuid.UUID
    email: str


class PasswordResetRequested(Event):
    """Запрошен сброс пароля."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.USER_PASSWORD_RESET_REQUESTED

    user_id: uuid.UUID
    email: str
    token: str


class PasswordReset(Event):
    """Пароль сброшен."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.USER_PASSWORD_RESET

    user_id: uuid.UUID
    email: str


class UserDeleted(Event):
    """Учётная запись удалена.

    Единственное событие, потеря которого необратима: подписчики обязаны
    стереть персональные данные пользователя. Публикуется через outbox.
    """

    routing_key: ClassVar[RoutingKey] = RoutingKey.USER_DELETED

    user_id: uuid.UUID


class ProfileCreated(Event):
    """Профиль создан."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.PROFILE_CREATED

    profile_id: uuid.UUID
    user_id: uuid.UUID
    handle: str
    account_type: str


class ProfileUpdated(Event):
    """Изменено отображаемое имя или аватар.

    Нужно тем, кто держит денормализованную копию карточки автора — в первую
    очередь ленте.
    """

    routing_key: ClassVar[RoutingKey] = RoutingKey.PROFILE_UPDATED

    profile_id: uuid.UUID
    display_name: str
    avatar_media_id: uuid.UUID | None = None


class ProfileBusinessVerified(Event):
    """Бизнес-аккаунт подтверждён модератором."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.PROFILE_BUSINESS_VERIFIED

    profile_id: uuid.UUID


class ProfileFollowed(Event):
    """Появился новый подписчик."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.PROFILE_FOLLOWED

    follower_id: uuid.UUID
    followee_id: uuid.UUID


class ProfileUnfollowed(Event):
    """Подписка отменена."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.PROFILE_UNFOLLOWED

    follower_id: uuid.UUID
    followee_id: uuid.UUID


class ProfileBlocked(Event):
    """Пользователь заблокировал другого.

    Лента и поиск держат кэш блок-листа и инвалидируют его по этому событию.
    """

    routing_key: ClassVar[RoutingKey] = RoutingKey.PROFILE_BLOCKED

    blocker_id: uuid.UUID
    blocked_id: uuid.UUID


class ProfileUnblocked(Event):
    """Блокировка снята."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.PROFILE_UNBLOCKED

    blocker_id: uuid.UUID
    blocked_id: uuid.UUID


class ProfileDeleted(Event):
    """Профиль удалён."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.PROFILE_DELETED

    profile_id: uuid.UUID
    user_id: uuid.UUID


def _all_event_types(base: type[Event]) -> list[type[Event]]:
    """
    Собрать все конкретные подклассы события.

    Тем же обходом, каким тесты проверяют уникальность ключей: рекурсивно
    по дереву `__subclasses__()`, а не ручным перечислением, которое
    разойдётся со схемами при первом же добавленном событии.

    :param base: базовый класс, с которого начинать обход.
    :return: список подклассов `base`.
    """
    found: list[type[Event]] = []
    for subclass in base.__subclasses__():
        found.append(subclass)
        found.extend(_all_event_types(subclass))
    return found


# Единый источник правды для потребителя: получив из AMQP routing_key и
# сырое тело, он находит здесь класс и валидирует тело через
# model_validate_json — той же моделью, которой издатель его собрал.
EVENTS_BY_ROUTING_KEY: dict[RoutingKey, type[Event]] = {
    event_type.routing_key: event_type for event_type in _all_event_types(Event)
}


__all__ = [
    "EVENTS_BY_ROUTING_KEY",
    "Event",
    "PasswordReset",
    "PasswordResetRequested",
    "ProfileBlocked",
    "ProfileBusinessVerified",
    "ProfileCreated",
    "ProfileDeleted",
    "ProfileFollowed",
    "ProfileUnblocked",
    "ProfileUnfollowed",
    "ProfileUpdated",
    "UserDeleted",
    "UserRegistered",
    "UserVerified",
    "VerificationRequested",
]
