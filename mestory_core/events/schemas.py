"""Типизированные схемы событий — контракт между сервисами."""

import uuid
from datetime import UTC, datetime
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from mestory_core.events.keys import RoutingKey

# Единый источник правды для потребителя: получив из AMQP routing_key и
# сырое тело, он находит здесь класс и валидирует тело через
# model_validate_json — той же моделью, которой издатель его собрал.
#
# Наполняется в `Event.__init_subclass__`, то есть в момент объявления
# подкласса. Прежде карта собиралась обходом `__subclasses__()` одной
# строкой в конце модуля, и это работало только потому, что все подклассы
# лежат здесь: `__subclasses__()` видит лишь то, что уже определено к
# моменту вызова, так что подкласс `Event`, заведённый потребителем в своём
# модуле, в карту не попадал молча — а молча означало бы, что его
# сообщения дедуплицируются и разбираются не той моделью, которой собраны,
# либо отбраковываются как неизвестный ключ.
EVENTS_BY_ROUTING_KEY: dict[RoutingKey, type["Event"]] = {}


class Event(BaseModel):
    """Базовое событие.

    `event_id` обязателен, потому что доставка at-least-once: потребитель
    может увидеть одно и то же сообщение дважды и обязан дедуплицировать
    по этому полю.
    """

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    routing_key: ClassVar[RoutingKey]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """
        Записать подкласс в карту ключей, как только он объявлен.

        Регистрация здесь, а не обходом дерева подклассов в конце модуля:
        обход зависит от того, что успело импортироваться, а объявление —
        нет. Подкласс, заведённый в любом другом модуле, оказывается в
        карте тем же действием, которым он создаётся.

        Свой `routing_key` обязателен, и проверяется именно `cls.__dict__`,
        а не `getattr`: унаследованный ключ принадлежит родителю, и
        подкласс, забывший назвать свой, молча занял бы его место в карте.
        Общую часть нескольких событий поэтому заводят примесью, а не
        подклассом `Event` без ключа.

        Дубликат ключа отвергается, а не затирается. Прежняя карта
        оставляла последнее совпадение, и два события с одним ключом
        разошлись бы с тем, как их разбирает потребитель, — но заметить это
        можно было бы только по сообщениям, разобранным не той моделью.

        Оба отказа происходят при объявлении, то есть при импорте модуля,
        который это натворил, а не на первом сообщении в проде.

        :param kwargs: аргументы класса, передаются дальше по MRO.
        :raises TypeError: если подкласс не назвал своего ключа или ключ уже
            занят другим классом.
        """
        super().__init_subclass__(**kwargs)
        key = cls.__dict__.get("routing_key")
        if key is None:
            message = (
                f"{cls.__name__} does not declare a routing_key of its own; "
                "every Event subclass is an event, and shared fields belong "
                "in a mixin rather than in a keyless subclass"
            )
            raise TypeError(message)
        registered = EVENTS_BY_ROUTING_KEY.get(key)
        if registered is not None and registered is not cls:
            message = (
                f"routing key {key.value!r} is already registered to "
                f"{registered.__name__}; {cls.__name__} cannot take it too"
            )
            raise TypeError(message)
        EVENTS_BY_ROUTING_KEY[key] = cls


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
    """Изменилась карточка автора.

    Нужно тем, кто держит денормализованную копию карточки — в первую очередь
    ленте. Несёт оба идентификатора: `user_id` — тот, под которым человек
    известен всем сервисам, `profile_id` — внутренний ключ `profile_service`.

    `account_type` здесь потому, что он есть на самой карточке. Без него
    смена типа аккаунта не доезжала бы до потребителей вовсе, и переход в
    креатора — который разрешает публиковать рекомендации — остался бы для
    сервиса публикаций невидимым. Раньше событие описывалось как «сменилось
    имя или аватар»; теперь честнее сказать «изменилась карточка автора».
    """

    routing_key: ClassVar[RoutingKey] = RoutingKey.PROFILE_UPDATED

    profile_id: uuid.UUID
    user_id: uuid.UUID
    display_name: str
    account_type: str
    avatar_media_id: uuid.UUID | None = None


class ProfileBusinessVerified(Event):
    """Бизнес-аккаунт подтверждён модератором."""

    routing_key: ClassVar[RoutingKey] = RoutingKey.PROFILE_BUSINESS_VERIFIED

    profile_id: uuid.UUID
    user_id: uuid.UUID


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
    Собрать все подклассы события обходом дерева.

    Карту больше не строит — её наполняет `Event.__init_subclass__`. Обход
    остался потому, что он отвечает на другой вопрос: что вообще объявлено,
    включая класс, который забыл назвать свой `routing_key` и потому в
    карту не попал. Сверка одного с другим и есть проверка на такой пропуск.

    :param base: базовый класс, с которого начинать обход.
    :return: список подклассов `base`.
    """
    found: list[type[Event]] = []
    for subclass in base.__subclasses__():
        found.append(subclass)
        found.extend(_all_event_types(subclass))
    return found


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
