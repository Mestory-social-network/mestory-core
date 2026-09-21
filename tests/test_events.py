import json
import logging
import uuid

import pytest

from mestory_core.events.keys import RoutingKey
from mestory_core.events.publisher import LoggingEventPublisher
from mestory_core.events.schemas import (
    Event,
    ProfileFollowed,
    UserDeleted,
    UserRegistered,
)


def test_every_routing_key_carries_a_source_prefix() -> None:
    """Ключ маршрутизации начинается с имени сервиса-источника.

    Без префикса потребитель не может забиндиться на всё от одного сервиса
    одной строкой, ради чего общий exchange и заводился.
    """
    for key in RoutingKey:
        assert key.value.split(".")[0] in {"auth", "profile"}


def test_events_get_a_unique_id_by_default() -> None:
    """Каждое событие несёт свой event_id — доставка at-least-once."""
    first = UserRegistered(user_id=uuid.uuid4(), email="a@example.com")
    second = UserRegistered(user_id=uuid.uuid4(), email="b@example.com")

    assert first.event_id != second.event_id


def test_event_knows_its_routing_key() -> None:
    """Событие само знает, под каким ключом публикуется."""
    assert UserDeleted.routing_key == RoutingKey.USER_DELETED
    assert ProfileFollowed.routing_key == RoutingKey.PROFILE_FOLLOWED


def test_routing_key_is_not_a_payload_field() -> None:
    """Ключ маршрутизации не дублируется в теле сообщения."""
    event = UserDeleted(user_id=uuid.uuid4())

    assert "routing_key" not in event.model_dump()


def test_every_event_class_has_a_distinct_routing_key() -> None:
    """Два события не делят один ключ — иначе потребитель их не различит."""
    subclasses = _all_subclasses(Event)
    keys = [subclass.routing_key for subclass in subclasses]

    assert len(keys) == len(set(keys))


def _all_subclasses(cls: type[Event]) -> list[type[Event]]:
    """
    Собрать все конкретные подклассы события.

    :param cls: базовый класс.
    :return: список подклассов.
    """
    found: list[type[Event]] = []
    for subclass in cls.__subclasses__():
        found.append(subclass)
        found.extend(_all_subclasses(subclass))
    return found


async def test_logging_publisher_writes_json(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Локальный публикатор пишет событие в лог целиком.

    Токены верификации попадают в лог намеренно: без почтового сервера это
    единственный способ пройти подтверждение email в разработке.
    """
    event = UserRegistered(user_id=uuid.uuid4(), email="a@example.com")

    with caplog.at_level(logging.INFO):
        await LoggingEventPublisher().publish(event)

    assert RoutingKey.USER_REGISTERED.value in caplog.text
    payload = json.loads(caplog.text.split(": ", 1)[1])
    assert payload["email"] == "a@example.com"
