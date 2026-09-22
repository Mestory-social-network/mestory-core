import json
import logging
import uuid
from types import TracebackType
from typing import cast

import aio_pika
import pytest
from aio_pika import Channel
from aio_pika.pool import Pool

from mestory_core.events.keys import EXCHANGE_NAME, RoutingKey
from mestory_core.events.publisher import LoggingEventPublisher, RabbitEventPublisher
from mestory_core.events.schemas import (
    EVENTS_BY_ROUTING_KEY,
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


def test_event_map_covers_every_routing_key_exactly_once() -> None:
    """Карта не забывает событие и не держит лишних ключей.

    Потребитель обходит `RoutingKey`, чтобы забиндиться на очередь; карта
    обязана знать класс для каждого из этих ключей и ни для какого другого.
    """
    assert set(EVENTS_BY_ROUTING_KEY) == set(RoutingKey)
    assert len(EVENTS_BY_ROUTING_KEY) == len(RoutingKey)


def test_event_map_resolves_to_the_class_declaring_that_key() -> None:
    """По ключу достаётся именно тот класс, у которого этот routing_key."""
    assert EVENTS_BY_ROUTING_KEY[RoutingKey.USER_DELETED] is UserDeleted
    assert EVENTS_BY_ROUTING_KEY[RoutingKey.PROFILE_FOLLOWED] is ProfileFollowed


def test_event_round_trips_through_its_mapped_class() -> None:
    """Событие переживает сериализацию и обратную валидацию через карту.

    Это и есть доказательство, что контракт работает с обеих сторон: издатель
    сериализует, потребитель по ключу находит класс и валидирует то же тело.
    """
    event = UserRegistered(user_id=uuid.uuid4(), email="a@example.com")

    body = event.model_dump_json()
    event_type = EVENTS_BY_ROUTING_KEY[event.routing_key]
    restored = event_type.model_validate_json(body)

    assert restored == event


class _FakeExchange:
    """Минимальная замена aio_pika.Exchange: запоминает, а не отправляет."""

    def __init__(self) -> None:
        """Завести пустую историю объявления и публикаций."""
        self.declare_kwargs: dict[str, object] = {}
        self.published: list[tuple[aio_pika.Message, str]] = []

    async def publish(self, message: aio_pika.Message, routing_key: str) -> None:
        """
        Запомнить сообщение вместо реальной отправки в брокер.

        :param message: публикуемое сообщение AMQP.
        :param routing_key: ключ маршрутизации публикации.
        """
        self.published.append((message, routing_key))


class _FakeChannel:
    """Минимальная замена aio_pika.Channel: declare_exchange отдаёт фикстуру."""

    def __init__(self, exchange: _FakeExchange) -> None:
        """
        Запомнить фиктивный exchange, который надо будет отдать.

        :param exchange: фиктивный exchange.
        """
        self._exchange = exchange

    async def declare_exchange(
        self,
        *,
        name: str,
        type: aio_pika.ExchangeType,
        durable: bool,
        auto_delete: bool,
    ) -> _FakeExchange:
        """
        Запомнить параметры объявления вместо реального объявления.

        :param name: имя exchange.
        :param type: тип exchange.
        :param durable: переживает ли exchange перезапуск брокера.
        :param auto_delete: удаляется ли exchange без слушателей.
        :return: фиктивный exchange.
        """
        self._exchange.declare_kwargs = {
            "name": name,
            "type": type,
            "durable": durable,
            "auto_delete": auto_delete,
        }
        return self._exchange


class _FakeAcquireContext:
    """Минимальная замена контекста `pool.acquire()`."""

    def __init__(self, channel: _FakeChannel) -> None:
        """
        Запомнить канал, который надо будет отдать в `async with`.

        :param channel: фиктивный канал.
        """
        self._channel = channel

    async def __aenter__(self) -> _FakeChannel:
        """
        Войти в контекст и отдать фиктивный канал.

        :return: фиктивный канал.
        """
        return self._channel

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """
        Выйти из контекста, не подавляя исключения.

        :param exc_type: тип исключения, если оно было.
        :param exc: исключение, если оно было.
        :param traceback: трассировка исключения, если оно было.
        """
        return


class _FakeChannelPool:
    """Минимальная замена aio_pika.pool.Pool: acquire() отдаёт один канал."""

    def __init__(self, channel: _FakeChannel) -> None:
        """
        Запомнить канал, который будет отдан при каждом acquire().

        :param channel: фиктивный канал.
        """
        self._channel = channel

    def acquire(self) -> _FakeAcquireContext:
        """
        Отдать асинхронный контекст с фиктивным каналом.

        :return: контекстный менеджер с каналом.
        """
        return _FakeAcquireContext(self._channel)


@pytest.fixture
def fake_exchange() -> _FakeExchange:
    """
    Дать пустой фиктивный exchange для проверки публикации.

    :return: фиктивный exchange.
    """
    return _FakeExchange()


@pytest.fixture
def rabbit_publisher(fake_exchange: _FakeExchange) -> RabbitEventPublisher:
    """
    Собрать `RabbitEventPublisher` поверх фиктивного пула каналов.

    :param fake_exchange: фиктивный exchange, куда попадёт публикация.
    :return: публикатор для теста.
    """
    channel = _FakeChannel(fake_exchange)
    pool = _FakeChannelPool(channel)
    # _FakeChannelPool — минимальная структурная замена Pool[Channel] (только
    # acquire()), не его подкласс; cast сообщает mypy то, что тест уже
    # проверяет поведением.
    return RabbitEventPublisher(cast(Pool[Channel], pool))


async def test_rabbit_publisher_declares_a_durable_topic_exchange(
    rabbit_publisher: RabbitEventPublisher,
    fake_exchange: _FakeExchange,
) -> None:
    """Exchange объявляется topic/durable/не auto-delete — как задаёт спека."""
    await rabbit_publisher.publish(UserDeleted(user_id=uuid.uuid4()))

    assert fake_exchange.declare_kwargs == {
        "name": EXCHANGE_NAME,
        "type": aio_pika.ExchangeType.TOPIC,
        "durable": True,
        "auto_delete": False,
    }


async def test_rabbit_publisher_publishes_under_the_event_routing_key(
    rabbit_publisher: RabbitEventPublisher,
    fake_exchange: _FakeExchange,
) -> None:
    """Сообщение публикуется под routing_key самого события."""
    event = ProfileFollowed(follower_id=uuid.uuid4(), followee_id=uuid.uuid4())

    await rabbit_publisher.publish(event)

    _, routing_key = fake_exchange.published[0]
    assert routing_key == RoutingKey.PROFILE_FOLLOWED.value


async def test_rabbit_publisher_marks_the_message_persistent_and_identified(
    rabbit_publisher: RabbitEventPublisher,
    fake_exchange: _FakeExchange,
) -> None:
    """Сообщение переживает перезапуск брокера и несёт свой event_id."""
    event = UserDeleted(user_id=uuid.uuid4())

    await rabbit_publisher.publish(event)

    message, _ = fake_exchange.published[0]
    assert message.delivery_mode == aio_pika.DeliveryMode.PERSISTENT
    assert message.message_id == str(event.event_id)
    assert message.content_type == "application/json"


async def test_rabbit_publisher_round_trips_the_event_body(
    rabbit_publisher: RabbitEventPublisher,
    fake_exchange: _FakeExchange,
) -> None:
    """Опубликованное тело валидируется обратно в то же событие через карту."""
    event = UserRegistered(user_id=uuid.uuid4(), email="a@example.com")

    await rabbit_publisher.publish(event)

    message, routing_key = fake_exchange.published[0]
    event_type = EVENTS_BY_ROUTING_KEY[RoutingKey(routing_key)]
    assert event_type.model_validate_json(message.body) == event
