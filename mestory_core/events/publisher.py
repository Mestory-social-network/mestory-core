"""Публикация событий."""

import logging
from typing import Protocol

import aio_pika
from aio_pika import Channel
from aio_pika.pool import Pool

from mestory_core.events.keys import EXCHANGE_NAME
from mestory_core.events.schemas import Event

logger = logging.getLogger(__name__)


class EventPublisher(Protocol):
    """Доставляет события тому, кто на них реагирует."""

    async def publish(self, event: Event) -> None:
        """
        Опубликовать одно событие.

        :param event: событие.
        """
        ...  # pragma: no cover


class LoggingEventPublisher:
    """Пишет события в лог. Используется в разработке и тестах.

    Нельзя внедрять в production: события несут токены подтверждения email
    и сброса пароля, и лог — не то место, где им следует оказаться.
    """

    async def publish(self, event: Event) -> None:
        """
        Записать событие в лог целиком, включая токены.

        Токены логируются намеренно: без почтового сервера это единственный
        способ пройти подтверждение email и сброс пароля локально.

        Нельзя использовать в production: токены подтверждения email и
        сброса пароля окажутся в агрегаторе логов, доступном половине
        команды. Там нужен `RabbitEventPublisher`.

        :param event: событие.
        """
        logger.info(
            "mestory event %s: %s",
            event.routing_key.value,
            event.model_dump_json(),
        )


class RabbitEventPublisher:
    """Публикует события в topic exchange RabbitMQ."""

    def __init__(
        self,
        channel_pool: Pool[Channel],
        exchange_name: str = EXCHANGE_NAME,
    ) -> None:
        """
        Инициализировать публикатор.

        :param channel_pool: пул каналов RabbitMQ.
        :param exchange_name: имя exchange.
        """
        self.channel_pool = channel_pool
        self.exchange_name = exchange_name

    async def publish(self, event: Event) -> None:
        """
        Опубликовать событие под его ключом маршрутизации.

        Сообщение помечается persistent: событие, потерянное при перезапуске
        брокера, — это и есть то, ради чего в auth_service заводится outbox.

        :param event: событие.
        """
        async with self.channel_pool.acquire() as channel:
            exchange = await channel.declare_exchange(
                name=self.exchange_name,
                type=aio_pika.ExchangeType.TOPIC,
                durable=True,
                auto_delete=False,
            )
            await exchange.publish(
                message=aio_pika.Message(
                    body=event.model_dump_json().encode(),
                    content_type="application/json",
                    message_id=str(event.event_id),
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                ),
                routing_key=event.routing_key.value,
            )
