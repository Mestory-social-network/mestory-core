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


class EchoingEventPublisher:
    """Публикует событие настоящим публикатором и дублирует его в лог.

    Нужен там, где одновременно требуется и доставка, и читаемый токен:
    локальный стенд. `LoggingEventPublisher` даёт токен, но ничего никому не
    доставляет, поэтому удаление аккаунта перестаёт доходить до соседних
    сервисов; `RabbitEventPublisher` доставляет, но подтвердить email
    локально нечем — потребителя у события подтверждения нет, почтового
    сервиса нет, и токен виден только в логе.

    Нельзя внедрять в production, по той же причине, что и
    `LoggingEventPublisher`: события несут токены подтверждения email и
    сброса пароля, и дублирование в лог кладёт их в агрегатор, доступный
    половине команды. Обёртка не делает это безопаснее — она добавляет
    доставку к той же утечке.
    """

    def __init__(self, inner: EventPublisher) -> None:
        """
        Обернуть настоящий публикатор.

        :param inner: публикатор, который действительно доставляет событие.
        """
        self._inner = inner

    async def publish(self, event: Event) -> None:
        """
        Доставить событие, и только потом записать его в лог.

        Порядок выбран, а не случаен. Запись в лог означает «доставлено»: её
        читают именно так, и запись, сделанная до неудачной публикации,
        говорила бы читателю неправду в тот момент, когда он разбирает
        аварию. Поэтому сначала доставка, а строка в логе появляется, только
        если доставка состоялась.

        Цена обратная и о ней стоит знать: если брокер недоступен, токена в
        логе не будет. Это сознательно — недоступный брокер на стенде ломает
        и всё остальное, а тихая строка «вот ваш токен» рядом с несработавшей
        доставкой хуже отсутствия строки.

        Исключение публикации пробрасывается как есть: вызывающий — в
        auth_service это воркер outbox — считает успешный `publish()`
        доставкой и помечает строку отправленной. Проглотить ошибку здесь
        значило бы пометить доставленным то, чего никто не получил.

        :param event: событие.
        """
        await self._inner.publish(event)
        logger.info(
            "mestory event %s (echoed): %s",
            event.routing_key.value,
            event.model_dump_json(),
        )
