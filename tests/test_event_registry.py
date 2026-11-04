"""Какой класс отвечает за ключ маршрутизации, и кто это решает."""

import contextlib
import gc
import uuid
from typing import ClassVar

import pytest

from mestory_core.events.keys import RoutingKey
from mestory_core.events.schemas import (
    EVENTS_BY_ROUTING_KEY,
    Event,
    UserDeleted,
    _all_event_types,
)


def test_every_declared_event_is_in_the_map() -> None:
    """Объявленное и зарегистрированное — одно и то же множество.

    Обход дерева подклассов отвечает на вопрос «что объявлено», карта — на
    вопрос «что зарегистрировано». Сейчас разойтись они не могут:
    регистрация происходит в `__init_subclass__`, а подкласс без своего
    ключа отвергается, так что третьего состояния нет.

    Тест остаётся сторожем этого свойства, а не его доказательством: он
    покраснеет, если регистрация снова станет условной — например если
    отсутствие ключа сделают пропуском вместо отказа, что и было прежним
    поведением карты, собиравшейся обходом.
    """
    declared = {
        event_type
        for event_type in _all_event_types(Event)
        # Класс, объявление которого отвергли, остаётся в
        # `__subclasses__()`: связь с родителем устанавливается до вызова
        # `__init_subclass__`, так что отказ его оттуда не убирает. Обход
        # поэтому может законно встретить класс без ключа — он не
        # зарегистрирован и не должен быть.
        if "routing_key" in event_type.__dict__
    }

    assert declared == set(EVENTS_BY_ROUTING_KEY.values())


def test_an_event_declared_elsewhere_registers_itself() -> None:
    """То, чего прежняя сборка карты не умела вовсе.

    Карта собиралась обходом `__subclasses__()` одной строкой в конце
    модуля схем, и `__subclasses__()` видит только то, что определено к
    моменту вызова. Событие, заведённое потребителем в собственном модуле,
    в карту не попадало — молча, и не потому, что так решили, а потому, что
    строка уже исполнилась.

    Этот тест объявляет подкласс здесь, то есть в другом модуле, уже после
    того, как схемы импортированы. Прежде он бы не появился в карте; теперь
    появляется, потому что регистрирует его само объявление.
    """
    key = RoutingKey.PROFILE_BUSINESS_VERIFIED
    original = EVENTS_BY_ROUTING_KEY[key]
    try:
        del EVENTS_BY_ROUTING_KEY[key]

        class LateComer(Event):
            """Событие, объявленное вне модуля схем."""

            routing_key: ClassVar[RoutingKey] = key

            profile_id: uuid.UUID

        assert EVENTS_BY_ROUTING_KEY[key] is LateComer
    finally:
        EVENTS_BY_ROUTING_KEY[key] = original


def test_two_events_cannot_claim_one_key() -> None:
    """Прежняя карта оставляла последнее совпадение, и молча.

    Два класса с одним ключом — это потребитель, разбирающий сообщение не
    той моделью, которой его собрали: поля не те, валидация либо падает,
    либо проходит и даёт другой смысл. Заметить это можно было бы только по
    самим сообщениям.

    Отказ происходит при объявлении, то есть при импорте модуля, который
    это натворил, — а не на первом сообщении в проде.
    """
    with pytest.raises(TypeError, match="already registered"):

        class Impostor(Event):
            """Претендует на уже занятый ключ."""

            routing_key: ClassVar[RoutingKey] = UserDeleted.routing_key

            user_id: uuid.UUID


def test_a_subclass_without_a_key_of_its_own_is_refused() -> None:
    """Забыть ключ — это занять родительский, молча.

    `routing_key` объявлен на `Event` как `ClassVar`, то есть наследуется.
    Подкласс, который своего не назвал, через `getattr` отдал бы ключ
    родителя — и встал бы в карту на его место. Поэтому проверяется
    `cls.__dict__`, и поэтому отсутствие ключа это отказ, а не пропуск.

    Общую часть нескольких событий заводят примесью: она не подкласс
    `Event`, в карту не просится и поля отдаёт так же.
    """
    with pytest.raises(TypeError, match="does not declare a routing_key"):

        class Keyless(Event):
            """Подкласс без собственного ключа."""

            profile_id: uuid.UUID

    # Отказ не отменяет создания класса: объект класса уже построен, и
    # связь с родителем установлена до вызова `__init_subclass__`, так что
    # `Event.__subclasses__()` его видит. Ссылки сбрасываются и запускается
    # сборка, чтобы слабая ссылка в этом списке умерла и обход в соседних
    # тестах не встретил класс без ключа. Сборка здесь не гарантия — ссылку
    # может удерживать трассировка, — поэтому обходы отдельно отфильтрованы.
    with contextlib.suppress(NameError):
        del Keyless
    gc.collect()
