import asyncio
import json

import httpx
import pytest

from mestory_core.auth.jwks import JwksClient, UnknownSigningKeyError
from tests.conftest import jwks_document

JWKS_URL = "https://auth.test/api/auth/.well-known/jwks.json"


@pytest.fixture
def jwks_transport(
    key_pair: tuple[str, str],
) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    """Транспорт, отдающий JWKS и считающий обращения к нему."""
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="test-kid")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, content=json.dumps(document))

    return httpx.MockTransport(handler), calls


async def test_known_kid_returns_a_pem(
    jwks_transport: tuple[httpx.MockTransport, list[httpx.Request]],
) -> None:
    """Известный kid отдаёт публичный ключ в PEM."""
    transport, _ = jwks_transport

    async with httpx.AsyncClient(transport=transport) as http:
        client = JwksClient(JWKS_URL, http)
        pem = await client.get_key("test-kid")

    assert pem.startswith("-----BEGIN PUBLIC KEY-----")


async def test_keys_are_cached_between_calls(
    jwks_transport: tuple[httpx.MockTransport, list[httpx.Request]],
) -> None:
    """Второй запрос того же kid не ходит по сети."""
    transport, calls = jwks_transport

    async with httpx.AsyncClient(transport=transport) as http:
        client = JwksClient(JWKS_URL, http)
        await client.get_key("test-kid")
        await client.get_key("test-kid")

    assert len(calls) == 1


async def test_unknown_kid_raises(
    jwks_transport: tuple[httpx.MockTransport, list[httpx.Request]],
) -> None:
    """Неизвестный kid приводит к явной ошибке, а не к None."""
    transport, _ = jwks_transport

    async with httpx.AsyncClient(transport=transport) as http:
        client = JwksClient(JWKS_URL, http)
        with pytest.raises(UnknownSigningKeyError):
            await client.get_key("nope")


async def test_unknown_kid_is_refetched_at_most_once_per_window(
    jwks_transport: tuple[httpx.MockTransport, list[httpx.Request]],
) -> None:
    """Поток токенов с мусорным kid не превращается в DoS на auth_service.

    Первый неизвестный kid оправдывает один рефетч — ключ мог только что
    провернуться. Последующие внутри окна обязаны отказывать без сети.
    """
    transport, calls = jwks_transport

    async with httpx.AsyncClient(transport=transport) as http:
        client = JwksClient(JWKS_URL, http, min_refetch_interval=60.0)
        for _ in range(20):
            with pytest.raises(UnknownSigningKeyError):
                await client.get_key("nope")

    assert len(calls) == 1


async def test_rotated_key_is_picked_up_after_the_window(
    key_pair: tuple[str, str],
) -> None:
    """Провернувшийся ключ подхватывается, когда окно троттлинга истекло."""
    _, public_pem = key_pair
    documents = [
        jwks_document(public_pem, kid="old-kid"),
        jwks_document(public_pem, kid="new-kid"),
    ]
    expected_fetches = len(documents)
    served: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        index = min(len(served), len(documents) - 1)
        served.append(index)
        return httpx.Response(200, content=json.dumps(documents[index]))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http, min_refetch_interval=0.0)
        await client.get_key("old-kid")
        pem = await client.get_key("new-kid")

    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert len(served) == expected_fetches


async def test_upstream_failure_propagates(key_pair: tuple[str, str]) -> None:
    """Недоступный auth_service даёт ошибку, а не молчаливый отказ в доступе."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http)
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_key("test-kid")


# --- Раунд правок 1: троттлинг не держит параллельную нагрузку, а сбой
# источника при пустом кэше не должен маскироваться под «неизвестный kid». ---


async def test_unknown_kid_swarm_on_cold_start_triggers_one_fetch(
    key_pair: tuple[str, str],
) -> None:
    """Параллельная нагрузка не обходит троттлинг, в отличие от последовательной.

    Последовательный цикл с `await` внутри никогда не заставал бы вторую
    корутину раньше, чем первая обновит кэш — поэтому такой тест не поймал
    бы гонку. Здесь все 20 обращений стартуют одновременно, а обработчик
    сам `await`-ит, чтобы честно уступить event loop и впустить остальные
    19 корутин, пока первая ещё «в полёте» — иначе `MockTransport` без
    единой настоящей точки приостановки просто выполнил бы 20 корутин одну
    за одной, и гонка никогда бы не проявилась.
    """
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="test-kid")
    calls: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        await asyncio.sleep(0.05)
        return httpx.Response(200, content=json.dumps(document))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http)
        results = await asyncio.gather(
            *(client.get_key("nope") for _ in range(20)),
            return_exceptions=True,
        )

    assert len(calls) == 1
    assert all(isinstance(result, UnknownSigningKeyError) for result in results)


async def test_concurrent_call_for_a_key_being_fetched_waits_instead_of_guessing(
    key_pair: tuple[str, str],
) -> None:
    """Запрос, заставший загрузку в процессе, дожидается её, а не гадает.

    Троттлинг мешает начать новую попытку, пока предыдущая ещё не
    отметилась как завершённая — но если конкурентный вызов из-за этого
    просто пропускает `_attempt_fetch`, он читает ещё пустой кэш и
    ошибочно отвергает валидный (в том числе только что провернутый) kid,
    хотя тот появится через миг, когда загрузка, идущая прямо сейчас,
    завершится. Правильное поведение — дождаться её и переоценить кэш.
    """
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="test-kid")
    calls: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        await asyncio.sleep(0.05)
        return httpx.Response(200, content=json.dumps(document))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http)
        results = await asyncio.gather(
            *(client.get_key("test-kid") for _ in range(20)),
        )

    assert len(calls) == 1
    assert all(pem.startswith("-----BEGIN PUBLIC KEY-----") for pem in results)


async def test_concurrent_burst_after_the_window_triggers_one_fetch(
    key_pair: tuple[str, str],
) -> None:
    """Стадо, заставшее и TTL, и окно троттлинга истёкшими, даёт один запрос.

    Как и в предыдущем тесте, обработчик сам приостанавливается, чтобы
    все 20 корутин всплеска реально пересеклись во времени, а не выполнились
    одна за другой.
    """
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="test-kid")
    calls: list[httpx.Request] = []

    expected_calls = 2  # прогрев + один общий рефетч на весь всплеск

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        await asyncio.sleep(0.05)
        return httpx.Response(200, content=json.dumps(document))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http, ttl=0.2, min_refetch_interval=0.2)
        await client.get_key("test-kid")
        await asyncio.sleep(0.3)

        results = await asyncio.gather(
            *(client.get_key("test-kid") for _ in range(20)),
        )

    assert len(calls) == expected_calls
    assert all(pem.startswith("-----BEGIN PUBLIC KEY-----") for pem in results)


async def test_upstream_outage_is_retried_at_most_once_per_window() -> None:
    """Лежащий источник получает не больше одного запроса за окно троттлинга.

    Без отдельной отметки времени неудачной попытки `_fetched_at` остаётся
    None навсегда, кэш вечно «устарел», и каждый вызов бьёт по сети заново.
    """
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http)
        for _ in range(10):
            with pytest.raises(httpx.HTTPStatusError):
                await client.get_key("test-kid")

    assert len(calls) == 1


async def test_upstream_outage_error_is_not_masked_as_unknown_key() -> None:
    """Авария источника не должна выглядеть как «неизвестный ключ».

    Пустой кэш плюс отказ от повторной попытки внутри окна троттлинга не
    равно «такого kid у нас нет» — это «мы не смогли проверить». Наружу
    обязана выйти ошибка источника того же типа и с тем же сообщением, что
    и в первый раз — но не тот же самый объект: повторный `raise` одного и
    того же экземпляра бесконечно растил бы его `__traceback__` (см.
    отдельный тест на это), поэтому второй вызов обязан получить свежую
    копию, связанную с исходной через `__cause__`.
    """
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http)
        with pytest.raises(httpx.HTTPStatusError) as first:
            await client.get_key("test-kid")
        with pytest.raises(httpx.HTTPStatusError) as second:
            await client.get_key("test-kid")

    assert type(second.value) is httpx.HTTPStatusError
    assert not isinstance(second.value, UnknownSigningKeyError)
    assert str(second.value) == str(first.value)
    assert second.value is not first.value
    assert second.value.__cause__ is first.value
    # .request/.response не выставлены конструктором HTTPStatusError
    # напрямую из args — они переданы отдельными keyword-only аргументами
    # и обязаны пережить пересоздание точно так же, как и тип с сообщением.
    assert second.value.request is first.value.request
    assert second.value.response is first.value.response


async def test_connection_outage_keeps_request_accessible_after_respawn() -> None:
    """Пересозданная сетевая ошибка не должна ронять `.request` `RuntimeError`.

    У `httpx.RequestError` (и его семейства — `ConnectError`,
    `ReadTimeout` и прочих) параметр `request` в конструкторе
    необязателен, поэтому наивное пересоздание через `cls(*exc.args)`
    проходит без `TypeError` и выглядит «удачным» путём — но настоящий
    объект запроса httpx привязывает к исключению уже ПОСЛЕ конструктора
    (`exc.request = request` в `request_context`), и это тот путь,
    которым транспорт реально бросает `ConnectError` — без `request=` в
    самом вызове. Задача 9 будет логировать `exc.request.url` (приём из
    документации httpx) — без сохранения этой привязки такой код упал бы
    `RuntimeError`-ом посреди спокойного превращения аварии в 503.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http)
        with pytest.raises(httpx.ConnectError) as first:
            await client.get_key("test-kid")
        with pytest.raises(httpx.ConnectError) as second:
            await client.get_key("test-kid")

    assert first.value.request is not None
    assert second.value.request is not None
    assert second.value.request is first.value.request


async def test_upstream_outage_does_not_grow_the_traceback_chain() -> None:
    """Повторные отказы в окне отката не удлиняют traceback без предела.

    `raise self._last_error` на уже поднятом объекте добавлял бы кадры
    текущего вызова к его `__traceback__` при каждом обращении — и так все
    время, пока источник не поднимется: 30 отказов подряд внутри окна
    отката ничем не отличаются по нагрузке на память и логи от одного,
    если каждый раз перевыбрасывается свежая копия с чистым traceback.
    """

    def traceback_length(tb: object) -> int:
        length = 0
        while tb is not None:
            length += 1
            tb = tb.tb_next  # type: ignore[attr-defined]
        return length

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http)
        lengths: list[int] = []
        for _ in range(30):
            with pytest.raises(httpx.HTTPStatusError) as caught:
                await client.get_key("test-kid")
            lengths.append(traceback_length(caught.value.__traceback__))

    # Первый вызов и правда идёт через _fetch(), поэтому его traceback
    # длиннее — это не рост, а другой путь. Важно, что все последующие,
    # throttled-повторы (каждый раз — свежая копия ошибки) не растут между
    # собой: 29 отказов подряд внутри окна отката держат одну и ту же
    # длину, а не удлиняются на каждый вызов.
    retried = lengths[1:]
    assert max(retried) == min(retried)


async def test_unknown_kid_with_warm_cache_raises_unknown_key_not_source_error(
    jwks_transport: tuple[httpx.MockTransport, list[httpx.Request]],
) -> None:
    """Непустой кэш с неизвестным kid — по-прежнему «не наш ключ», а не авария.

    Регрессионная проверка: различение аварии и неизвестного kid не должно
    задевать исходное поведение при живом источнике.
    """
    transport, _ = jwks_transport

    async with httpx.AsyncClient(transport=transport) as http:
        client = JwksClient(JWKS_URL, http)
        await client.get_key("test-kid")
        with pytest.raises(UnknownSigningKeyError):
            await client.get_key("nope")


async def test_ttl_below_min_refetch_interval_is_rejected() -> None:
    """Клиент отвергает ttl меньше окна троттлинга при конструировании."""
    async with httpx.AsyncClient() as http:
        with pytest.raises(ValueError, match="ttl"):
            JwksClient(JWKS_URL, http, ttl=1.0, min_refetch_interval=2.0)
