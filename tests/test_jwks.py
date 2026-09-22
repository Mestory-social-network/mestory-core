import asyncio
import base64
import json
import logging

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import mestory_core.auth.jwks as jwks_module
from mestory_core.auth.jwks import (
    JwksClient,
    MalformedJwksDocumentError,
    UnknownSigningKeyError,
)
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


# --- Раунд правок 1 к задаче 9: сломанный документ — не голый TypeError. ---


async def test_non_rsa_key_raises_malformed_document_error() -> None:
    """Ключ не-RSA типа в документе JWKS — это порча документа, а не bug.

    Раньше `_to_pem` поднимал голый `TypeError`, неотличимый от бага в
    произвольном месте цепочки проверки токена. Выделенный тип нужен,
    чтобы `dependencies.get_claims` мог узко ловить именно этот случай.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()

    def b64url(value: int) -> str:
        raw = value.to_bytes(32, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    document = {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "ec-kid",
                "x": b64url(numbers.x),
                "y": b64url(numbers.y),
            },
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(document))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http)
        with pytest.raises(MalformedJwksDocumentError):
            await client.get_key("ec-kid")


# --- Раунд правок к финальному ревью: I1/I2/I3 — всё это порядок операций
# внутри get_key, а не таксономия исключений (та пятью раундами раньше уже
# закрыта). ---


@pytest.mark.parametrize(
    "raw_body",
    [
        pytest.param(b"<html>502 Bad Gateway</html>", id="html_error_page"),
        pytest.param(b'{"keys": [', id="truncated_json"),
        pytest.param(
            json.dumps({"keys": [1, 2]}).encode(),
            id="keys_entries_not_objects",
        ),
        pytest.param(
            json.dumps({"keys": ["kid-ish"]}).encode(),
            id="keys_entries_are_strings",
        ),
        pytest.param(json.dumps({"keys": None}).encode(), id="keys_is_null"),
        pytest.param(
            json.dumps([{"kid": "top-level-list"}]).encode(),
            id="document_is_a_list",
        ),
    ],
)
async def test_malformed_jwks_document_raises_malformed_error_not_a_builtin(
    raw_body: bytes,
) -> None:
    """Ответ 200 с испорченным телом — это MalformedJwksDocumentError, не 500.

    Регрессия для I1: раньше форма документа не проверялась, только форма
    отдельного ключа внутри него. Прокси, отдающий 200 с HTML-страницей
    ошибки — обычный случай, а не экзотика — раньше всплывал голым
    `json.JSONDecodeError`/`TypeError`/`AttributeError`, который
    `dependencies.get_claims` не перехватывает узко (и не должен: это
    молча замаскировало бы настоящий программистский баг), и сервис отвечал
    500 вместо честного 503 — причём на всё окно троттлинга, потому что
    сломанный ответ оседает в `_last_error` точно так же, как настоящая
    сетевая авария.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=raw_body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http)
        with pytest.raises(MalformedJwksDocumentError):
            await client.get_key("any-kid")


async def test_stale_cache_survives_a_failed_refresh(
    key_pair: tuple[str, str],
) -> None:
    """Провалившийся рефетч не должен ронять запрос, который кэш ещё может обслужить.

    Регрессия для I2: TTL для RS256 — это гигиена, а не граница
    безопасности, ключи живут неделями. Запрос с kid, который устаревший (по
    TTL) кэш всё ещё знает, не должен получать 503 только потому, что именно
    в этот момент источник недоступен — устаревшая, но почти наверняка ещё
    валидная запись обязана его обслужить.
    """
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="test-kid")
    calls: list[httpx.Request] = []
    expected_calls = 2  # прогрев + один провалившийся рефетч, без исключения

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, content=json.dumps(document))
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http, ttl=0.05, min_refetch_interval=0.0)
        warm_pem = await client.get_key("test-kid")

        await asyncio.sleep(0.1)  # TTL истёк, источник теперь мёртв

        stale_pem = await client.get_key("test-kid")

    assert stale_pem == warm_pem
    assert len(calls) == expected_calls


async def test_cached_lookup_is_not_delayed_by_an_unrelated_in_flight_fetch(
    key_pair: tuple[str, str],
) -> None:
    """Свежий кэш отвечает сразу, даже пока идёт загрузка ради чужого kid.

    Регрессия для I3: раньше единственным условием попытки войти в секцию
    блокировки было "блокировка занята ИЛИ пора обновиться" — без проверки,
    что кэш прямо сейчас уже отвечает на ЭТОТ kid. Шквал мусорных kid,
    поймавший конец окна троттлинга, запускал настоящую (и в проде — до 5с,
    таймаут httpx по умолчанию) загрузку, и любой другой конкурентный
    вызов — даже за давно закэшированным и свежим ключом — дожидался её
    целиком. Троттлинг, защищающий auth_service, превращался в усилитель
    задержки на потребителе, управляемый неаутентифицированным атакующим.
    """
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="known-kid")
    release_fetch = asyncio.Event()
    fetch_started = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        fetch_started.set()
        await release_fetch.wait()
        return httpx.Response(200, content=json.dumps(document))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http, min_refetch_interval=0.0)

        # Прогрев: кэш свежий и знает "known-kid" после этого вызова.
        release_fetch.set()
        await client.get_key("known-kid")
        release_fetch.clear()
        fetch_started.clear()

        # Мусорный kid запускает настоящую загрузку, которая зависает.
        stuck = asyncio.create_task(client.get_key("garbage-kid"))
        await fetch_started.wait()  # дождаться, пока загрузка реально пойдёт по сети

        loop = asyncio.get_running_loop()
        start = loop.time()
        cached_pem = await asyncio.wait_for(client.get_key("known-kid"), timeout=1.0)
        elapsed = loop.time() - start

        release_fetch.set()  # отпустить зависшую загрузку
        with pytest.raises(UnknownSigningKeyError):
            await stuck

    max_elapsed_without_waiting = 0.2  # щедрый запас; зависшая загрузка не отпустится
    assert cached_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert elapsed < max_elapsed_without_waiting


# --- Дефект 1: `except Exception` в откате на устаревший кэш глотал баги. ---


async def test_bug_in_parse_path_propagates_even_with_warm_cache(
    monkeypatch: pytest.MonkeyPatch,
    key_pair: tuple[str, str],
) -> None:
    """Баг в цепочке fetch/parse не должен тонуть в тёплом кэше.

    Регрессия: `except Exception` в откате на устаревший кэш ловил вообще
    всё, включая `AttributeError` из бага где-то в `_to_pem` — так что
    сам баг не долетал до вызывающего кода ни разу, пока кэш ещё мог
    ответить сам. Итог до фикса: три подряд 200 из устаревшего кэша,
    ключ никогда больше не подхватывает ротацию, и ни строчки в логе.
    """
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="test-kid")
    calls: list[httpx.Request] = []
    expected_calls = 2  # прогрев + один рефетч, где и сработал баг

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, content=json.dumps(document))

    def buggy_to_pem(jwk: dict[str, object]) -> str:
        raise AttributeError("boom: a bug in _to_pem, not a source outage")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http, ttl=0.05, min_refetch_interval=0.0)
        await client.get_key("test-kid")  # прогрев: кэш тёплый

        await asyncio.sleep(0.1)  # TTL истёк — следующий вызов рефетчит

        monkeypatch.setattr(jwks_module, "_to_pem", buggy_to_pem)

        with pytest.raises(AttributeError, match="boom"):
            await client.get_key("test-kid")

    assert len(calls) == expected_calls


async def test_stale_cache_fallback_logs_a_warning(
    caplog: pytest.LogCaptureFixture,
    key_pair: tuple[str, str],
) -> None:
    """Обслуживание из устаревшего кэша во время настоящей аварии — в логе.

    До фикса откат на устаревший кэш проходил абсолютно молча: ни разу
    ничего не логировалось и не поднималось, пока источник ключей лежал.
    """
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="test-kid")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, content=json.dumps(document))
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http, ttl=0.05, min_refetch_interval=0.0)
        warm_pem = await client.get_key("test-kid")

        await asyncio.sleep(0.1)  # TTL истёк, источник теперь мёртв

        with caplog.at_level(logging.WARNING, logger="mestory_core.auth.jwks"):
            stale_pem = await client.get_key("test-kid")

    assert stale_pem == warm_pem
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.WARNING
    assert "stale cache" in caplog.records[0].getMessage()


# --- Дефект 2: документ без пригодных ключей маскировался под пустой JWKS. ---


@pytest.mark.parametrize(
    "raw_body",
    [
        pytest.param(json.dumps({"hello": "world"}).encode(), id="no_keys_field"),
        pytest.param(json.dumps({"keys": []}).encode(), id="empty_keys_list"),
        pytest.param(
            json.dumps(
                {
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "alg": "RS256",
                            "n": "AQAB",
                            "e": "AQAB",
                        },
                    ],
                },
            ).encode(),
            id="no_entry_has_a_kid",
        ),
    ],
)
async def test_document_with_no_usable_keys_raises_malformed_error(
    raw_body: bytes,
) -> None:
    """Документ без единого потенциально пригодного ключа — не пустой JWKS.

    До фикса `document.get("keys", [])` подставлял `[]` и на отсутствующее
    поле, и на пустой список: `self._keys` оставался пустым словарём, и
    следующий же запрос получал `UnknownSigningKeyError` — 401 для всех, —
    хотя источник фактически не смог отдать пригодный документ и это
    честная авария (503), а не решение проверяющего кода.

    Третий параметр — тот же класс дефекта с другой формой: документ,
    структурно валидный и с непустым 'keys', но где ни одна запись не несёт
    'kid'. Разбор в `_fetch` строит `self._keys` фильтром `if "kid" in
    jwk` — такой документ тоже даёт пустой кэш, только скрыто: сам по себе
    он не выглядит пустым, и следующий, вообще не связанный с этой загрузкой
    запрос получал бы `UnknownSigningKeyError` (401 всем), а не честную
    503-аварию источника.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=raw_body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = JwksClient(JWKS_URL, http)
        with pytest.raises(MalformedJwksDocumentError):
            await client.get_key("any-kid")


# --- Дефект 3: сообщение UnknownSigningKeyError раскрывало адрес JWKS. ---


async def test_unknown_kid_message_does_not_leak_jwks_url(
    jwks_transport: tuple[httpx.MockTransport, list[httpx.Request]],
) -> None:
    """Сообщение об неизвестном kid не содержит внутренний адрес JWKS.

    До фикса сообщение включало `self._url` напрямую, и оно долетало без
    изменений до тела 401, которое видит неаутентифицированный клиент —
    тот же класс утечки, что уже был закрыт для деталей pydantic в
    `claims.py`.
    """
    transport, _ = jwks_transport

    async with httpx.AsyncClient(transport=transport) as http:
        client = JwksClient(JWKS_URL, http)
        with pytest.raises(UnknownSigningKeyError) as exc_info:
            await client.get_key("nope")

    assert JWKS_URL not in str(exc_info.value)
