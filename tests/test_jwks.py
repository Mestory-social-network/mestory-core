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
