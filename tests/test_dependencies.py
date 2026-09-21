"""Тесты FastAPI-зависимостей авторизации: 401 / 403 / 503 различимы."""

import base64
import json
from collections.abc import Callable

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends, FastAPI
from httpx import ASGITransport

from mestory_core.auth.claims import AccessTokenClaims
from mestory_core.auth.dependencies import (
    get_claims,
    require_permissions,
    require_roles,
)
from mestory_core.auth.jwks import JwksClient
from mestory_core.auth.verifier import AccessTokenVerifier
from mestory_core.permissions import Permission
from tests.conftest import AUDIENCE, ISSUER, jwks_document

JWKS_URL = "https://auth.test/api/auth/.well-known/jwks.json"


def _build_app(handler: Callable[[httpx.Request], httpx.Response]) -> FastAPI:
    """
    Собрать приложение с тремя защищёнными эндпоинтами и заданным JWKS-транспортом.

    :param handler: обработчик, отвечающий на запрос к документу JWKS.
    :return: приложение FastAPI.
    """
    application = FastAPI()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application.state.access_token_verifier = AccessTokenVerifier(
        JwksClient(JWKS_URL, http),
        audience=AUDIENCE,
        issuer=ISSUER,
    )

    @application.get("/me")
    async def me(claims: AccessTokenClaims = Depends(get_claims)) -> dict[str, str]:
        return {"sub": str(claims.sub)}

    @application.get("/moderator")
    async def moderator(
        claims: AccessTokenClaims = Depends(require_roles("moderator")),
    ) -> dict[str, str]:
        return {"sub": str(claims.sub)}

    @application.get("/assign")
    async def assign(
        claims: AccessTokenClaims = Depends(
            require_permissions(Permission.ROLE_ASSIGN),
        ),
    ) -> dict[str, str]:
        return {"sub": str(claims.sub)}

    return application


def _client_for(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.AsyncClient:
    """
    Собрать HTTP-клиент к приложению с заданным JWKS-транспортом.

    :param handler: обработчик, отвечающий на запрос к документу JWKS.
    :return: асинхронный HTTP-клиент, ходящий в приложение напрямую.
    """
    application = _build_app(handler)
    return httpx.AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    )


@pytest.fixture
def app(key_pair: tuple[str, str]) -> FastAPI:
    """Приложение с тремя защищёнными по-разному эндпоинтами."""
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="test-kid")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(document))

    return _build_app(handler)


@pytest.fixture
def client(app: FastAPI) -> httpx.AsyncClient:
    """HTTP-клиент, ходящий в приложение напрямую."""
    return httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    )


async def test_valid_token_is_accepted(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
) -> None:
    """Корректный токен пропускается."""
    async with client:
        response = await client.get(
            "/me",
            headers={"Authorization": f"Bearer {make_token()}"},
        )

    assert response.status_code == httpx.codes.OK


async def test_missing_header_is_401(client: httpx.AsyncClient) -> None:
    """Запрос без заголовка — 401, не 403."""
    async with client:
        response = await client.get("/me")

    assert response.status_code == httpx.codes.UNAUTHORIZED
    assert response.json()["detail"]["code"] == "not_authenticated"


async def test_unknown_kid_is_401(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
) -> None:
    """Токен, подписанный неизвестным ключом, — 401."""
    async with client:
        response = await client.get(
            "/me",
            headers={"Authorization": f"Bearer {make_token(kid='forged')}"},
        )

    assert response.status_code == httpx.codes.UNAUTHORIZED
    assert response.json()["detail"]["code"] == "invalid_token"


async def test_missing_role_is_403(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
) -> None:
    """Аутентифицирован, но роли не хватает — 403."""
    async with client:
        response = await client.get(
            "/moderator",
            headers={"Authorization": f"Bearer {make_token(roles=['user'])}"},
        )

    assert response.status_code == httpx.codes.FORBIDDEN
    assert response.json()["detail"]["code"] == "forbidden"


async def test_matching_role_is_allowed(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
) -> None:
    """Нужная роль пропускает."""
    async with client:
        response = await client.get(
            "/moderator",
            headers={"Authorization": f"Bearer {make_token(roles=['moderator'])}"},
        )

    assert response.status_code == httpx.codes.OK


async def test_admin_bypasses_role_checks(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
) -> None:
    """Админ проходит проверку роли, которой у него нет."""
    async with client:
        response = await client.get(
            "/moderator",
            headers={"Authorization": f"Bearer {make_token(roles=['admin'])}"},
        )

    assert response.status_code == httpx.codes.OK


async def test_superuser_bypasses_checks_in_every_service(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
) -> None:
    """Суперюзер проходит проверки и здесь, а не только в auth_service.

    Ровно ради этого is_superuser добавлен в claims: иначе флаг работал бы
    в одном сервисе и молча не работал во всех остальных.
    """
    token = make_token(roles=["user"], is_superuser=True)
    async with client:
        response = await client.get(
            "/assign",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == httpx.codes.OK


async def test_missing_permission_is_403(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
) -> None:
    """Прав не хватает — 403."""
    async with client:
        response = await client.get(
            "/assign",
            headers={"Authorization": f"Bearer {make_token(roles=['moderator'])}"},
        )

    assert response.status_code == httpx.codes.FORBIDDEN


def test_require_roles_rejects_an_empty_spec() -> None:
    """Вызов без ролей — ошибка программиста, а не разрешение всем."""
    with pytest.raises(ValueError, match="at least one role"):
        require_roles()


def test_require_permissions_rejects_an_empty_spec() -> None:
    """Вызов без прав — ошибка программиста, а не разрешение всем."""
    with pytest.raises(ValueError, match="at least one permission"):
        require_permissions()


# --- Поправка 2: недоступность источника ключей — это 503, а не 401/500. ---


async def test_key_source_unreachable_is_503_not_401_or_500(
    make_token: Callable[..., str],
) -> None:
    """Транспорт до JWKS рвётся сетевой ошибкой — эндпоинт отдаёт 503.

    Не 401 (иначе авария auth_service разлогинила бы всех пользователей) и
    не 500 (иначе клиент не отличил бы временный сбой от бага).
    """

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    async with _client_for(handler) as client:
        response = await client.get(
            "/me",
            headers={"Authorization": f"Bearer {make_token()}"},
        )

    assert response.status_code == httpx.codes.SERVICE_UNAVAILABLE
    assert response.json()["detail"]["code"] == "auth_unavailable"


async def test_key_source_error_response_is_503_not_401_or_500(
    make_token: Callable[..., str],
) -> None:
    """Источник JWKS отвечает 503 — эндпоинт тоже отдаёт 503, не 401/500."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async with _client_for(handler) as client:
        response = await client.get(
            "/me",
            headers={"Authorization": f"Bearer {make_token()}"},
        )

    assert response.status_code == httpx.codes.SERVICE_UNAVAILABLE
    assert response.json()["detail"]["code"] == "auth_unavailable"


async def test_outage_branch_does_not_swallow_invalid_token(
    make_token: Callable[..., str],
    key_pair: tuple[str, str],
) -> None:
    """При живом источнике неприемлемый токен по-прежнему даёт 401, не 503."""
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="test-kid")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(document))

    async with _client_for(handler) as client:
        response = await client.get(
            "/me",
            headers={"Authorization": f"Bearer {make_token(kid='forged')}"},
        )

    assert response.status_code == httpx.codes.UNAUTHORIZED
    assert response.json()["detail"]["code"] == "invalid_token"


async def test_outage_branch_does_not_swallow_missing_permission(
    make_token: Callable[..., str],
    key_pair: tuple[str, str],
) -> None:
    """При живом источнике нехватка прав по-прежнему даёт 403, не 503."""
    _, public_pem = key_pair
    document = jwks_document(public_pem, kid="test-kid")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(document))

    async with _client_for(handler) as client:
        response = await client.get(
            "/assign",
            headers={"Authorization": f"Bearer {make_token(roles=['moderator'])}"},
        )

    assert response.status_code == httpx.codes.FORBIDDEN


# --- Раунд правок 1: MalformedJwksDocumentError сужает перехват, но 503 за
# сломанный документ остаётся на месте, а произвольный TypeError — нет. ---


async def test_malformed_jwks_document_is_still_503(
    make_token: Callable[..., str],
) -> None:
    """Документ JWKS с не-RSA ключом по-прежнему даёт 503 auth_unavailable.

    Фиксирует, что сужение перехвата в get_claims (с голого TypeError до
    MalformedJwksDocumentError) не сломало этот случай: испорченный
    документ — такая же невозможность проверить, как и недоступный сервер.
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
                "kid": "test-kid",
                "x": b64url(numbers.x),
                "y": b64url(numbers.y),
            },
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(document))

    async with _client_for(handler) as client:
        response = await client.get(
            "/me",
            headers={"Authorization": f"Bearer {make_token()}"},
        )

    assert response.status_code == httpx.codes.SERVICE_UNAVAILABLE
    assert response.json()["detail"]["code"] == "auth_unavailable"


class _BuggyVerifier:
    """Заглушка верификатора, эмулирующая программистский баг в цепочке.

    Настоящий баг где угодно в `verifier.verify()` (например, в
    `verify_access_token` или в `model_validate`) может всплыть голым
    `TypeError`. Такой баг обязан остаться громким — get_claims не должен
    ловить произвольный `TypeError` и подавать его клиенту как спокойное
    503 «источник недоступен, попробуйте позже».
    """

    async def verify(self, token: str) -> AccessTokenClaims:
        """
        Всегда падать с TypeError, как настоящий баг где-то в проверке.

        :param token: игнорируется.
        :raises TypeError: всегда.
        """
        raise TypeError("boom: a programming bug, not a source outage")


async def test_bare_type_error_is_not_masked_as_auth_unavailable(
    make_token: Callable[..., str],
) -> None:
    """Голый TypeError из бага в проверке не превращается в тихий 503.

    Это зеркало поправки 2: там авария источника не должна была выглядеть
    как плохой токен (401); здесь баг не должен выглядеть как авария (503).
    Ожидание — исключение долетает до вызывающего кода необработанным
    (в тестовом ASGI-клиенте это означает, что оно поднимается из самого
    вызова `client.get`, а не приходит как HTTP-ответ).
    """
    application = FastAPI()
    application.state.access_token_verifier = _BuggyVerifier()

    @application.get("/me")
    async def me(claims: AccessTokenClaims = Depends(get_claims)) -> dict[str, str]:
        return {"sub": str(claims.sub)}

    async with httpx.AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        with pytest.raises(TypeError, match="boom"):
            await client.get(
                "/me",
                headers={"Authorization": f"Bearer {make_token()}"},
            )
