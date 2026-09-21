"""Тесты FastAPI-зависимостей авторизации: 401 / 403 / 503 различимы."""

import json
from collections.abc import Callable

import httpx
import pytest
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
