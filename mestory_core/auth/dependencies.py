"""FastAPI-зависимости авторизации, работающие на claims токена."""

from collections.abc import Awaitable, Callable

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from mestory_core.auth.claims import AccessTokenClaims
from mestory_core.auth.jwks import MalformedJwksDocumentError
from mestory_core.auth.verifier import AccessTokenVerifier
from mestory_core.errors import ProblemDetail
from mestory_core.permissions import ROLE_ADMIN, Permission, permissions_for_roles

bearer_scheme = HTTPBearer(auto_error=False)


def _problem(
    status_code: int,
    code: str,
    detail: str,
    *,
    headers: dict[str, str] | None = None,
) -> HTTPException:
    """
    Собрать HTTPException с телом в формате ProblemDetail.

    :param status_code: код ответа.
    :param code: машиночитаемый код ошибки.
    :param detail: человекочитаемое описание.
    :param headers: дополнительные заголовки ответа.
    :return: готовое исключение.
    """
    body = ProblemDetail(code=code, detail=detail)
    return HTTPException(
        status_code=status_code,
        detail=body.model_dump(),
        headers=headers,
    )


def _unauthorized(code: str, detail: str) -> HTTPException:
    """
    Собрать 401 с заголовком, которого требует RFC 6750.

    Ресурс, защищённый bearer-токеном, обязан отвечать на 401
    `WWW-Authenticate: Bearer` — без него клиент не может отличить
    "нет токена"/"токен не принят" от произвольной другой причины 401.

    :param code: машиночитаемый код ошибки.
    :param detail: человекочитаемое описание.
    :return: готовое исключение с заголовком `WWW-Authenticate`.
    """
    return _problem(
        status.HTTP_401_UNAUTHORIZED,
        code,
        detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_claims(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AccessTokenClaims:
    """
    Проверить Bearer-токен запроса и вернуть его claims.

    Верификатор берётся из `app.state.access_token_verifier` — приложение
    обязано положить его туда в своём lifespan.

    Недоступность источника ключей (`httpx.HTTPError`) и повреждённый
    документ JWKS (`MalformedJwksDocumentError` — ключ не RSA либо иначе не
    разобрать) обрабатываются отдельной веткой, идущей после
    `jwt.InvalidTokenError`: это не «токен плохой», а «мы не можем это
    проверить», и раздача 401 в этом случае разлогинила бы всех
    пользователей на время аварии `auth_service`, а 500 — скрыла бы
    временный характер отказа от клиентов, которые могли бы повторить
    запрос. Ветка стоит после обработки `jwt.InvalidTokenError`, но не
    перекрывает её: ни `httpx.HTTPError`, ни `MalformedJwksDocumentError` не
    являются подклассами `jwt.InvalidTokenError`, поэтому уже обработанные
    случаи в неё не попадают.

    Перехват нарочно не расширен до голого `TypeError`: тот прикрывал бы
    всю цепочку `verifier.verify()`, включая `verify_access_token` и
    `model_validate`, и превращал бы любой программистский баг где угодно
    в этой цепочке в тихое «попробуйте позже» вместо громкого 500, который
    кто-нибудь заметит и починит.

    :param request: текущий запрос.
    :param credentials: разобранный заголовок Authorization.
    :return: проверенные claims.
    :raises HTTPException: 401, если токен отсутствует или неприемлем;
        503, если источник ключей недоступен или его документ повреждён.
    """
    if credentials is None:
        raise _unauthorized(
            "not_authenticated",
            "Authorization header with a Bearer token is required.",
        )

    verifier: AccessTokenVerifier | None = getattr(
        request.app.state,
        "access_token_verifier",
        None,
    )
    if verifier is None:
        raise RuntimeError(
            "app.state.access_token_verifier is not set; the application "
            "must configure it in its lifespan before serving requests.",
        )
    try:
        return await verifier.verify(credentials.credentials)
    except jwt.InvalidTokenError as exc:
        raise _unauthorized(
            "invalid_token",
            str(exc),
        ) from exc
    except (httpx.HTTPError, MalformedJwksDocumentError) as exc:
        raise _problem(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "auth_unavailable",
            "Unable to verify the token: the signing key source is "
            "unavailable. Try again shortly.",
        ) from exc


def _is_unrestricted(claims: AccessTokenClaims) -> bool:
    """
    Проверить, обходит ли владелец токена проверки ролей и прав.

    :param claims: claims токена.
    :return: True для админов и суперюзеров.
    """
    return claims.is_superuser or ROLE_ADMIN in claims.roles


def require_roles(*roles: str) -> Callable[..., Awaitable[AccessTokenClaims]]:
    """
    Построить зависимость, требующую хотя бы одну из указанных ролей.

    :param roles: допустимые имена ролей.
    :return: зависимость FastAPI.
    :raises ValueError: если не указано ни одной роли.
    """
    required = frozenset(roles)
    if not required:
        raise ValueError(
            "require_roles() requires at least one role; "
            "a call with no roles is a programming error.",
        )

    async def checker(
        claims: AccessTokenClaims = Depends(get_claims),
    ) -> AccessTokenClaims:
        """
        Проверить, что у владельца токена есть нужная роль.

        :param claims: claims токена.
        :return: те же claims.
        :raises HTTPException: 403, если ни одной требуемой роли нет.
        """
        if _is_unrestricted(claims) or required & frozenset(claims.roles):
            return claims
        raise _problem(
            status.HTTP_403_FORBIDDEN,
            "forbidden",
            f"Requires one of the roles: {', '.join(sorted(required))}.",
        )

    return checker


def require_permissions(
    *permissions: Permission,
) -> Callable[..., Awaitable[AccessTokenClaims]]:
    """
    Построить зависимость, требующую все указанные права.

    Права выводятся из ролей в токене, а не из базы: у сервиса, который эту
    зависимость использует, таблицы ролей нет и не будет.

    :param permissions: требуемые права.
    :return: зависимость FastAPI.
    :raises ValueError: если не указано ни одного права.
    """
    required = frozenset(permissions)
    if not required:
        raise ValueError(
            "require_permissions() requires at least one permission; "
            "a call with no permissions is a programming error.",
        )

    async def checker(
        claims: AccessTokenClaims = Depends(get_claims),
    ) -> AccessTokenClaims:
        """
        Проверить, что роли токена дают все требуемые права.

        :param claims: claims токена.
        :return: те же claims.
        :raises HTTPException: 403, если какого-то права не хватает.
        """
        if _is_unrestricted(claims):
            return claims
        if required <= permissions_for_roles(claims.roles):
            return claims
        raise _problem(
            status.HTTP_403_FORBIDDEN,
            "forbidden",
            f"Requires permissions: {', '.join(sorted(required))}.",
        )

    return checker
