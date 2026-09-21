"""Проверка access-токенов по ключам из JWKS."""

import jwt

from mestory_core.auth.claims import AccessTokenClaims, verify_access_token
from mestory_core.auth.jwks import JwksClient, UnknownSigningKeyError


class AccessTokenVerifier:
    """Проверяет access-токены, получая ключи из JWKS издателя.

    Denylist отозванных токенов принципиально не проверяется: другие сервисы
    валидируют токен локально, и отозванный access-токен остаётся приемлемым
    до своего истечения — не более 15 минут. Это осознанный размен, описанный
    в README auth_service.
    """

    def __init__(
        self,
        jwks: JwksClient,
        *,
        audience: str,
        issuer: str,
    ) -> None:
        """
        Инициализировать верификатор.

        :param jwks: клиент, отдающий публичные ключи по kid.
        :param audience: ожидаемая аудитория токена.
        :param issuer: ожидаемый издатель токена.
        """
        self._jwks = jwks
        self._audience = audience
        self._issuer = issuer

    async def verify(self, token: str) -> AccessTokenClaims:
        """
        Проверить токен и вернуть его claims.

        Ошибки недоступности источника ключей (`httpx.HTTPError` и его
        потомки, а также `MalformedJwksDocumentError` из сломанного
        документа JWKS) нарочно не перехватываются здесь и уходят наружу
        как есть: это не «токен плохой», а «мы не можем проверить», и
        заворачивать их в `jwt.InvalidTokenError` означало бы неотличимо
        превратить аварию источника в 401 для всех пользователей сразу.

        :param token: закодированный токен.
        :return: проверенные claims.
        :raises jwt.InvalidTokenError: если токен неприемлем по любой
            причине, включая неизвестный kid.
        :raises httpx.HTTPError: если документ JWKS получить не удалось.
        :raises MalformedJwksDocumentError: если документ JWKS получен, но
            повреждён (ключ не является RSA либо иначе не разобрать).
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.DecodeError as exc:
            raise jwt.InvalidTokenError(str(exc)) from exc

        kid = header.get("kid")
        if not kid:
            raise jwt.InvalidTokenError("Token header carries no 'kid'.")

        try:
            public_key = await self._jwks.get_key(kid)
        except UnknownSigningKeyError as exc:
            raise jwt.InvalidTokenError(str(exc)) from exc

        return verify_access_token(
            token,
            public_key,
            audience=self._audience,
            issuer=self._issuer,
        )
