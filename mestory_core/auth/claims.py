"""Модель и проверка claims access-токена."""

import uuid
from datetime import UTC, datetime

import jwt
from pydantic import BaseModel, ValidationError

JWT_ALGORITHM = "RS256"
TOKEN_TYPE_ACCESS = "access"  # noqa: S105

REQUIRED_CLAIMS = ["exp", "iat", "sub", "jti", "aud", "iss"]


class AccessTokenClaims(BaseModel):
    """Проверенные claims access-токена."""

    sub: uuid.UUID
    jti: uuid.UUID
    roles: list[str]
    is_verified: bool
    is_superuser: bool = False
    iat: int
    exp: int

    def remaining_seconds(self) -> int:
        """
        Сколько секунд токену ещё жить, считая от текущего момента.

        Именно этот TTL нужен записи в denylist: держать отозванный jti
        дольше его собственного истечения бессмысленно. Снизу ограничено
        нулём, чтобы уже истёкший токен давал не отрицательный TTL.

        :return: остаток жизни в целых секундах, никогда не отрицательный.
        """
        now = int(datetime.now(UTC).timestamp())
        return max(self.exp - now, 0)


def verify_access_token(
    token: str,
    public_key: str,
    *,
    audience: str,
    issuer: str,
) -> AccessTokenClaims:
    """
    Проверить подпись токена и разобрать его claims.

    Функция ничего не знает о том, откуда взялся ключ: `auth_service`
    передаёт свой публичный PEM, остальные сервисы — ключ, полученный из
    JWKS по `kid`.

    :param token: закодированный токен.
    :param public_key: PEM публичного ключа, которым проверяется подпись.
    :param audience: ожидаемая аудитория.
    :param issuer: ожидаемый издатель.
    :return: проверенные claims.
    :raises jwt.InvalidTokenError: если токен повреждён, истёк, подписан
        другим ключом, не является access-токеном или его claims не
        проходят валидацию модели.
    """
    payload = jwt.decode(
        token,
        public_key,
        algorithms=[JWT_ALGORITHM],
        audience=audience,
        issuer=issuer,
        options={"require": REQUIRED_CLAIMS},
    )
    if payload.get("type") != TOKEN_TYPE_ACCESS:
        raise jwt.InvalidTokenError(
            f"Expected token type {TOKEN_TYPE_ACCESS!r}, got {payload.get('type')!r}.",
        )
    try:
        return AccessTokenClaims.model_validate(payload)
    except ValidationError as exc:
        raise jwt.InvalidTokenError(
            f"Token claims failed validation: {exc}",
        ) from exc
