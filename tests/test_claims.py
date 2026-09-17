from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from mestory_core.auth.claims import AccessTokenClaims, verify_access_token
from tests.conftest import AUDIENCE, ISSUER


def test_valid_token_is_parsed(
    key_pair: tuple[str, str],
    make_token: Callable[..., str],
) -> None:
    """Корректный токен разбирается в claims."""
    _, public_pem = key_pair

    claims = verify_access_token(
        make_token(roles=["user", "moderator"]),
        public_pem,
        audience=AUDIENCE,
        issuer=ISSUER,
    )

    assert claims.roles == ["user", "moderator"]
    assert claims.is_verified is True


def test_is_superuser_defaults_to_false(
    key_pair: tuple[str, str],
    make_token: Callable[..., str],
) -> None:
    """Токен без is_superuser разбирается, а не падает.

    Токены, выпущенные до появления поля, живут ещё 15 минут после деплоя.
    Отсутствие значения по умолчанию уронило бы все живые сессии.
    """
    _, public_pem = key_pair

    claims = verify_access_token(
        make_token(),
        public_pem,
        audience=AUDIENCE,
        issuer=ISSUER,
    )

    assert claims.is_superuser is False


def test_is_superuser_is_read_when_present(
    key_pair: tuple[str, str],
    make_token: Callable[..., str],
) -> None:
    """Если поле есть, оно попадает в claims."""
    _, public_pem = key_pair

    claims = verify_access_token(
        make_token(is_superuser=True),
        public_pem,
        audience=AUDIENCE,
        issuer=ISSUER,
    )

    assert claims.is_superuser is True


def test_refresh_token_type_is_rejected(
    key_pair: tuple[str, str],
    make_token: Callable[..., str],
) -> None:
    """Токен другого типа не принимается как access."""
    _, public_pem = key_pair

    with pytest.raises(jwt.InvalidTokenError):
        verify_access_token(
            make_token(type="refresh"),
            public_pem,
            audience=AUDIENCE,
            issuer=ISSUER,
        )


def test_wrong_audience_is_rejected(
    key_pair: tuple[str, str],
    make_token: Callable[..., str],
) -> None:
    """Токен, выпущенный для другой аудитории, не принимается."""
    _, public_pem = key_pair

    with pytest.raises(jwt.InvalidTokenError):
        verify_access_token(
            make_token(aud="someone-else"),
            public_pem,
            audience=AUDIENCE,
            issuer=ISSUER,
        )


def test_expired_token_is_rejected(
    key_pair: tuple[str, str],
    make_token: Callable[..., str],
) -> None:
    """Истёкший токен не принимается."""
    _, public_pem = key_pair
    past = datetime.now(UTC) - timedelta(hours=1)

    with pytest.raises(jwt.InvalidTokenError):
        verify_access_token(
            make_token(iat=past, exp=past + timedelta(minutes=15)),
            public_pem,
            audience=AUDIENCE,
            issuer=ISSUER,
        )


def test_remaining_seconds_is_never_negative() -> None:
    """У истёкшего токена остаток равен нулю, а не отрицательному числу."""
    past = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())
    claims = AccessTokenClaims(
        sub="00000000-0000-0000-0000-000000000001",
        jti="00000000-0000-0000-0000-000000000002",
        roles=["user"],
        is_verified=True,
        iat=past,
        exp=past,
    )

    assert claims.remaining_seconds() == 0
