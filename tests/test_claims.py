import base64
import hashlib
import hmac
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from mestory_core.auth.claims import AccessTokenClaims, verify_access_token
from tests.conftest import AUDIENCE, ISSUER


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _forge_hs256_token(payload: dict[str, object], secret: str) -> str:
    """
    Собрать HS256-токен вручную, в обход собственной защиты PyJWT.

    `jwt.encode(..., algorithm="HS256")` отказывается использовать PEM-ключ
    как HMAC-секрет ("asymmetric key... should not be used as an HMAC
    secret") — это подсказка на этапе выпуска, а не на этапе проверки.
    Атакующий, подделывающий токен, эту подсказку игнорирует и просто
    хэширует байты публичного PEM вручную. Именно это здесь и делается,
    чтобы протестировать защиту verify_access_token на этапе decode
    (`algorithms=[JWT_ALGORITHM]`), а не защиту PyJWT на этапе encode.

    :param payload: claims токена (timestamps — уже int, не datetime).
    :param secret: строка, используемая как HMAC-секрет.
    :return: собранный JWT.
    """
    header_b64 = _b64url(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode(),
    )
    payload_b64 = _b64url(
        json.dumps(payload, separators=(",", ":")).encode(),
    )
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{signing_input.decode()}.{_b64url(signature)}"


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


def test_unknown_claim_is_ignored_not_rejected(
    key_pair: tuple[str, str],
    make_token: Callable[..., str],
) -> None:
    """Claim, которого модель не знает, не валит токен.

    Регрессия для отложенного пункта 15: `extra="ignore"` в
    `AccessTokenClaims` — платформенный инвариант (`auth_service` обязан
    мочь добавить новый claim и выкатить его раньше, чем эта библиотека
    научится его понимать, не обрывая 401 уже живые сессии), а не просто
    унаследованное по умолчанию поведение pydantic. Явное объявление нужно
    покрыть тестом, а не полагаться на то, что дефолт фреймворка не
    поменяется.
    """
    _, public_pem = key_pair

    claims = verify_access_token(
        make_token(future_claim_from_auth_service="not modelled yet"),
        public_pem,
        audience=AUDIENCE,
        issuer=ISSUER,
    )

    assert not hasattr(claims, "future_claim_from_auth_service")


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


def test_broken_roles_field_is_rejected_as_invalid_token(
    key_pair: tuple[str, str],
    make_token: Callable[..., str],
) -> None:
    """Подписанный токен со сломанным полем roles не течёт наружу как ValidationError.

    Задача 9 строит поверх verify_access_token FastAPI-зависимость, которая
    ловит ровно jwt.InvalidTokenError и превращает его в 401. Необёрнутая
    pydantic.ValidationError не наследует InvalidTokenError и вылетела бы
    наружу как необработанный 500.
    """
    _, public_pem = key_pair

    with pytest.raises(jwt.InvalidTokenError):
        verify_access_token(
            make_token(roles="не список"),
            public_pem,
            audience=AUDIENCE,
            issuer=ISSUER,
        )


def test_broken_is_verified_field_is_rejected_as_invalid_token(
    key_pair: tuple[str, str],
    make_token: Callable[..., str],
) -> None:
    """Подписанный токен со сломанным полем is_verified даёт InvalidTokenError."""
    _, public_pem = key_pair

    with pytest.raises(jwt.InvalidTokenError):
        verify_access_token(
            make_token(is_verified=None),
            public_pem,
            audience=AUDIENCE,
            issuer=ISSUER,
        )


def test_broken_claim_error_message_does_not_leak_pydantic_internals(
    key_pair: tuple[str, str],
    make_token: Callable[..., str],
) -> None:
    """Сообщение об ошибке — фиксированная строка, а не текст pydantic.

    Регрессия для M3: `ValidationError` pydantic несёт имена внутренних
    полей модели, эхо присланных значений и ссылки на
    errors.pydantic.dev — ни то, ни другое не должно попасть в текст
    исключения, который `dependencies.get_claims` кладёт прямиком в тело
    публичного 401-ответа.
    """
    _, public_pem = key_pair

    with pytest.raises(jwt.InvalidTokenError) as excinfo:
        verify_access_token(
            make_token(is_verified="не bool"),
            public_pem,
            audience=AUDIENCE,
            issuer=ISSUER,
        )

    message = str(excinfo.value)
    assert message == "Token claims failed validation."
    assert "is_verified" not in message
    assert "pydantic.dev" not in message


def test_hs256_signed_token_is_rejected(key_pair: tuple[str, str]) -> None:
    """Токен, подписанный HS256 с публичным PEM в роли HMAC-секрета, не проходит.

    Классическая атака подмены алгоритма: если бы verify_access_token
    принимала произвольный алгоритм из списка, включающий HS256, публичный
    RSA-ключ, который все стороны считают публичным, можно было бы
    использовать как общий HMAC-секрет для подделки токена.
    """
    _, public_pem = key_pair
    issued_at = int(datetime.now(UTC).timestamp())
    payload = {
        "sub": str(uuid.uuid4()),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "jti": str(uuid.uuid4()),
        "type": "access",
        "roles": ["user"],
        "is_verified": True,
        "iat": issued_at,
        "exp": issued_at + int(timedelta(minutes=15).total_seconds()),
    }
    forged = _forge_hs256_token(payload, public_pem)

    with pytest.raises(jwt.InvalidTokenError):
        verify_access_token(
            forged,
            public_pem,
            audience=AUDIENCE,
            issuer=ISSUER,
        )


def test_alg_none_token_is_rejected(key_pair: tuple[str, str]) -> None:
    """Неподписанный токен с alg: none не проходит проверку."""
    _, public_pem = key_pair
    issued_at = datetime.now(UTC)
    payload = {
        "sub": str(uuid.uuid4()),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "jti": str(uuid.uuid4()),
        "type": "access",
        "roles": ["user"],
        "is_verified": True,
        "iat": issued_at,
        "exp": issued_at + timedelta(minutes=15),
    }
    # Стаб PyJWT не допускает key=None в сигнатуре, хотя alg "none" именно
    # этого и требует во время выполнения.
    unsigned = jwt.encode(payload, key=None, algorithm="none")  # type: ignore[arg-type]

    with pytest.raises(jwt.InvalidTokenError):
        verify_access_token(
            unsigned,
            public_pem,
            audience=AUDIENCE,
            issuer=ISSUER,
        )


def test_remaining_seconds_is_never_negative() -> None:
    """У истёкшего токена остаток равен нулю, а не отрицательному числу."""
    past = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())
    claims = AccessTokenClaims(
        sub=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        jti=uuid.UUID("00000000-0000-0000-0000-000000000002"),
        roles=["user"],
        is_verified=True,
        iat=past,
        exp=past,
    )

    assert claims.remaining_seconds() == 0
