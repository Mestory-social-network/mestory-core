"""Общие фикстуры: ключи и токены для тестов авторизации."""

import base64
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# Реальные значения auth_service (auth_service/settings.py): расхождение
# здесь означало бы, что тесты проверяют не ту аудиторию/издателя, которые
# сервисы получают в проде, и не заметили бы неверную настройку.
AUDIENCE = "mestory:api"
ISSUER = "mestory-auth"


def jwks_document(public_pem: str, kid: str) -> dict[str, Any]:
    """
    Собрать документ JWKS так же, как его отдаёт auth_service.

    Живёт в conftest, потому что нужен и тестам JWKS-клиента, и тестам
    зависимостей авторизации.

    :param public_pem: PEM публичного ключа.
    :param kid: идентификатор ключа.
    :return: документ JWKS.
    """
    public_key = serialization.load_pem_public_key(public_pem.encode())
    assert isinstance(public_key, RSAPublicKey)
    numbers = public_key.public_numbers()

    def b64url(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": b64url(numbers.n),
                "e": b64url(numbers.e),
            },
        ],
    }


@pytest.fixture(scope="session")
def key_pair() -> tuple[str, str]:
    """
    Сгенерировать пару RSA-ключей на весь прогон.

    :return: кортеж (приватный PEM, публичный PEM).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture
def make_token(key_pair: tuple[str, str]) -> Callable[..., str]:
    """
    Вернуть фабрику подписанных токенов с переопределяемыми полями.

    :param key_pair: пара ключей прогона.
    :return: фабрика токенов.
    """
    private_pem, _ = key_pair

    def factory(*, kid: str = "test-kid", **overrides: Any) -> str:
        issued_at = datetime.now(UTC)
        payload: dict[str, Any] = {
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
        payload.update(overrides)
        return jwt.encode(
            payload,
            private_pem,
            algorithm="RS256",
            headers={"kid": kid},
        )

    return factory
