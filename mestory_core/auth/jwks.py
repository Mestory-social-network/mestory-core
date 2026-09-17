"""Асинхронный клиент JWKS с кэшем ключей по kid."""

import time
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class UnknownSigningKeyError(Exception):
    """В документе JWKS нет ключа с запрошенным kid."""


class JwksClient:
    """Отдаёт публичные ключи по kid, держа документ JWKS в памяти.

    Свой клиент вместо `jwt.PyJWKClient` по одной причине: штатный
    синхронный и на сетевом запросе блокирует event loop целиком.
    """

    def __init__(
        self,
        url: str,
        http: httpx.AsyncClient,
        *,
        ttl: float = 3600.0,
        min_refetch_interval: float = 30.0,
    ) -> None:
        """
        Инициализировать клиент.

        :param url: адрес документа JWKS.
        :param http: клиент, которым выполняются запросы.
        :param ttl: сколько секунд кэш считается свежим.
        :param min_refetch_interval: минимальный промежуток между
            перезагрузками документа, вызванными неизвестным kid.
        """
        self._url = url
        self._http = http
        self._ttl = ttl
        self._min_refetch_interval = min_refetch_interval
        self._keys: dict[str, str] = {}
        self._fetched_at: float | None = None

    async def get_key(self, kid: str) -> str:
        """
        Вернуть публичный ключ в PEM по его kid.

        :param kid: идентификатор ключа из заголовка токена.
        :return: PEM публичного ключа.
        :raises UnknownSigningKeyError: если ключа нет в документе, либо он
            отсутствует и окно троттлинга ещё не истекло.
        :raises httpx.HTTPStatusError: если документ не удалось получить.
        """
        if self._is_stale():
            await self._fetch()

        key = self._keys.get(kid)
        if key is not None:
            return key

        if not self._may_refetch():
            raise UnknownSigningKeyError(
                f"No key {kid!r} in JWKS, and the refetch window has not elapsed.",
            )

        await self._fetch()
        key = self._keys.get(kid)
        if key is None:
            raise UnknownSigningKeyError(f"No key {kid!r} in JWKS at {self._url}.")
        return key

    def _is_stale(self) -> bool:
        """
        Проверить, истёк ли срок годности кэша.

        :return: True, если документ ни разу не загружался или устарел.
        """
        if self._fetched_at is None:
            return True
        return (time.monotonic() - self._fetched_at) >= self._ttl

    def _may_refetch(self) -> bool:
        """
        Проверить, разрешена ли перезагрузка из-за неизвестного kid.

        Без этого ограничения поток токенов с выдуманным kid превращается в
        поток запросов к auth_service — то есть в отказ в обслуживании,
        устроенный нашими же руками.

        :return: True, если окно троттлинга истекло.
        """
        if self._fetched_at is None:
            return True
        return (time.monotonic() - self._fetched_at) >= self._min_refetch_interval

    async def _fetch(self) -> None:
        """
        Загрузить документ JWKS и заменить им кэш.

        :raises httpx.HTTPStatusError: если сервер ответил ошибкой.
        """
        response = await self._http.get(self._url)
        response.raise_for_status()
        document: dict[str, Any] = response.json()
        self._keys = {
            jwk["kid"]: _to_pem(jwk)
            for jwk in document.get("keys", [])
            if "kid" in jwk
        }
        self._fetched_at = time.monotonic()


def _to_pem(jwk: dict[str, Any]) -> str:
    """
    Преобразовать элемент JWKS в PEM публичного ключа.

    :param jwk: один ключ из документа JWKS.
    :return: PEM публичного ключа.
    :raises TypeError: если ключ не является RSA-ключом.
    """
    key = jwt.PyJWK.from_dict(jwk).key
    if not isinstance(key, RSAPublicKey):
        raise TypeError(f"Only RSA keys are supported, got {type(key).__name__}.")
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
