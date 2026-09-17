"""Асинхронный клиент JWKS с кэшем ключей по kid."""

import asyncio
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

    Единственный полёт к источнику держит `asyncio.Lock`. Вызов, заставший
    загрузку уже в процессе, дожидается её — иначе он рисковал бы прочитать
    кэш раньше, чем эта загрузка его обновит, и ошибочно отверг бы валидный
    (например, только что провернутый) ключ. Вызов, заставший кэш просто
    устаревшим или kid — неизвестным, без активной загрузки, перепроверяет
    условие уже под блокировкой: иначе троттлинг работал бы только на
    последовательной нагрузке, а параллельная обходила бы его целиком.
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
        :param min_refetch_interval: минимальный промежуток между попытками
            перезагрузки документа — вызванными ли неизвестным kid, или
            провалом предыдущей попытки.
        :raises ValueError: если `ttl` меньше `min_refetch_interval` — иначе
            плановая перезагрузка по истечении TTL срабатывала бы чаще, чем
            допускает окно троттлинга, тихо обходя защиту и для обычного,
            не подозрительного трафика.
        """
        if ttl < min_refetch_interval:
            raise ValueError(
                "ttl must be >= min_refetch_interval, got "
                f"ttl={ttl!r}, min_refetch_interval={min_refetch_interval!r}.",
            )
        self._url = url
        self._http = http
        self._ttl = ttl
        self._min_refetch_interval = min_refetch_interval
        self._keys: dict[str, str] = {}
        self._fetched_at: float | None = None
        self._last_attempt_at: float = float("-inf")
        self._last_error: Exception | None = None
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> str:
        """
        Вернуть публичный ключ в PEM по его kid.

        :param kid: идентификатор ключа из заголовка токена.
        :return: PEM публичного ключа.
        :raises UnknownSigningKeyError: если документ загружен, непуст, но
            ключа с таким kid в нём нет.
        :raises httpx.HTTPError: если получить документ не удалось — этой
            попыткой или последней, чья ошибка ещё не сброшена успешной
            загрузкой (при этом кэш пуст, а окно троттлинга не позволяет
            попробовать снова прямо сейчас). Это не «неизвестный kid»: без
            разделения источник, лежащий во время аварии, разлогинил бы
            всех пользователей вместо честного 503. Наружу каждый раз
            выходит новый экземпляр той же ошибки (тип и сообщение те же),
            а не один и тот же объект — иначе цепочка `__traceback__` росла
            бы без предела на протяжении всей аварии.
        :raises TypeError: если ключ в документе JWKS не является RSA.
        """
        if self._lock.locked() or self._should_attempt_fetch(kid):
            await self._attempt_fetch(kid)

        key = self._keys.get(kid)
        if key is not None:
            return key

        if self._keys:
            # Документ свежий (или ещё не устарел) и непустой — просто нет
            # такого kid. Ключи у нас есть, этот не наш.
            raise UnknownSigningKeyError(f"No key {kid!r} in JWKS at {self._url}.")

        # Кэш пуст. Если это из-за недавнего сбоя загрузки — это авария
        # источника, а не «неизвестный ключ», и наружу должна выйти именно
        # она. Перевыбрасываем не сам сохранённый объект (см. `_respawn`),
        # а его свежую копию, связанную через `from` — иначе каждый вызов
        # внутри окна отката удлинял бы traceback того же самого объекта.
        if self._last_error is not None:
            raise _respawn(self._last_error) from self._last_error
        raise UnknownSigningKeyError(f"No key {kid!r} in JWKS at {self._url}.")

    def _should_attempt_fetch(self, kid: str) -> bool:
        """
        Определить, оправдана ли новая попытка загрузить документ.

        :param kid: идентификатор ключа, ради которого вызван `get_key`.
        :return: True, если кэш пора обновить (по TTL или из-за
            отсутствующего kid) и окно троттлинга это позволяет.
        """
        needs_refresh = self._is_stale() or kid not in self._keys
        return needs_refresh and self._may_refetch()

    async def _attempt_fetch(self, kid: str) -> None:
        """
        Загрузить документ под блокировкой, если это всё ещё нужно.

        Условие перепроверяется внутри блокировки: пока эта корутина
        дожидалась освобождения, документ мог уже обновить кто-то другой
        (или окно троттлинга — ещё не истечь для новой попытки). Без
        повторной проверки конкурентные вызовы, заставшие одно и то же
        «нужно грузить» до захвата блокировки, дошли бы до сети все разом —
        троттлинг существовал бы только на бумаге.

        :param kid: идентификатор ключа, ради которого вызван `get_key`.
        """
        async with self._lock:
            if not self._should_attempt_fetch(kid):
                return
            self._last_attempt_at = time.monotonic()
            try:
                await self._fetch()
            except Exception as exc:
                self._last_error = exc
                raise
            else:
                self._last_error = None

    def _is_stale(self) -> bool:
        """
        Проверить, истёк ли срок годности кэша.

        :return: True, если документ ни разу не был загружен успешно, либо
            с последней успешной загрузки прошло не меньше `ttl`.
        """
        if self._fetched_at is None:
            return True
        return (time.monotonic() - self._fetched_at) >= self._ttl

    def _may_refetch(self) -> bool:
        """
        Проверить, истекло ли окно троттлинга с последней попытки.

        Попытка считается вне зависимости от исхода: и успешная загрузка, и
        сбой источника двигают отметку. Если считать только успехи (как в
        исходной реализации), `_fetched_at` при постоянно падающем источнике
        никогда не проставляется, кэш вечно кажется «устаревшим», и каждый
        входящий запрос порождает новую попытку — окно троттлинга просто не
        участвует в этом пути.

        :return: True, если окно троттлинга истекло.
        """
        return (
            time.monotonic() - self._last_attempt_at
        ) >= self._min_refetch_interval

    async def _fetch(self) -> None:
        """
        Загрузить документ JWKS и заменить им кэш.

        :raises httpx.HTTPError: если запрос не удался или сервер ответил
            ошибкой.
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


def _respawn(exc: Exception) -> Exception:
    """
    Создать свежий экземпляр той же ошибки, не трогая и не мутируя исходный.

    Нужен, чтобы повторно "поднять" запомненную ошибку источника, не
    перевыбрасывая один и тот же объект: `raise exc` на уже поднятом `exc`
    удлиняет его `__traceback__` на кадры текущего вызова, и без предела —
    все 30 (и больше) отказов подряд внутри окна отката растили бы одну и
    ту же цепочку, пока авария не закончится.

    Сперва пробуем вызвать обычный конструктор с теми же позиционными
    `args` — это работает для подавляющего большинства исключений и
    уважает их собственную логику `__init__`. У части исключений `httpx`
    (например, `HTTPStatusError`) конструктор требует keyword-only
    `request`/`response`, которых нет в `args` — тогда откатываемся на
    создание экземпляра в обход `__init__` (`cls.__new__(cls)`) и переносим
    `args` и `__dict__` напрямую. Это не пытается угадать сигнатуру
    конструктора и работает для любого исключения без `__slots__`, но тип
    обязан остаться прежним в обоих случаях: по нему задача 9 будет
    отличать «не смогли проверить» от «токен плохой».

    :param exc: сохранённая ошибка предыдущей попытки.
    :return: новый экземпляр того же типа с тем же сообщением и состоянием.
    """
    cls = type(exc)
    try:
        return cls(*exc.args)
    except TypeError:
        # `object.__new__(cls)` отказывается работать напрямую, когда у
        # cls переопределён __init__, но не __new__ (Python считает это
        # небезопасным и просит звать `cls.__new__` явно) — используем
        # его, а не `object.__new__`.
        fresh = cls.__new__(cls)
        fresh.args = exc.args
        fresh.__dict__.update(exc.__dict__)
        return fresh


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
