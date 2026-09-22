"""Асинхронный клиент JWKS с кэшем ключей по kid."""

import asyncio
import logging
import time
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

logger = logging.getLogger(__name__)


class UnknownSigningKeyError(Exception):
    """В документе JWKS нет ключа с запрошенным kid."""


class MalformedJwksDocumentError(Exception):
    """Документ JWKS получен, но содержит ключ, непригодный для проверки.

    Отдельный тип нужен, чтобы `dependencies.get_claims` мог сузить перехват
    до по-настоящему «не можем проверить» и не глотать заодно произвольный
    `TypeError` из бага где-то в цепочке проверки токена — тот обязан
    остаться громким 500, а не притвориться аварией источника ключей.
    """


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

        Порядок внутри метода намеренно такой: (1) свежий кэш — раньше
        любого обращения к блокировке; (2) блокировка и загрузка, только
        если кэш сам ответить не может; (3) откат на устаревший, но
        непустой для этого kid кэш, если загрузка не удалась; (4)
        классификация неудачи, только если и кэш, и загрузка не дали
        ответа. Требование (1) защищает горячий путь от паразитной
        задержки: без него запрос с уже закэшированным kid ждал бы
        завершения чужой загрузки (например, вызванной шквалом токенов с
        мусорным kid) наравне с тем, кто её вызвал. Требование (3) не даёт
        аварии источника проваливать запросы, которые устаревший (но
        почти наверняка ещё валидный — RS256-ключи живут неделями) кэш мог
        обслужить сам.

        :param kid: идентификатор ключа из заголовка токена.
        :return: PEM публичного ключа.
        :raises UnknownSigningKeyError: если документ загружен, непуст, но
            ключа с таким kid в нём нет.
        :raises httpx.HTTPError: если получить документ не удалось и кэш не
            может ответить на этот kid — ни свежим, ни устаревшим
            значением. Наружу каждый раз выходит новый экземпляр той же
            ошибки (тип и сообщение те же), а не один и тот же объект —
            иначе цепочка `__traceback__` росла бы без предела на
            протяжении всей аварии.
        :raises MalformedJwksDocumentError: если документ JWKS не парсится
            как JSON, имеет не ту форму, либо содержит ключ, который не
            является RSA или иначе не может быть разобран — и кэш не может
            ответить на этот kid ни свежим, ни устаревшим значением.
        """
        # 1. Свежий кэш — первым делом и до блокировки. Кэш общий на весь
        #    документ (одна отметка `_fetched_at`), а не по kid, поэтому
        #    "свежий" здесь значит "документ не устарел по TTL". Обращение
        #    к `self._lock` (даже просто `.locked()`) для уже отвечаемого из
        #    кэша запроса — лишнее: конкурентная загрузка ради ЧУЖОГО kid не
        #    должна задерживать запрос, чей ключ уже под рукой (см. тест
        #    `test_cached_lookup_is_not_delayed_by_an_unrelated_in_flight_fetch`).
        key = self._keys.get(kid)
        if key is not None and not self._is_stale():
            return key

        # 2. Блокировка и загрузка — только если кэш не может ответить сам:
        #    kid неизвестен, либо документ устарел. Присоединяемся к уже
        #    идущей загрузке (`self._lock.locked()`) или начинаем свою.
        if self._lock.locked() or self._should_attempt_fetch(kid):
            try:
                await self._attempt_fetch(kid)
            except (httpx.HTTPError, MalformedJwksDocumentError) as exc:
                # 3. Откат на устаревший кэш — но только для двух исходов,
                #    которые на самом деле значат «не смогли получить
                #    пригодный документ»: сеть/сервер (`httpx.HTTPError`) и
                #    контракт документа (`MalformedJwksDocumentError`). Кэш
                #    (пусть и просроченный по TTL) уже содержит именно этот
                #    kid — обслуживаем запрос им, а не проваливаем его.
                #    RS256-ключи живут неделями: просроченный по TTL кэш
                #    почти наверняка всё ещё валиден, и падать здесь значит
                #    защищать источник ключей ценой чужого запроса, который
                #    кэш мог обслужить сам (см.
                #    `test_stale_cache_survives_a_failed_refresh`).
                #    Любой другой exception (программистский баг где-то в
                #    цепочке `_fetch`/`_to_pem`) обязан пройти сквозь эту
                #    ветку необработанным — иначе тёплый кэш маскировал бы
                #    его точно так же тихо, как и настоящую аварию (см.
                #    `test_bug_in_parse_path_propagates_even_with_warm_cache`).
                #    Если и стейл-кэш не спасает — перевыбрасываем как есть:
                #    именно эта ветка (а не перезаписанный `self._last_error`)
                #    даёт первому в аварии вызову «сырую» ошибку без
                #    искусственного пересоздания, как и раньше.
                key = self._keys.get(kid)
                if key is not None:
                    logger.warning(
                        "JWKS refresh failed (%s: %s); serving kid %r from "
                        "stale cache.",
                        type(exc).__name__,
                        exc,
                        kid,
                    )
                    return key
                raise

        # 4. Классификация неудачи — только когда кэш действительно не может
        #    ответить: ни свежим, ни устаревшим значением для этого kid.
        key = self._keys.get(kid)
        if key is not None:
            return key

        if self._keys:
            # Документ свежий (или ещё не устарел) и непустой — просто нет
            # такого kid. Ключи у нас есть, этот не наш.
            raise self._unknown_signing_key(kid)

        # Кэш пуст. Если это из-за недавнего сбоя загрузки — это авария
        # источника, а не «неизвестный ключ», и наружу должна выйти именно
        # она. Перевыбрасываем не сам сохранённый объект (см. `_respawn`),
        # а его свежую копию, связанную через `from` — иначе каждый вызов
        # внутри окна отката удлинял бы traceback того же самого объекта.
        if self._last_error is not None:
            raise _respawn(self._last_error) from self._last_error
        raise self._unknown_signing_key(kid)

    def _unknown_signing_key(self, kid: str) -> UnknownSigningKeyError:
        """
        Собрать `UnknownSigningKeyError` для kid, которого нет в документе.

        Сообщение исключения долетает до вызывающего кода без изменений
        (`AccessTokenVerifier.verify` заворачивает его в
        `jwt.InvalidTokenError`, `get_claims` кладёт `str(exc)` прямо в
        тело 401) — тот же класс утечки, что уже был закрыт в
        `claims.py` для деталей pydantic. Адрес JWKS полезен для
        диагностики, но не для неаутентифицированного клиента, поэтому он
        остаётся только в логе.

        :param kid: идентификатор ключа, которого нет в документе.
        :return: готовое исключение с сообщением, безопасным для 401.
        """
        logger.info("No key %r in JWKS document at %s.", kid, self._url)
        return UnknownSigningKeyError(f"No signing key found for kid {kid!r}.")

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

        Источнику не доверяем: прокси, вернувший 200 с HTML-страницей
        ошибки, обрезанным телом или структурно неверным JSON — обычный
        случай, а не экзотика. Без проверки формы такие ответы всплывали бы
        голыми `json.JSONDecodeError`/`TypeError`/`AttributeError` из
        глубины словарного включения ниже, `get_claims` не смог бы отличить
        их от программистского бага (см. `MalformedJwksDocumentError`) и
        сервис отвечал бы 500 вместо честного 503 — да ещё и на всё окно
        троттлинга: сломанный ответ оседает в `_last_error` точно так же,
        как реальная сетевая авария.

        :raises httpx.HTTPError: если запрос не удался или сервер ответил
            ошибкой.
        :raises MalformedJwksDocumentError: если тело не парсится как JSON,
            распарсенный документ не имеет ожидаемой формы (не объект,
            `keys` — не список, элемент `keys` — не объект), либо документ
            структурно валиден, но не даёт ни одного ключа, пригодного для
            проверки (`keys` отсутствует, пуст, или ни один элемент не
            несёт `kid`).
        """
        response = await self._http.get(self._url)
        response.raise_for_status()
        try:
            document: Any = response.json()
        except ValueError as exc:
            # response.json() поднимает json.JSONDecodeError — подкласс
            # ValueError — на нечитаемом как JSON теле (обрезанном,
            # HTML-странице ошибки и т.п.).
            raise MalformedJwksDocumentError(
                f"JWKS document at {self._url} is not valid JSON: {exc}",
            ) from exc

        if not isinstance(document, dict):
            raise MalformedJwksDocumentError(
                f"JWKS document at {self._url} must be a JSON object, got "
                f"{type(document).__name__}.",
            )
        # `document.get("keys", [])` подставляет [] и на отсутствующее поле,
        # и (будучи уже списком) не трогает пустой список — обе формы дальше
        # обрабатывает одна и та же проверка ниже, а не два отдельных raise.
        raw_keys = document.get("keys", [])
        if not isinstance(raw_keys, list):
            raise MalformedJwksDocumentError(
                f"JWKS document at {self._url}: field 'keys' must be a "
                f"list, got {type(raw_keys).__name__}.",
            )
        for entry in raw_keys:
            if not isinstance(entry, dict):
                raise MalformedJwksDocumentError(
                    f"JWKS document at {self._url}: entry in 'keys' must "
                    f"be an object, got {type(entry).__name__}.",
                )

        # Собираем в локальную переменную, а не прямо в self._keys: провал
        # проверки ниже не должен стирать ещё годный кэш от предыдущей
        # успешной загрузки (см. откат на устаревший кэш в get_key) —
        # неудачная попытка обязана оставить состояние клиента как было,
        # точно так же, как и все проверки формы выше.
        parsed_keys = {
            jwk["kid"]: _to_pem(jwk) for jwk in raw_keys if "kid" in jwk
        }
        # Единая точка «документ не дал ни одного пригодного ключа» —
        # раньше это были три места (отсутствующее поле 'keys', пустой
        # список, и — до этого фикса — молча отфильтрованные записи без
        # kid), с одной и той же причиной и одним и тем же исходом
        # (self._keys пуст), но разной судьбой: первые два были заранее
        # закрыты явным raise, третий — нет, потому что сам не выглядел как
        # пустой документ, пока не разваливался следующий, не связанный с
        # ним запрос. Теперь причина одна, и здесь же единственная проверка
        # для всех её форм. Различие, которое обязано остаться: НЕПУСТОЙ
        # кэш с генуинно отсутствующим kid — это по-прежнему
        # `UnknownSigningKeyError` (401), а не эта ветка — проверка ниже
        # смотрит на результат ЭТОЙ загрузки, а не на итоговый self._keys
        # после отката на устаревший кэш (см.
        # `test_unknown_kid_with_warm_cache_raises_unknown_key_not_source_error`).
        if not parsed_keys:
            raise MalformedJwksDocumentError(
                f"JWKS document at {self._url} yielded no usable signing "
                f"keys: 'keys' is missing, empty, or none of its entries "
                f"carry a 'kid'.",
            )

        self._keys = parsed_keys
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
    создание экземпляра в обход `__init__` (`cls.__new__(cls)`). Это не
    пытается угадать сигнатуру конструктора и работает для любого
    исключения без `__slots__`, но тип обязан остаться прежним в обоих
    случаях: по нему задача 9 будет отличать «не смогли проверить» от
    «токен плохой».

    `args` и `__dict__` переносятся безусловно, каким бы путём ни был
    создан `fresh`, а не только на запасном. У `httpx.RequestError` (и
    его семейства — `ConnectError`, `ReadTimeout` и прочих) параметр
    `request` в конструкторе необязателен, поэтому основной путь
    `cls(*exc.args)` не бросает `TypeError` и срабатывает как «удачный» —
    но сам объект запроса httpx привязывает к исключению уже ПОСЛЕ
    конструктора (`exc.request = request` в `request_context`). Без
    безусловного переноса `__dict__` эта привязка терялась бы у
    пересозданного исключения, и `fresh.request` бросал бы
    `RuntimeError`. `__cause__`, `__context__` и `__traceback__` в CPython
    не хранятся в `__dict__` — это отдельные слоты, — поэтому перенос
    `__dict__` не утаскивает за собой ту самую накопленную цепочку,
    ради избавления от которой всё и затевалось.

    :param exc: сохранённая ошибка предыдущей попытки.
    :return: новый экземпляр того же типа с тем же сообщением и состоянием.
    """
    cls = type(exc)
    try:
        fresh = cls(*exc.args)
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

    Ключ приходит из документа, которому мы не доверяем, и разобрать его
    может не получиться по-разному:

    - `jwt.PyJWK.from_dict` бросает `jwt.InvalidKeyError` (наследует
      `jwt.PyJWTError` напрямую, а не `jwt.PyJWKError`, — проверено
      экспериментально на PyJWT 2.14.0) для отсутствующего или
      неподдерживаемого `kty`/`crv` и для битого материала ключа
      (например, `n` с некорректным base64url);
    - тот же `from_dict` бросает `jwt.PyJWKError` напрямую, если для
      ключа не нашёлся алгоритм, и `jwt.MissingCryptographyError`
      (подкласс `jwt.PyJWKError`), если для алгоритма не хватает
      экстра-зависимости `cryptography` — оба задокументированы в
      докстринге `jwt.PyJWK.__init__`;
    - ключ, который `from_dict` разобрал успешно, но не RSA, детектируется
      уже здесь и раньше поднимался как голый `TypeError`.

    Все эти случаи — порча самого документа, а не баг в нашем коде, поэтому
    ни один из исходных типов не выходит наружу как есть: все оборачиваются
    в `MalformedJwksDocumentError` с сохранением причины через `from`.
    Вызывающий код (`dependencies.get_claims`) обязан узко ловить именно
    «документ сломан», а не любой `TypeError` или `jwt.PyJWTError` вообще —
    иначе он заодно проглотил бы и настоящий программистский баг,
    случившийся где-то дальше по цепочке проверки токена.

    :param jwk: один ключ из документа JWKS.
    :return: PEM публичного ключа.
    :raises MalformedJwksDocumentError: если ключ не является RSA-ключом
        либо иначе не может быть разобран.
    """
    try:
        key = jwt.PyJWK.from_dict(jwk).key
        if not isinstance(key, RSAPublicKey):
            raise TypeError(
                f"Only RSA keys are supported, got {type(key).__name__}.",
            )
    except (TypeError, jwt.InvalidKeyError, jwt.PyJWKError) as exc:
        raise MalformedJwksDocumentError(str(exc)) from exc
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
