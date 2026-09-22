# mestory-core

Общий код сервисов Mestory: проверка access-токенов, права, категории и
контракт событий.

## Подключение

```bash
uv add git+https://github.com/Mestory-social-network/mestory-core@v0.1.2
```

Версия пинуется тегом всегда. Ломающее изменение схемы события — мажорная
версия и переходный период, в котором событие публикуется под двумя ключами.

### Как выпускается версия

Строка установки выше, `version` в `pyproject.toml` и `__version__` в
`mestory_core/__init__.py` обязаны совпадать с тегом, который на них
указывает, — иначе README инструктирует ставить версию, отличную от той,
что описывает. Поэтому выпуск версии — один коммит, а не тег на
случайный коммит:

1. В одном коммите обновить все три места сразу: строку установки в этом
   README, `version` в `pyproject.toml`, `__version__` в
   `mestory_core/__init__.py`.
2. Только после этого коммита поставить на него тег `vX.Y.Z` — не раньше
   и не отдельным коммитом после.
3. Запушить коммит и тег вместе (`git push origin main --tags`).

## Что внутри

| Модуль | Что даёт |
|---|---|
| `mestory_core.permissions` | `Permission`, `ROLE_*`, `permissions_for_roles` |
| `mestory_core.categories` | `Category` |
| `mestory_core.errors` | `ProblemDetail` |
| `mestory_core.auth.claims` | `AccessTokenClaims`, `verify_access_token` |
| `mestory_core.auth.jwks` | `JwksClient`, `UnknownSigningKeyError`, `MalformedJwksDocumentError` |
| `mestory_core.auth.verifier` | `AccessTokenVerifier` |
| `mestory_core.auth.dependencies` | `get_claims`, `require_roles`, `require_permissions` |
| `mestory_core.events.keys` | `RoutingKey`, `EXCHANGE_NAME` |
| `mestory_core.events.schemas` | классы событий (`UserRegistered`, `ProfileCreated`, …), `EVENTS_BY_ROUTING_KEY` |
| `mestory_core.events.publisher` | `EventPublisher`, `LoggingEventPublisher`, `RabbitEventPublisher` |

## Как подключить авторизацию в сервисе

Три значения, которые должен получить каждый потребитель, задаёт
`auth_service` (см. `auth_service/settings.py` и его роутер) — ошибиться
здесь означает не сломаться шумно: неверная аудитория отклоняет 401 каждый
токен, но тратит на диагностику вечер:

| Настройка | Значение |
|---|---|
| `settings.jwks_url` | `http://<хост auth_service>/api/auth/.well-known/jwks.json` |
| `settings.jwt_audience` | `mestory:api` |
| `settings.jwt_issuer` | `mestory-auth` |

Внутри сети `mestory` (см. README `mestory-infra`, раздел «Подключения
изнутри сети») это `http://mestory-traefik/api/auth/.well-known/jwks.json`.

В lifespan приложения:

```python
import httpx
from mestory_core.auth.jwks import JwksClient
from mestory_core.auth.verifier import AccessTokenVerifier

app.state.http = httpx.AsyncClient()
app.state.access_token_verifier = AccessTokenVerifier(
    JwksClient(settings.jwks_url, app.state.http),
    audience=settings.jwt_audience,
    issuer=settings.jwt_issuer,
)
```

В эндпоинте:

```python
from fastapi import Depends
from mestory_core.auth.claims import AccessTokenClaims
from mestory_core.auth.dependencies import require_permissions
from mestory_core.permissions import Permission


@router.get("/me")
async def me(
    claims: AccessTokenClaims = Depends(
        require_permissions(Permission.USER_READ_SELF),
    ),
) -> ProfileRead:
    ...
```

## Три исхода проверки токена — и почему их нельзя путать

`get_claims` (и всё, что на нём строится — `require_roles`,
`require_permissions`) различает не два исхода, а три. Путать «токен
плохой» с «не можем проверить» нельзя: сервис, отвечающий 401 во время
аварии `auth_service`, разлогинит всех пользователей, хотя ни один их
токен не стал недействительным.

| Что произошло | Что бросается | Что отвечает сервис |
|---|---|---|
| Токен неприемлем: подпись не сошлась, истёк срок, не та аудитория/издатель, не тот тип токена, claims не проходят модель | `jwt.InvalidTokenError` | `401` |
| Токен приемлем, но роли не дают нужного права | — (`require_roles`/`require_permissions` отвечают сами) | `403` |
| Документ JWKS загружен, непуст, но ключа с таким `kid` в нём нет | `mestory_core.auth.jwks.UnknownSigningKeyError`, `AccessTokenVerifier.verify` оборачивает его в `jwt.InvalidTokenError` | `401` |
| Документ JWKS получить не удалось (сеть, `auth_service` недоступен, ответ с ошибкой) | `httpx.HTTPError` и его потомки | `503` |
| Документ получен, но непригоден: ключ не RSA либо не разбирается | `mestory_core.auth.jwks.MalformedJwksDocumentError` | `503` |

Ключевая мысль: **«не можем проверить» — это не «токен плохой».**
Неизвестный `kid` при непустом, свежем документе — это реальный отказ
токена (401): такого ключа нет и не будет. А недоступность или порча
самого документа JWKS — это авария источника ключей, а не токена: `401`
здесь означал бы, что легитимные пользователи не смогут работать с
сервисом, пока `auth_service` не поднимется, хотя их токены в порядке.
`get_claims` уже разводит эти случаи по отдельным веткам `except`; тому,
кто пишет собственные обработчики поверх `AccessTokenVerifier` напрямую,
нужно сохранить то же разделение.

## Контракт событий: `EVENTS_BY_ROUTING_KEY`

`mestory_core.events.schemas.EVENTS_BY_ROUTING_KEY` — это словарь
`RoutingKey -> type[Event]`, отображающий ключ маршрутизации сообщения на
класс, которым его тело валидируется. Это единственное, ради чего контракт
пригоден со стороны потребителя: без него потребитель не может узнать,
какой моделью разобрать пришедшее сообщение.

```python
import aio_pika

from mestory_core.events.schemas import EVENTS_BY_ROUTING_KEY
from mestory_core.events.keys import RoutingKey


async def on_message(message: aio_pika.IncomingMessage) -> None:
    async with message.process():
        routing_key = RoutingKey(message.routing_key)
        event_cls = EVENTS_BY_ROUTING_KEY[routing_key]
        event = event_cls.model_validate_json(message.body)
        # дедупликация по event.event_id, затем обработка
```

Потребитель дедуплицирует по `event.event_id` (uuid4): доставка
at-least-once, одно и то же сообщение может прийти дважды.

### `LoggingEventPublisher` — только для разработки

`mestory_core.events.publisher.LoggingEventPublisher` пишет каждое
опубликованное событие в лог целиком, **включая токены подтверждения
email и сброса пароля**. Это намеренно: без почтового сервера это
единственный способ пройти подтверждение email локально. **Использовать в
production нельзя** — токены окажутся в агрегаторе логов, доступном
половине команды. Там нужен `RabbitEventPublisher`, публикующий события в
topic exchange `mestory.events` (durable, persistent-сообщения).

## Чего здесь нет намеренно

- **Зависимости от СУБД.** Ни SQLAlchemy, ни alembic: сервису, которому
  нужна лишь проверка токена, ORM не нужна.
- **Проверки denylist отозванных токенов.** Другие сервисы валидируют токен
  локально; отозванный access-токен остаётся приемлемым до истечения, не
  более 15 минут. Размен описан в README `auth-service`.
- **Выпуска токенов.** `build_access_token` остаётся в `auth-service`: он
  один владеет приватным ключом.
