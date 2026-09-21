"""Единый формат тела ошибки API."""

from pydantic import BaseModel


class ProblemDetail(BaseModel):
    """Тело ответа при ошибке.

    `code` машиночитаем и стабилен — клиент ветвится по нему. `detail`
    человекочитаем и может меняться без предупреждения.
    """

    code: str
    detail: str
