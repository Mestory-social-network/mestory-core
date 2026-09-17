"""Справочник категорий мест, мероприятий и публикаций."""

import enum


class Category(enum.StrEnum):
    """Категория места, мероприятия или публикации.

    Справочник статичен намеренно: он нужен профилю, местам и публикациям
    одновременно, меняется раз в полгода и не стоит таблицы в базе. Общий
    импорт гарантирует, что три сервиса не разойдутся в написании.
    """

    COFFEE = "coffee"
    RESTAURANT = "restaurant"
    BAR = "bar"
    BREAKFAST = "breakfast"
    PARK = "park"
    MUSEUM = "museum"
    CONCERT = "concert"
    EXHIBITION = "exhibition"
