from mestory_core.categories import Category


def test_categories_cover_the_mvp_board() -> None:
    """Справочник совпадает с категориями с MVP-доски."""  # noqa: RUF002
    assert {category.value for category in Category} == {
        "coffee",
        "restaurant",
        "bar",
        "breakfast",
        "park",
        "museum",
        "concert",
        "exhibition",
    }


def test_category_is_a_string() -> None:
    """Категория сериализуется как строка — она едет в JSON и в БД."""
    assert Category.COFFEE == "coffee"
