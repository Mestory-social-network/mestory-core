from mestory_core.categories import Category


def test_categories_cover_the_mvp_board() -> None:
    """Справочник совпадает с категориями с MVP-доски."""
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
    # mypy считает Literal[Category.COFFEE] и Literal["coffee"] непересекающимися
    # типами, хотя во время выполнения StrEnum делает их равными, — это и
    # проверяется здесь.
    assert Category.COFFEE == "coffee"  # type: ignore[comparison-overlap]
