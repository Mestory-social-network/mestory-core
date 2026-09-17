def test_package_exposes_a_version() -> None:
    """Пакет публикует свою версию — по ней сервисы пинуют зависимость."""
    import mestory_core

    assert isinstance(mestory_core.__version__, str)
    assert mestory_core.__version__
