"""The marker that makes this package's annotations visible to consumers."""

import importlib.resources

import mestory_core


def test_the_package_ships_its_type_marker() -> None:
    """Without `py.typed` every name here arrives in a consumer as `Any`.

    A distribution's annotations are ignored unless it says they are
    intentional. Until this file existed, `Permission`, `AccessTokenClaims`,
    `EventPublisher`, `Event` and `EVENTS_BY_ROUTING_KEY` all reached the
    services as `Any`, so `mypy --strict` checked nothing at the one seam
    four repositories share.

    That was not theoretical: with the marker added, `auth_service` reports
    `Argument "audience" to "verify_access_token"` -- it passes a
    `list[str]` where the signature said `str`, which is harmless at
    runtime because PyJWT accepts both, and was invisible to every type
    check in the platform.

    Asserted through `importlib.resources`, which reads the *installed*
    package rather than the source tree, so a packaging change that stopped
    including the file fails here instead of silently turning the seam back
    into `Any` for everyone.
    """
    marker = importlib.resources.files(mestory_core).joinpath("py.typed")

    assert marker.is_file(), (
        "py.typed is not in the installed package; consumers will see every "
        "name in mestory_core as Any"
    )
