from unittest.mock import MagicMock, patch

import pytest
from ipwhois import ASNRegistryError, HTTPLookupError  # type: ignore

from cidr_resolver import CidrResolver, check_throttle
from utilities.file_cache import FileCache
from utilities.network import WhoisStrategy


@pytest.fixture
def mock_cache() -> FileCache[str, str]:
    return MagicMock(spec=FileCache)


@pytest.fixture
def mock_strategy() -> WhoisStrategy:
    return MagicMock(spec=WhoisStrategy)


def test_get_cidr_cached_ip_cidr_resolver(
    mock_cache: FileCache[str, str],
    mock_strategy: WhoisStrategy
) -> None:
    mock_cache.__contains__.return_value = True
    mock_cache.__getitem__.return_value = "192.0.2.0/24"

    resolver = CidrResolver(mock_cache, mock_strategy)
    result = resolver.get_cidr("192.0.2.1")

    assert result == "192.0.2.0/24"
    mock_cache.__getitem__.assert_called_once_with("192.0.2.1")


def test_get_cidr_uncached_ip_cidr_resolver(
    mock_cache: FileCache[str, str],
    mock_strategy: WhoisStrategy
) -> None:
    mock_cache.__contains__.return_value = False
    mock_strategy.get_cidr.return_value = "198.51.100.0/24"

    resolver = CidrResolver(mock_cache, mock_strategy)
    result = resolver.get_cidr("198.51.100.1")

    assert result == "198.51.100.0/24"
    mock_strategy.get_cidr.assert_called_once_with("198.51.100.1")
    mock_cache.__setitem__.assert_called_once_with(
        "198.51.100.1", "198.51.100.0/24"
    )


@pytest.mark.parametrize("exc", [
    HTTPLookupError("fail"),
    ASNRegistryError("fail"),
    ConnectionResetError("fail")
])
def test_get_cidr_recoverable_error_cidr_resolver(
    exc: Exception,
    mock_cache: FileCache[str, str],
    mock_strategy: WhoisStrategy
) -> None:
    mock_cache.__contains__.return_value = False
    mock_strategy.get_cidr.side_effect = exc

    resolver = CidrResolver(mock_cache, mock_strategy)

    with pytest.raises(type(exc)):
        resolver.get_cidr("203.0.113.1")


def test_get_cidr_unexpected_error_cidr_resolver(
    mock_cache: FileCache[str, str],
    mock_strategy: WhoisStrategy
) -> None:
    mock_cache.__contains__.return_value = False
    mock_strategy.get_cidr.side_effect = RuntimeError("unexpected")

    resolver = CidrResolver(mock_cache, mock_strategy)

    with pytest.raises(RuntimeError):
        resolver.get_cidr("203.0.113.2")


def test_resolve_ip_with_cidr_input_cidr_resolver(
    mock_cache: FileCache[str, str],
    mock_strategy: WhoisStrategy
) -> None:
    resolver = CidrResolver(mock_cache, mock_strategy)
    result = resolver.resolve_ip("192.0.2.0/24")
    assert result == "192.0.2.0/24"


def test_resolve_ip_with_ip_input_cidr_resolver(
    mock_cache: FileCache[str, str],
    mock_strategy: WhoisStrategy
) -> None:
    mock_cache.__contains__.return_value = False
    mock_strategy.get_cidr.return_value = "192.0.2.0/24"

    resolver = CidrResolver(mock_cache, mock_strategy)
    result = resolver.resolve_ip("192.0.2.1")

    assert result == "192.0.2.0/24"


def test_aggregate_ips_success_and_failure_cidr_resolver(
    mock_cache: FileCache[str, str],
    mock_strategy: WhoisStrategy
) -> None:
    mock_cache.__contains__.side_effect = [False, False]
    mock_strategy.get_cidr.side_effect = [
        "192.0.2.0/24",
        RuntimeError("fail")
    ]

    resolver = CidrResolver(mock_cache, mock_strategy)

    with patch("cidr_resolver.check_throttle") as _:
        result, failed = resolver.aggregate_ips(
            ["192.0.2.1", "203.0.113.1"]
        )

    assert result == ["192.0.2.0/24"]
    assert failed == ["203.0.113.1"]


def test_check_throttle_triggers_sleep() -> None:
    with patch("time.sleep") as mock_sleep:
        check_throttle(10, 10, 5)
        mock_sleep.assert_called_once_with(5)


def test_check_throttle_does_not_trigger_sleep() -> None:
    with patch("time.sleep") as mock_sleep:
        check_throttle(9, 10, 5)
        mock_sleep.assert_not_called()
