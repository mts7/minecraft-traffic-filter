from unittest.mock import MagicMock

import pytest
from ipwhois import IPDefinedError  # type: ignore

from utilities.network import WhoisStrategy, format_block_line, is_cidr


def test_get_cidr_success_whois_strategy() -> None:
    mock_obj = MagicMock()
    mock_obj.lookup_rdap.return_value = {"asn_cidr": "192.0.2.0/24"}
    mock_factory = MagicMock(return_value=mock_obj)

    strategy = WhoisStrategy(mock_factory)
    result = strategy.get_cidr("192.0.2.1")

    assert result == "192.0.2.0/24"
    mock_factory.assert_called_once_with("192.0.2.1")
    mock_obj.lookup_rdap.assert_called_once_with(depth=1)


def test_get_cidr_ipdefinederror_whois_strategy() -> None:
    mock_factory = MagicMock(side_effect=IPDefinedError("Reserved IP"))

    strategy = WhoisStrategy(mock_factory)

    with pytest.raises(IPDefinedError):
        strategy.get_cidr("127.0.0.1")


def test_get_cidr_generic_exception_whois_strategy() -> None:
    mock_obj = MagicMock()
    mock_obj.lookup_rdap.side_effect = RuntimeError("RDAP failed")
    mock_factory = MagicMock(return_value=mock_obj)

    strategy = WhoisStrategy(mock_factory)

    with pytest.raises(RuntimeError):
        strategy.get_cidr("198.51.100.1")


def test_is_cidr_valid_cidr() -> None:
    assert is_cidr("192.0.2.0/24") is True


def test_is_cidr_valid_ip_not_cidr() -> None:
    assert is_cidr("192.0.2.1") is False


def test_is_cidr_invalid_ip() -> None:
    assert is_cidr("invalid-ip") is False


def test_format_block_line_valid_cidr() -> None:
    result = format_block_line("203.0.113.0/24")
    assert result == "block drop from 203.0.113.0/24 to any"
