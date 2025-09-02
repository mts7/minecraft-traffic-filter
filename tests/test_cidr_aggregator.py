import builtins
import json
from typing import Dict, List, Tuple
from unittest.mock import MagicMock, mock_open, patch

import pytest

from cidr_aggregator import (CACHE_FILE, aggregate_ips, format_block_line,
                             get_cidr_ipwhois, is_cidr, load_cache, main,
                             save_cache)


@patch("os.path.exists", return_value=False)
def test_load_cache_file_missing(mock_exists: MagicMock) -> None:
    result: Dict[str, str] = load_cache("file.json")
    assert result == {}
    mock_exists.assert_called_once()


@patch("os.path.exists", return_value=True)
@patch("builtins.open", new_callable=mock_open, read_data='{"a": "b"}')
def test_load_cache_valid_json(
    mock_open_fn: MagicMock,
    mock_exists: MagicMock
) -> None:
    result: Dict[str, str] = load_cache("file.json")
    assert result == {"a": "b"}
    mock_open_fn.assert_called_once()
    mock_exists.assert_called_once()


@patch("os.path.exists", return_value=True)
@patch("builtins.open", new_callable=mock_open, read_data="not json")
def test_load_cache_invalid_json_raises(
    _mock_open_fn: MagicMock,
    _mock_exists: MagicMock
) -> None:
    with pytest.raises(json.JSONDecodeError):
        load_cache("file.json")


@patch("os.path.exists", return_value=True)
@patch("builtins.open", new_callable=mock_open, read_data="42")
def test_load_cache_non_dict_json_raises(
    _mock_open_fn: MagicMock,
    _mock_exists: MagicMock
) -> None:
    with pytest.raises(TypeError):
        load_cache("file.json")


@patch("os.path.exists", return_value=True)
@patch("builtins.open", side_effect=OSError("Permission denied"))
def test_load_cache_open_failure_raises(
    _mock_open_fn: MagicMock,
    _mock_exists: MagicMock
) -> None:
    with pytest.raises(OSError):
        load_cache("file.json")


@patch("os.path.exists", return_value=True)
@patch("builtins.open", new_callable=mock_open, read_data='{"a": 1}')
def test_load_cache_non_str_values_not_allowed(
    _mock_open_fn: MagicMock,
    _mock_exists: MagicMock
) -> None:
    with pytest.raises(TypeError):
        load_cache("file.json")


@pytest.fixture
def mock_json_dump():
    with patch.object(json, "dump") as m:
        yield m


@pytest.fixture
def mock_open_fixture():
    with patch.object(builtins, "open", create=True) as m:
        yield m


def test_save_cache_valid_dict(
    mock_open_fixture: MagicMock, mock_json_dump: MagicMock
) -> None:
    cache = {"key": "value"}
    save_cache(cache, "file.json")
    mock_open_fixture.assert_called_once_with("file.json", "w")
    mock_json_dump.assert_called_once_with(
        cache,
        mock_open_fixture.return_value.__enter__(),
        indent=2)


def test_save_cache_empty_dict(
    mock_open_fixture: MagicMock, mock_json_dump: MagicMock
) -> None:
    cache: dict[str, str] = {}
    save_cache(cache, "file.json")
    mock_json_dump.assert_called_once_with(
        cache,
        mock_open_fixture.return_value.__enter__(),
        indent=2)


def test_save_cache_list_input(
    mock_open_fixture: MagicMock, mock_json_dump: MagicMock
) -> None:
    cache = [1, 2, 3]
    save_cache(cache, "file.json")  # type: ignore
    mock_json_dump.assert_called_once_with(
        cache,
        mock_open_fixture.return_value.__enter__(),
        indent=2)


def test_save_cache_invalid_type_raises(
    mock_open_fixture: MagicMock, mock_json_dump: MagicMock
) -> None:
    mock_json_dump.side_effect = TypeError("Not serializable")
    with pytest.raises(TypeError, match="Not serializable"):
        save_cache(object(), "file.json")  # type: ignore


def test_save_cache_file_write_error(
    mock_open_fixture: MagicMock
) -> None:
    mock_open_fixture.side_effect = IOError("Disk full")
    with pytest.raises(IOError, match="Disk full"):
        save_cache({"key": "value"}, "file.json")


@pytest.fixture
def mock_ipwhois():
    with patch("cidr_aggregator.IPWhois") as mock_class:
        yield mock_class


@pytest.fixture
def mock_ipdefinederror():
    with patch("cidr_aggregator.IPDefinedError") as mock_exc:
        yield mock_exc


def test_get_cidr_ipwhois_success(
    mock_ipwhois: MagicMock
) -> None:
    mock_instance = MagicMock()
    mock_instance.lookup_rdap.return_value = {"asn_cidr": "5.6.7.0/24"}
    mock_ipwhois.return_value = mock_instance

    result: str = get_cidr_ipwhois("5.6.7.8")
    assert result == "5.6.7.0/24"


def test_get_cidr_ipwhois_no_cidr(
    mock_ipwhois: MagicMock
) -> None:
    mock_instance = MagicMock()
    mock_instance.lookup_rdap.return_value = {}
    mock_ipwhois.return_value = mock_instance

    result: str = get_cidr_ipwhois("9.9.9.9")
    assert result is None


def test_get_cidr_ipwhois_ipdefinederror(
    mock_ipwhois: MagicMock
) -> None:
    # TODO: use dependency injection in source code and adjust test
    class FakeIPDefinedError(Exception):
        pass

    with pytest.raises(FakeIPDefinedError, match="Reserved IP"):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.side_effect = FakeIPDefinedError(
            "Reserved IP")
        mock_ipwhois.return_value = mock_instance

        get_cidr_ipwhois("192.168.0.1")


def test_get_cidr_ipwhois_generic_exception(
    mock_ipwhois: MagicMock
) -> None:
    with pytest.raises(RuntimeError, match="Unexpected failure"):
        mock_ipwhois.side_effect = RuntimeError("Unexpected failure")

        get_cidr_ipwhois("10.0.0.1")


@pytest.fixture
def mock_is_cidr():
    with patch("cidr_aggregator.is_cidr") as m:
        yield m


@pytest.fixture
def mock_get_cidr_ipwhois():
    with patch("cidr_aggregator.get_cidr_ipwhois") as m:
        yield m


def test_aggregate_ips_all_cidr(
    mock_is_cidr: MagicMock, mock_get_cidr_ipwhois: MagicMock
) -> None:
    ips: List[str] = ["1.2.3.0/24", "5.6.7.0/24"]
    mock_is_cidr.side_effect = lambda ip: True

    result: Tuple[List[str], List[str]] = aggregate_ips(ips, {}, "file.json")
    assert set(result[0]) == {"1.2.3.0/24", "5.6.7.0/24"}
    assert result[1] == []
    mock_get_cidr_ipwhois.assert_not_called()


def test_aggregate_ips_all_resolvable_ips(
    mock_is_cidr: MagicMock, mock_get_cidr_ipwhois: MagicMock
) -> None:
    ips: List[str] = ["8.8.8.8", "1.1.1.1"]
    mock_is_cidr.side_effect = lambda ip: False
    mock_get_cidr_ipwhois.side_effect = ["8.8.8.0/24", "1.1.1.0/24"]

    cache: Dict[str, str] = {}
    result: Tuple[List[str], List[str]] = aggregate_ips(
        ips, cache, "file.json")
    assert set(result[0]) == {"8.8.8.0/24", "1.1.1.0/24"}
    assert result[1] == []


def test_aggregate_ips_mixed_inputs(
    mock_is_cidr: MagicMock, mock_get_cidr_ipwhois: MagicMock
) -> None:
    ips: List[str] = ["1.2.3.0/24", "9.9.9.9"]
    mock_is_cidr.side_effect = lambda ip: ip.endswith("/24")
    mock_get_cidr_ipwhois.return_value = "9.9.9.0/24"

    cache: Dict[str, str] = {}
    result: Tuple[List[str], List[str]] = aggregate_ips(
        ips, cache, "file.json")
    assert set(result[0]) == {"1.2.3.0/24", "9.9.9.0/24"}
    assert result[1] == []


def test_aggregate_ips_unresolvable_ips(
    mock_is_cidr: MagicMock, mock_get_cidr_ipwhois: MagicMock
) -> None:
    ips: List[str] = ["10.0.0.1", "172.16.0.1"]
    mock_is_cidr.side_effect = lambda ip: False
    mock_get_cidr_ipwhois.side_effect = [None, None]

    cache: Dict[str, str] = {}
    result: Tuple[List[str], List[str]] = aggregate_ips(
        ips, cache, "file.json")
    assert result[0] == []
    assert set(result[1]) == {"10.0.0.1", "172.16.0.1"}


def test_aggregate_ips_duplicate_cidrs(
    mock_is_cidr: MagicMock, mock_get_cidr_ipwhois: MagicMock
) -> None:
    ips: List[str] = ["1.2.3.0/24", "1.2.3.0/24", "8.8.8.8"]
    mock_is_cidr.side_effect = lambda ip: ip.endswith("/24")
    mock_get_cidr_ipwhois.return_value = "1.2.3.0/24"

    cache: Dict[str, str] = {}
    result: Tuple[List[str], List[str]] = aggregate_ips(
        ips, cache, "file.json")
    assert result[0] == ["1.2.3.0/24"]
    assert result[1] == []


def test_format_block_line_valid_cidr() -> None:
    cidr: str = "192.168.0.0/24"
    expected: str = "block drop from 192.168.0.0/24 to any"
    result: str = format_block_line(cidr)
    assert result == expected


def test_format_block_line_single_ip() -> None:
    cidr: str = "8.8.8.8"
    expected: str = "block drop from 8.8.8.8 to any"
    result: str = format_block_line(cidr)
    assert result == expected


def test_format_block_line_empty_string() -> None:
    cidr: str = ""
    expected: str = "block drop from  to any"
    result: str = format_block_line(cidr)
    assert result == expected


def test_format_block_line_whitespace_only() -> None:
    cidr: str = "   "
    expected: str = f"block drop from {cidr} to any"
    result: str = format_block_line(cidr)
    assert result == expected


def test_format_block_line_non_ip_string() -> None:
    cidr: str = "not-an-ip"
    expected: str = "block drop from not-an-ip to any"
    result: str = format_block_line(cidr)
    assert result == expected


def test_is_cidr_valid_cidr() -> None:
    ip: str = "192.168.0.0/24"
    result: bool = is_cidr(ip)
    assert result is True


def test_is_cidr_single_ip() -> None:
    ip: str = "8.8.8.8"
    result: bool = is_cidr(ip)
    assert result is False


def test_is_cidr_invalid_format() -> None:
    ip: str = "not-an-ip"
    result: bool = is_cidr(ip)
    assert result is False


def test_is_cidr_empty_string() -> None:
    ip: str = ""
    result: bool = is_cidr(ip)
    assert result is False


def test_is_cidr_whitespace_only() -> None:
    ip: str = "   "
    result: bool = is_cidr(ip)
    assert result is False


def test_is_cidr_ipv6_cidr() -> None:
    ip: str = "2001:db8::/32"
    result: bool = is_cidr(ip)
    assert result is True


def test_is_cidr_ipv6_single_address() -> None:
    ip: str = "2001:db8::1"
    result: bool = is_cidr(ip)
    assert result is False


@patch("cidr_aggregator.format_block_line")
@patch("cidr_aggregator.save_cache")
@patch("cidr_aggregator.aggregate_ips")
@patch("cidr_aggregator.load_cache")
def test_main_all_resolved(
    mock_load_cache: MagicMock,
    mock_aggregate_ips: MagicMock,
    mock_save_cache: MagicMock,
    mock_format_block_line: MagicMock
) -> None:
    mock_load_cache.return_value = {"cached": "value"}
    mock_aggregate_ips.return_value = (["1.2.3.0/24", "5.6.7.0/24"], [])
    mock_format_block_line.side_effect = lambda cidr: f"block {cidr}"

    ips: List[str] = ["1.2.3.4", "5.6.7.8"]
    main(ips)

    mock_load_cache.assert_called_once()
    mock_aggregate_ips.assert_called_once_with(
        ips, {"cached": "value"}, CACHE_FILE)
    mock_save_cache.assert_called_once_with({"cached": "value"}, CACHE_FILE)
    mock_format_block_line.assert_any_call("1.2.3.0/24")
    mock_format_block_line.assert_any_call("5.6.7.0/24")


@patch("cidr_aggregator.format_block_line")
@patch("cidr_aggregator.aggregate_ips")
@patch("cidr_aggregator.load_cache")
def test_main_with_unresolved_ips(
    mock_load_cache: MagicMock,
    mock_aggregate_ips: MagicMock,
    mock_format_block_line: MagicMock
) -> None:
    mock_load_cache.return_value = {}
    mock_aggregate_ips.return_value = (["8.8.8.0/24"], ["10.0.0.1"])
    mock_format_block_line.side_effect = lambda x: f"block {x}"

    ips: List[str] = ["8.8.8.8", "10.0.0.1"]
    main(ips)

    mock_format_block_line.assert_any_call("8.8.8.0/24")
    mock_format_block_line.assert_any_call("10.0.0.1")


@patch("cidr_aggregator.format_block_line")
@patch("cidr_aggregator.save_cache")
@patch("cidr_aggregator.aggregate_ips")
@patch("cidr_aggregator.load_cache")
def test_main_empty_input(
    mock_load_cache: MagicMock,
    mock_aggregate_ips: MagicMock,
    mock_save_cache: MagicMock,
    mock_format_block_line: MagicMock
) -> None:
    mock_load_cache.return_value = {}
    mock_aggregate_ips.return_value = ([], [])
    ips: List[str] = []

    main(ips)

    mock_format_block_line.assert_not_called()
    mock_save_cache.assert_called_once_with({}, CACHE_FILE)
