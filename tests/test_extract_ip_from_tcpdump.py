import os
import re
from typing import Optional, Set
from unittest.mock import MagicMock, mock_open, patch

import pytest

from extract_ip_from_tcpdump import (LOG_FILE, extract_destination_ip,
                                     load_allowed_ips, run_tcpdump,
                                     should_track_ip, track_ip)


@pytest.mark.parametrize(
    "line, expected",
    [
        (
            "12:34:56.789 IP 192.168.1.100.12345 > 10.0.0.1.80: Flags [S], ..",
            "10.0.0.1",
        ),
        (
            "IP 172.16.0.5.443 > 192.168.0.10.1234: Flags [P.], ...",
            "192.168.0.10",
        ),
        (
            "IP 127.0.0.1.1234 > 8.8.8.8.53: Flags [S], ...",
            "8.8.8.8",
        ),
        (
            "IP 10.0.0.1.1234 > malformed line with no port",
            None,
        ),
        (
            "Completely unrelated log line",
            None,
        ),
        (
            "IP 192.168.1.1.1234 > 256.256.256.256.80: Flags [S], ...",
            "256.256.256.256",  # Still matches regex, even if invalid IP
        ),
        (
            "IP 192.168.1.1.1234 > 10.0.0.1.80:",
            "10.0.0.1",
        ),
        (
            "IP 192.168.1.1.1234 > 10.0.0.1.80: Extra > 192.168.0.1.443:",
            "10.0.0.1",  # Only first match should be returned
        ),
    ],
)
def test_extract_destination_ip_valid_and_edge_cases(
    line: str, expected: Optional[str]
) -> None:
    result: Optional[str] = extract_destination_ip(line)
    assert result == expected


def test_extract_destination_ip_regex_called_once() -> None:
    line: str = "IP 192.168.1.1.1234 > 10.0.0.1.80: Flags [S], ..."
    with patch("re.search") as mock_search:
        mock_search.return_value = re.match(
            r"> (\d+\.\d+\.\d+\.\d+)\.\d+:", "> 10.0.0.1.80:"
        )
        result: Optional[str] = extract_destination_ip(line)
        assert result == "10.0.0.1"
        mock_search.assert_called_once()


@pytest.mark.parametrize(
    "env_value, expected",
    [
        ("192.168.1.1,10.0.0.1", {"192.168.1.1", "10.0.0.1"}),
        (" 192.168.1.1 , 10.0.0.1 ", {"192.168.1.1", "10.0.0.1"}),
        ("", set()),
        (",,,", set()),
        ("192.168.1.1,,10.0.0.1,", {"192.168.1.1", "10.0.0.1"}),
        ("192.168.1.1,192.168.1.1", {"192.168.1.1"}),
        ("  ", set()),
        ("192.168.1.1 , , 10.0.0.1 , ", {"192.168.1.1", "10.0.0.1"}),
    ],
)
def test_load_allowed_ips_various_inputs(
    env_value: str, expected: Set[str]
) -> None:
    with patch.dict(os.environ, {"ALLOWED_IPS": env_value}):
        result: Set[str] = load_allowed_ips()
        assert result == expected


def test_load_allowed_ips_env_not_set() -> None:
    with patch.dict(os.environ, {}, clear=True):
        result: Set[str] = load_allowed_ips()
        assert result == set()


@patch.dict(os.environ, {"IP_ADDRESS": "invalid_ip"})
def test_run_tcpdump_invalid_ip_raises() -> None:
    with pytest.raises(ValueError, match="Invalid IP address: invalid_ip"):
        run_tcpdump()


@patch.dict(os.environ, {"IP_ADDRESS": "192.168.1.1"})
@patch("extract_ip_from_tcpdump.load_allowed_ips", return_value={"10.0.0.1"})
@patch("extract_ip_from_tcpdump.extract_destination_ip",
       return_value="10.0.0.1")
@patch("extract_ip_from_tcpdump.should_track_ip", return_value=True)
@patch("extract_ip_from_tcpdump.track_ip")
@patch("subprocess.Popen")
def test_run_tcpdump_valid_ip_executes(
    mock_popen: MagicMock,
    mock_track_ip: MagicMock,
    *_: MagicMock
) -> None:
    mock_proc = MagicMock()
    mock_proc.stdout = iter(["some tcpdump output"])
    mock_popen.return_value = mock_proc

    run_tcpdump()

    mock_popen.assert_called_once()
    mock_track_ip.assert_called_once_with("10.0.0.1", set(), LOG_FILE)


@patch.dict(os.environ, {"IP_ADDRESS": "192.168.1.1"})
@patch("extract_ip_from_tcpdump.load_allowed_ips", return_value=set())
@patch("subprocess.Popen")
def test_run_tcpdump_none_stdout_raises(
    mock_popen: MagicMock,
    *_: MagicMock
) -> None:
    mock_proc = MagicMock()
    mock_proc.stdout = None
    mock_popen.return_value = mock_proc

    with pytest.raises(RuntimeError, match="Expected process.stdout"):
        run_tcpdump()


@patch.dict("os.environ", {"IP_ADDRESS": "192.168.1.1"})
@patch("extract_ip_from_tcpdump.load_allowed_ips", return_value=set())
@patch("extract_ip_from_tcpdump.extract_destination_ip",
       side_effect=KeyboardInterrupt)
@patch("extract_ip_from_tcpdump.should_track_ip")
@patch("extract_ip_from_tcpdump.track_ip")
@patch("subprocess.Popen")
def test_run_tcpdump_keyboard_interrupt(
    mock_popen: MagicMock,
    *_: MagicMock
) -> None:
    mock_proc = MagicMock()
    mock_proc.stdout = iter(["line1", "line2"])
    mock_popen.return_value = mock_proc

    run_tcpdump()

    mock_proc.terminate.assert_called_once()


@pytest.mark.parametrize(
    "ip, tracked, allowed, expected",
    [
        ("10.0.0.1", set(), set(), True),
        ("10.0.0.1", {"10.0.0.1"}, set(), False),
        ("10.0.0.1", set(), {"10.0.0.1"}, False),
        ("10.0.0.1", {"10.0.0.1"}, {"10.0.0.1"}, False),
        ("10.0.0.1", {"192.168.1.1"}, {"172.16.0.1"}, True),
    ],
)
def test_should_track_ip(
    ip: str,
    tracked: set[str],
    allowed: set[str],
    expected: bool
) -> None:
    result: bool = should_track_ip(ip, tracked, allowed)
    assert result is expected


def test_track_ip_adds_and_writes() -> None:
    tracked: set[str] = set()
    ip: str = "10.0.0.1"
    log_file: str = "log.txt"

    m = mock_open()
    with patch("builtins.open", m):
        track_ip(ip, tracked, log_file)

    assert ip in tracked
    m.assert_called_once_with(log_file, "a")
    m().write.assert_called_once_with(f"{ip}\n")
