from unittest.mock import MagicMock, mock_open, patch

import pytest

from block_ip import (PF_CONF_PATH, BlockIPError, append_pf_rule, is_root,
                      reload_pfctl, run_block_ip, validate_ip)


def test_is_root_true(monkeypatch) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert is_root() is True


def test_is_root_false(monkeypatch) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    assert is_root() is False


@pytest.mark.parametrize("ip", [
    "192.0.2.1",
    "203.0.113.0/24",
    "10.0.0.0/8"
])
def test_validate_ip_valid(ip: str) -> None:
    assert validate_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "999.999.999.999",
    "abc.def.ghi.jkl",
    "192.0.2.1/33",
    "192.0.2"
])
def test_validate_ip_invalid(ip: str) -> None:
    assert validate_ip(ip) is False


def test_append_pf_rule_writes_to_file() -> None:
    m = mock_open()
    with patch("builtins.open", m):
        append_pf_rule("192.0.2.1")
    m.assert_called_once_with(PF_CONF_PATH, "a")
    m().write.assert_called_once_with("block drop from 192.0.2.1 to any\n")


def test_reload_pfctl_runs_commands(monkeypatch) -> None:
    mock_run = MagicMock()
    monkeypatch.setattr("subprocess.run", mock_run)
    reload_pfctl()
    mock_run.assert_any_call(
        ["/sbin/pfctl", "-f", PF_CONF_PATH],
        check=True,
        shell=False
    )
    mock_run.assert_any_call(
        ["/sbin/pfctl", "-E"],
        check=True,
        shell=False
    )


def test_run_block_ip_not_root(monkeypatch) -> None:
    monkeypatch.setattr("block_ip.is_root", lambda: False)
    with pytest.raises(BlockIPError, match="must be run as root"):
        run_block_ip(["block_ip.py", "192.0.2.1"])


def test_run_block_ip_invalid_args(monkeypatch) -> None:
    monkeypatch.setattr("block_ip.is_root", lambda: True)
    with pytest.raises(BlockIPError, match="Usage:"):
        run_block_ip(["block_ip.py"])


def test_run_block_ip_invalid_ip(monkeypatch) -> None:
    monkeypatch.setattr("block_ip.is_root", lambda: True)
    monkeypatch.setattr("block_ip.validate_ip", lambda ip: False)
    with pytest.raises(BlockIPError, match="Invalid IP format"):
        run_block_ip(["block_ip.py", "invalid-ip"])


def test_run_block_ip_success(monkeypatch) -> None:
    monkeypatch.setattr("block_ip.is_root", lambda: True)
    monkeypatch.setattr("block_ip.validate_ip", lambda ip: True)
    monkeypatch.setattr("block_ip.append_pf_rule", MagicMock())
    monkeypatch.setattr("block_ip.reload_pfctl", MagicMock())
    mock_run = MagicMock()
    monkeypatch.setattr("subprocess.run", mock_run)

    run_block_ip(["block_ip.py", "192.0.2.1"])

    mock_run.assert_any_call(
        ["/sbin/pfctl", "-sr"],
        shell=False
    )
    mock_run.assert_any_call(
        ["/bin/cat", PF_CONF_PATH],
        shell=False
    )
