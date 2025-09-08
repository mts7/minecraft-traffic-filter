import socket
from unittest.mock import MagicMock

import pytest

from detect_microsoft_servers import (check_domain, ping, print_result,
                                      print_summary, resolve_domain,
                                      validate_ip)


def test_check_domain_success(monkeypatch) -> None:
    monkeypatch.setattr("detect_microsoft_servers.resolve_domain",
                        lambda d: "192.0.2.1")
    monkeypatch.setattr("detect_microsoft_servers.validate_ip",
                        lambda ip: None)
    monkeypatch.setattr("detect_microsoft_servers.ping",
                        lambda ip: True)

    domain, ip, reachable = check_domain("example.com")
    assert domain == "example.com"
    assert ip == "192.0.2.1"
    assert reachable is True


def test_check_domain_resolution_failed(monkeypatch) -> None:
    monkeypatch.setattr("detect_microsoft_servers.resolve_domain",
                        lambda d: None)

    domain, ip, reachable = check_domain("bad.domain")
    assert domain == "bad.domain"
    assert ip == "Resolution failed"
    assert reachable is False


def test_check_domain_invalid_ip(monkeypatch) -> None:
    monkeypatch.setattr("detect_microsoft_servers.resolve_domain",
                        lambda d: "invalid-ip")
    monkeypatch.setattr("detect_microsoft_servers.validate_ip",
                        lambda ip: (_ for _ in ()).throw(ValueError("bad ip")))

    with pytest.raises(ValueError, match="bad ip"):
        check_domain("invalid.domain")


def test_ping_success(monkeypatch) -> None:
    mock_run = MagicMock()
    mock_run.returncode = 0
    monkeypatch.setattr("subprocess.run", lambda *_,
                        **__: mock_run)

    assert ping("192.0.2.1") is True


def test_ping_failure(monkeypatch) -> None:
    mock_run = MagicMock()
    mock_run.returncode = 1
    monkeypatch.setattr("subprocess.run", lambda *_,
                        **__: mock_run)

    assert ping("192.0.2.1") is False


def test_ping_exception(monkeypatch) -> None:
    monkeypatch.setattr("subprocess.run",
                        lambda *_,
                        **__: (_ for _ in ()).throw(RuntimeError("fail")))

    assert ping("192.0.2.1") is False


def test_print_result_resolution_failed(
        capsys: pytest.CaptureFixture[str]) -> None:
    print_result("example.com", "Resolution failed", False)
    output = capsys.readouterr().out
    assert "example.com" in output
    assert "Resolution failed" in output


def test_print_result_reachable(capsys: pytest.CaptureFixture[str]) -> None:
    print_result("example.com", "192.0.2.1", True)
    output = capsys.readouterr().out
    assert "reachable" in output


def test_print_result_unreachable(capsys: pytest.CaptureFixture[str]) -> None:
    print_result("example.com", "192.0.2.1", False)
    output = capsys.readouterr().out
    assert "unreachable" in output


def test_print_summary_with_unreachable(
        capsys: pytest.CaptureFixture[str]) -> None:
    print_summary(["example.com", "bad.domain"])
    output = capsys.readouterr().out
    assert "Unreachable Domains" in output
    assert "- example.com" in output
    assert "- bad.domain" in output


def test_print_summary_all_reachable(
        capsys: pytest.CaptureFixture[str]) -> None:
    print_summary([])
    output = capsys.readouterr().out
    assert "✅ All domains reachable." in output


def test_resolve_domain_success(monkeypatch) -> None:
    monkeypatch.setattr("socket.gethostbyname", lambda d: "192.0.2.1")
    assert resolve_domain("example.com") == "192.0.2.1"


def test_resolve_domain_failure(monkeypatch) -> None:
    monkeypatch.setattr("socket.gethostbyname",
                        lambda d: (_ for _ in ()).throw(
                            socket.gaierror("fail")))
    assert resolve_domain("bad.domain") is None


def test_validate_ip_valid() -> None:
    validate_ip("192.0.2.1")  # should not raise


def test_validate_ip_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid IP address"):
        validate_ip("999.999.999.999")
