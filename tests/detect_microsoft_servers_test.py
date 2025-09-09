import socket
from unittest.mock import MagicMock, patch

import pytest

from detect_microsoft_servers import (check_domain, main, output, ping,
                                      print_header, print_result,
                                      print_summary, resolve_domain,
                                      validate_ip)


def test_check_domain_success() -> None:
    with patch("detect_microsoft_servers.resolve_domain",
               return_value="192.0.2.1"), \
            patch("detect_microsoft_servers.validate_ip"), \
            patch("detect_microsoft_servers.ping", return_value=True):
        domain, ip, reachable = check_domain("example.com")
        assert domain == "example.com"
        assert ip == "192.0.2.1"
        assert reachable is True


def test_check_domain_resolution_failed() -> None:
    with patch("detect_microsoft_servers.resolve_domain",
               return_value=None):
        domain, ip, reachable = check_domain("bad.domain")
        assert domain == "bad.domain"
        assert ip == "Resolution failed"
        assert reachable is False


def test_check_domain_invalid_ip() -> None:
    with patch("detect_microsoft_servers.resolve_domain",
               return_value="invalid-ip"), \
        patch("detect_microsoft_servers.validate_ip",
              side_effect=ValueError("Invalid IP")):
        with pytest.raises(ValueError, match="Invalid IP"):
            check_domain("invalid.domain")


def test_ping_success() -> None:
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    with patch("subprocess.run", return_value=mock_proc):
        assert ping("192.0.2.1") is True


def test_ping_failure() -> None:
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    with patch("subprocess.run", return_value=mock_proc):
        assert ping("192.0.2.1") is False


def test_ping_exception() -> None:
    with patch("subprocess.run",
               side_effect=RuntimeError("ping failed")):
        assert ping("192.0.2.1") is False


def test_print_header_output(monkeypatch) -> None:
    mock_output = MagicMock()
    monkeypatch.setattr("detect_microsoft_servers.output", mock_output)
    print_header()
    assert mock_output.call_count == 1
    assert "Connectivity Check" in mock_output.call_args[0][0]


def test_print_result_resolution_failed(monkeypatch) -> None:
    mock_output = MagicMock()
    monkeypatch.setattr("detect_microsoft_servers.output", mock_output)
    print_result("example.com", "Resolution failed", False)
    expected = f"{'example.com':<30} | Resolution failed"
    mock_output.assert_called_once_with(expected)


def test_print_result_reachable(monkeypatch) -> None:
    mock_output = MagicMock()
    monkeypatch.setattr("detect_microsoft_servers.output", mock_output)
    print_result("example.com", "192.0.2.1", True)
    expected = f"{'example.com':<30} | {'192.0.2.1':<15} | reachable"
    mock_output.assert_called_once_with(expected)


def test_print_result_unreachable(monkeypatch) -> None:
    mock_output = MagicMock()
    monkeypatch.setattr("detect_microsoft_servers.output", mock_output)
    print_result("example.com", "192.0.2.1", False)
    expected = f"{'example.com':<30} | {'192.0.2.1':<15} | unreachable"
    mock_output.assert_called_once_with(expected)


def test_print_summary_with_unreachable(monkeypatch) -> None:
    mock_output = MagicMock()
    monkeypatch.setattr("detect_microsoft_servers.output", mock_output)
    print_summary(["example.com", "bad.domain"])
    assert mock_output.call_count == 3
    assert mock_output.call_args_list[0][0][0] == "\nUnreachable Domains:"
    assert mock_output.call_args_list[1][0][0] == "- example.com"
    assert mock_output.call_args_list[2][0][0] == "- bad.domain"


def test_print_summary_all_reachable(monkeypatch) -> None:
    mock_output = MagicMock()
    monkeypatch.setattr("detect_microsoft_servers.output", mock_output)
    print_summary([])
    mock_output.assert_called_once_with("\n✅ All domains reachable.")


def test_resolve_domain_success(monkeypatch) -> None:
    monkeypatch.setattr("socket.gethostbyname",
                        lambda d: "192.0.2.1")
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


def test_output_prints_correctly() -> None:
    with patch("builtins.print") as mock_print:
        output("Hello world")
        mock_print.assert_called_once_with("Hello world")


def test_main_all_domains_reachable(monkeypatch) -> None:
    mock_output = MagicMock()
    monkeypatch.setattr("detect_microsoft_servers.output", mock_output)

    monkeypatch.setattr("detect_microsoft_servers.check_domain",
                        lambda d: (d, "192.0.2.1", True))

    domains = ["example.com", "xbox.com"]
    main(domains)

    calls = [call[0][0] for call in mock_output.call_args_list]

    assert any("Connectivity Check" in msg for msg in calls)
    assert any("reachable" in msg for msg in calls)
    assert any("✅ All domains reachable." in msg for msg in calls)
    assert not any("Unreachable Domains" in msg for msg in calls)


def test_main_some_domains_unreachable(monkeypatch) -> None:
    mock_output = MagicMock()
    monkeypatch.setattr("detect_microsoft_servers.output", mock_output)

    def mock_check(domain: str) -> tuple[str, str, bool]:
        return (domain, "192.0.2.1", domain != "fail.com")

    monkeypatch.setattr("detect_microsoft_servers.check_domain", mock_check)

    domains = ["good.com", "fail.com"]
    main(domains)

    calls = [call[0][0] for call in mock_output.call_args_list]

    assert any("reachable" in msg for msg in calls)
    assert any("unreachable" in msg for msg in calls)
    assert any("Unreachable Domains:" in msg for msg in calls)
    assert any("- fail.com" in msg for msg in calls)


def test_main_all_domains_unreachable(monkeypatch) -> None:
    mock_output = MagicMock()
    monkeypatch.setattr("detect_microsoft_servers.output", mock_output)

    monkeypatch.setattr("detect_microsoft_servers.check_domain",
                        lambda d: (d, "Resolution failed", False))

    domains = ["a.com", "b.com"]
    main(domains)

    calls = [call[0][0] for call in mock_output.call_args_list]

    assert all("Resolution failed" in msg or "unreachable" in msg
               for msg in calls if "|" in msg)
    assert any("Unreachable Domains:" in msg for msg in calls)
    assert any("- a.com" in msg for msg in calls)
    assert any("- b.com" in msg for msg in calls)
    assert not any("✅ All domains reachable." in msg for msg in calls)


def test_main_empty_domain_list(monkeypatch) -> None:
    mock_output = MagicMock()
    monkeypatch.setattr("detect_microsoft_servers.output", mock_output)

    main([])

    calls = [call[0][0] for call in mock_output.call_args_list]

    assert any("Connectivity Check" in msg for msg in calls)
    assert any("✅ All domains reachable." in msg for msg in calls)
    assert not any("Unreachable Domains:" in msg for msg in calls)
