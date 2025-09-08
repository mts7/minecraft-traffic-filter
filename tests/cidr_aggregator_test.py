from unittest.mock import MagicMock, patch

import pytest

from cidr_aggregator import main
from utilities.file_cache import FileCache
from utilities.network import WhoisStrategy


@pytest.fixture
def mock_cache() -> FileCache[str, str]:
    return MagicMock(spec=FileCache)


@pytest.fixture
def mock_strategy() -> WhoisStrategy:
    return MagicMock(spec=WhoisStrategy)


@pytest.fixture
def mock_resolver() -> MagicMock:
    resolver = MagicMock()
    resolver.aggregate_ips.return_value = (
        {"192.0.2.0/24", "198.51.100.0/24"},
        {"203.0.113.42"}
    )
    return resolver


def test_main_prints_aggregated_and_failed_ips(
    mock_cache: FileCache[str, str],
    mock_strategy: WhoisStrategy,
    mock_resolver: MagicMock,
    capsys: pytest.CaptureFixture[str]
) -> None:
    with patch("cidr_aggregator.CidrResolver", return_value=mock_resolver), \
        patch("cidr_aggregator.format_block_line",
              side_effect=lambda cidr: f"block drop from {cidr} to any"):
        main(["192.0.2.1", "203.0.113.42"], mock_cache, mock_strategy)

    output = capsys.readouterr().out
    assert "✅ Aggregated CIDRs and IPs:" in output
    assert "block drop from 192.0.2.0/24 to any" in output
    assert "block drop from 198.51.100.0/24 to any" in output
    assert "⚠️ Unresolved IPs:" in output
    assert "block drop from 203.0.113.42 to any" in output


def test_main_prints_only_aggregated_when_no_failures(
    mock_cache: FileCache[str, str],
    mock_strategy: WhoisStrategy,
    capsys: pytest.CaptureFixture[str]
) -> None:
    resolver = MagicMock()
    resolver.aggregate_ips.return_value = (
        {"198.51.100.0/24"},
        set()
    )

    with patch("cidr_aggregator.CidrResolver", return_value=resolver), \
        patch("cidr_aggregator.format_block_line",
              side_effect=lambda cidr: f"block drop from {cidr} to any"):
        main(["198.51.100.1"], mock_cache, mock_strategy)

    output = capsys.readouterr().out
    assert "✅ Aggregated CIDRs and IPs:" in output
    assert "block drop from 198.51.100.0/24 to any" in output
    assert "⚠️ Unresolved IPs:" not in output


def test_main_prints_only_failed_when_no_aggregated(
    mock_cache: FileCache[str, str],
    mock_strategy: WhoisStrategy,
    capsys: pytest.CaptureFixture[str]
) -> None:
    resolver = MagicMock()
    resolver.aggregate_ips.return_value = (
        set(),
        {"203.0.113.42"}
    )

    with patch("cidr_aggregator.CidrResolver", return_value=resolver), \
        patch("cidr_aggregator.format_block_line",
              side_effect=lambda cidr: f"block drop from {cidr} to any"):
        main(["203.0.113.42"], mock_cache, mock_strategy)

    output = capsys.readouterr().out
    assert "✅ Aggregated CIDRs and IPs:" in output
    assert "⚠️ Unresolved IPs:" in output
    assert "block drop from 203.0.113.42 to any" in output
