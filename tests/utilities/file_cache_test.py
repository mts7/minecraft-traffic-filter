import json
from unittest.mock import mock_open, patch

import pytest

from utilities.file_cache import FileCache


@pytest.fixture
def dummy_path() -> str:
    return "/fake/path/cache.json"


@pytest.fixture
def dummy_data() -> dict[str, str]:
    return {"key1": "value1", "key2": "value2"}


def test_init_load_valid_json_filecache(dummy_path: str) -> None:
    mock_data = json.dumps({"key1": "value1"})
    with patch("os.path.exists", return_value=True), \
            patch("builtins.open", mock_open(read_data=mock_data)):
        cache = FileCache[str, str](dummy_path)
        assert cache.get("key1") == "value1"


def test_init_load_invalid_json_filecache(dummy_path: str) -> None:
    with patch("os.path.exists", return_value=True), \
        patch("builtins.open", mock_open(read_data="{invalid json")), \
        patch("json.load", side_effect=json.JSONDecodeError(
            "msg", "doc", 0)):
        cache = FileCache[str, str](dummy_path)
        assert cache.get("key1") is None


def test_get_existing_key_filecache(dummy_path: str) -> None:
    cache = FileCache[str, str](dummy_path)
    cache._cache["foo"] = "bar"
    assert cache.get("foo") == "bar"


def test_get_missing_key_filecache(dummy_path: str) -> None:
    cache = FileCache[str, str](dummy_path)
    assert cache.get("missing") is None


def test_set_and_get_filecache(dummy_path: str) -> None:
    with patch("builtins.open", mock_open()) as m:
        cache = FileCache[str, str](dummy_path)
        cache.set("newkey", "newval")
        assert cache.get("newkey") == "newval"
        handle = m()
        handle.write.assert_called()


def test_contains_true_filecache(dummy_path: str) -> None:
    cache = FileCache[str, str](dummy_path)
    cache._cache["exists"] = "yes"
    assert "exists" in cache


def test_contains_false_filecache(dummy_path: str) -> None:
    cache = FileCache[str, str](dummy_path)
    assert "missing" not in cache


def test_getitem_filecache(dummy_path: str) -> None:
    cache = FileCache[str, str](dummy_path)
    cache._cache["x"] = "y"
    assert cache["x"] == "y"


def test_setitem_filecache(dummy_path: str) -> None:
    with patch("builtins.open", mock_open()) as m:
        cache = FileCache[str, str](dummy_path)
        cache["a"] = "b"
        assert cache.get("a") == "b"
        m().write.assert_called()


def test_items_filecache(dummy_path: str) -> None:
    cache = FileCache[str, str](dummy_path)
    cache._cache = {"a": "b", "c": "d"}
    assert list(cache.items()) == [("a", "b"), ("c", "d")]


def test_keys_filecache(dummy_path: str) -> None:
    cache = FileCache[str, str](dummy_path)
    cache._cache = {"x": "1", "y": "2"}
    assert list(cache.keys()) == ["x", "y"]


def test_values_filecache(dummy_path: str) -> None:
    cache = FileCache[str, str](dummy_path)
    cache._cache = {"x": "1", "y": "2"}
    assert list(cache.values()) == ["1", "2"]


def test_parse_key_default_filecache(dummy_path: str) -> None:
    cache = FileCache[str, str](dummy_path)
    assert cache._parse_key("abc") == "abc"


def test_save_writes_json_filecache(dummy_path: str) -> None:
    cache = FileCache[str, str](dummy_path)
    cache._cache = {"a": "b"}
    with patch("builtins.open", mock_open()) as m:
        cache._save()
        m().write.assert_called()
