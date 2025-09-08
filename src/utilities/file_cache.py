import json
import os
from typing import Generic, Optional, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class FileCache(Generic[K, V]):
    def __init__(self, path: str):
        self.path = path
        self._cache: dict[K, V] = {}
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.path):
            with open(self.path, "r") as f:
                try:
                    raw = json.load(f)
                    self._cache = {
                        self._parse_key(k): v for k,
                        v in raw.items()
                    }
                except json.JSONDecodeError:
                    self._cache = {}

    def _parse_key(self, key: str) -> K:
        return key  # type: ignore

    def get(self, key: K) -> Optional[V]:
        return self._cache.get(key)

    def set(self, key: K, value: V) -> None:
        self._cache[key] = value
        self._save()

    def _save(self) -> None:
        with open(self.path, "w") as f:
            json.dump(self._cache, f, indent=2)

    def __contains__(self, key: K) -> bool:
        return key in self._cache

    def __getitem__(self, key: K) -> V:
        return self._cache[key]

    def __setitem__(self, key: K, value: V) -> None:
        self.set(key, value)

    def items(self):
        return self._cache.items()

    def keys(self):
        return self._cache.keys()

    def values(self):
        return self._cache.values()
