"""Small in-memory cache for stable provider metadata, never measurements."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Generic, TypeVar

T = TypeVar("T")


class ProviderMetadataCache(Generic[T]):
    """Cache a provider catalog by caller-supplied metadata signature.

    Returned collections are copies so UI code cannot mutate the cached tuple.
    Benchmark results and latency measurements must never be stored here.
    """

    def __init__(self) -> None:
        self._signature: str | None = None
        self._providers: tuple[T, ...] = ()

    def get(self, signature: str, factory: Callable[[], Iterable[T]]) -> list[T]:
        if self._signature != signature:
            self._providers = tuple(factory())
            self._signature = signature
        return list(self._providers)

    def clear(self) -> None:
        self._signature = None
        self._providers = ()
