"""Dependency-aware work queue for the scan scheduler.

Replaces ``graphlib.TopologicalSorter`` with a lightweight dynamic DAG
that supports post-prepare additions (recursion, lookahead, redirects).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable

from apiscan.kite import Route


# ---------------------------------------------------------------------------
# Work items
# ---------------------------------------------------------------------------

@dataclass
class ProbeWork:
    """Probe a prefix for handler boundaries."""
    prefix: str = ""
    depth: int = 0


@dataclass
class RouteWork:
    """Scan a route against its baseline."""
    route: Route = None


@dataclass
class LookaheadWork:
    """Lightweight GET probe for a single lookahead segment."""
    prefix: str = ""
    segment: str = ""


# ---------------------------------------------------------------------------
# Work queue
# ---------------------------------------------------------------------------

class WorkQueue:
    """Dependency-aware work queue.

    Items are declared with ``add(key, item, *deps)`` before calling
    ``prepare()``.  Workers pull ready items via ``get()`` and signal
    completion with ``item_done(key)``, which releases dependents.

    Unlike ``graphlib.TopologicalSorter``, this supports dynamic additions
    after ``prepare()`` via ``enqueue_dynamic()`` and
    ``enqueue_recursive_batch()``.
    """

    def __init__(self) -> None:
        self._deps: dict[str, set[str]] = {}         # key → unsatisfied deps
        self._dependents: dict[str, set[str]] = {}    # dep → keys waiting on it
        self._items: dict[str, Any] = {}
        self._ready: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        self._completed: set[str] = set()
        self._queued: set[str] = set()                # pushed to ready or auto-completed
        self._manual_gates: set[str] = set()
        self._inflight = 0
        self._done = asyncio.Event()
        self._done.set()
        self.skip_fn: Callable[[str, Any], bool] | None = None
        self.skipped = 0

    def add(self, key: str, item: Any, *deps: str) -> None:
        """Declare a work item with dependencies (before prepare)."""
        self._items[key] = item
        self._deps[key] = set(deps)
        for dep in deps:
            self._dependents.setdefault(dep, set()).add(key)

    def add_manual_gate(self, key: str, *deps: str) -> None:
        """Declare a gate node completed explicitly via ``item_done``.

        Gates block dependents until scan logic calls ``item_done(key)``.
        They are NOT pushed to the worker queue.
        """
        self._manual_gates.add(key)
        self._deps[key] = set(deps)
        for dep in deps:
            self._dependents.setdefault(dep, set()).add(key)

    def prepare(self) -> None:
        """Finalise the static graph and push initially-ready items."""
        # Strip deps that were already completed (virtual nodes auto-completed
        # during add phase won't happen here, but defensive).
        for key in self._deps:
            self._deps[key] -= self._completed
        self._push_ready()

    def _push_ready(self, candidates: list[str] | None = None) -> None:
        """Push items with no remaining deps to the ready queue.

        *candidates* is a list of keys to check. When ``None`` (initial
        prepare), all keys are scanned once.  Cascading releases from
        virtual nodes and skip_fn are handled via a work-list so only
        affected keys are visited — never a full scan of ``_deps``.
        """
        if candidates is None:
            # Initial prepare: scan everything once
            candidates = [k for k in self._deps if not self._deps[k] and k not in self._queued]

        while candidates:
            key = candidates.pop()
            if key in self._queued:
                continue
            if self._deps.get(key):
                continue
            self._queued.add(key)

            # Manual gates: count as inflight but don't go to worker queue
            if key in self._manual_gates:
                self._inflight += 1
                self._done.clear()
                continue

            item = self._items.get(key)
            if item is None:
                # Virtual node — auto-complete
                self._completed.add(key)
                candidates.extend(self._release_dependents(key))
                continue

            if self.skip_fn and self.skip_fn(key, item):
                self.skipped += 1
                self._completed.add(key)
                candidates.extend(self._release_dependents(key))
                continue

            self._inflight += 1
            self._done.clear()
            self._ready.put_nowait((key, item))

    def _release_dependents(self, key: str) -> list[str]:
        """Remove *key* from all dependents' dep sets.

        Returns keys whose dep sets became empty (newly ready candidates).
        """
        newly_ready: list[str] = []
        for dep_key in self._dependents.get(key, ()):
            deps = self._deps.get(dep_key)
            if deps is not None:
                deps.discard(key)
                if not deps and dep_key not in self._queued:
                    newly_ready.append(dep_key)
        return newly_ready

    @property
    def ready_count(self) -> int:
        """Items ready to be pulled by workers."""
        return self._ready.qsize()

    @property
    def blocked_count(self) -> int:
        """Items waiting on unsatisfied dependencies."""
        return max(0, self._inflight - self._ready.qsize())

    async def get(self) -> tuple[str, Any]:
        """Pull the next ready item. Returns ``(key, item)``."""
        return await self._ready.get()

    def item_done(self, key: str) -> None:
        """Mark *key* complete and release its dependents."""
        self._inflight -= 1
        self._completed.add(key)
        candidates = self._release_dependents(key)
        if candidates:
            self._push_ready(candidates)
        if self._inflight == 0:
            self._done.set()

    def enqueue_dynamic(self, key: str, item: Any) -> None:
        """Add work whose dependencies are already satisfied."""
        self._items[key] = item
        self._deps[key] = set()
        self._queued.add(key)
        self._inflight += 1
        self._done.clear()
        self._ready.put_nowait((key, item))

    def enqueue_recursive_batch(
        self, items: list[tuple[str, Any, list[str]]],
    ) -> None:
        """Add a batch of items with internal dependencies.

        Each entry is ``(key, item, dep_keys)``.  Items whose deps are
        already completed go straight to the ready queue.
        """
        if not items:
            return
        candidates = []
        for key, item, deps in items:
            self._items[key] = item
            dep_set = set(deps) - self._completed
            self._deps[key] = dep_set
            for dep in dep_set:
                self._dependents.setdefault(dep, set()).add(key)
            if not dep_set:
                candidates.append(key)
        if candidates:
            self._push_ready(candidates)

    async def wait(self) -> None:
        """Block until all work (static + dynamic) is complete."""
        await self._done.wait()
