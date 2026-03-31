"""Unified scan tree: routes, baselines, and prefix probing in one structure.

Organises routes into a tree by URL path segments.  Each node can hold:
- **Routes** from the wordlist (in insertion order)
- **Baselines** per HTTP method (discovered by probing)

Async iteration is depth-first.  At each node the tree:
1. Probes for a handler boundary (if the node has children and no baseline yet)
2. Yields the node's routes

This ensures baselines are established before children are scanned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import AsyncIterator

from apiscan.inference import (
    Baseline,
    ResponseSignature,
    _ALTERNATE_METHODS,
    _random_segment,
    build_baseline,
    matches_baseline,
)
from apiscan.kite import Route


@dataclass
class _Node:
    """A node in the scan tree, representing one path segment."""
    segment: str
    routes: list[Route] = field(default_factory=list)
    children: dict[str, _Node] = field(default_factory=dict)
    _insertion_order: list[str] = field(default_factory=list)
    baselines: dict[str, Baseline] = field(default_factory=dict)  # method -> Baseline

    def get_or_create(self, segment: str) -> _Node:
        if segment not in self.children:
            self.children[segment] = _Node(segment=segment)
            self._insertion_order.append(segment)
        return self.children[segment]


class ScanTree:
    """Unified tree holding routes and baselines, iterable depth-first.

    Usage::

        tree = ScanTree(routes)
        await tree.initialize(send_fn)   # root baselines
        async for route in tree.walk(send_fn):
            # route's ancestors are already baselined
            ...
    """

    def __init__(self, routes: list[Route] | None = None) -> None:
        self._root = _Node(segment="")
        self.route_count = 0
        self._fresh_boundaries: set[tuple[str, str]] = set()
        if routes:
            for route in routes:
                self.insert(route)

    def insert(self, route: Route) -> None:
        """Insert a route into the tree based on its template path."""
        path = route.template_path
        if not path.startswith("/"):
            path = "/" + path
        segments = _split(path)
        node = self._root
        for seg in segments:
            node = node.get_or_create(seg)
        node.routes.append(route)
        self.route_count += 1

    def __len__(self) -> int:
        return self.route_count

    # ------------------------------------------------------------------
    # Baseline access (used by InferenceEngine)
    # ------------------------------------------------------------------

    def consume_fresh_boundary(self, prefix: str, method: str) -> bool:
        """Return ``True`` (once) if this prefix/method is a freshly discovered boundary.

        The first call for a given ``(prefix, method)`` returns ``True`` and
        clears the flag.  Subsequent calls return ``False``.  Used by the
        inference engine to report the boundary itself as a finding before
        filtering its children.
        """
        key = (prefix, method)
        if key in self._fresh_boundaries:
            self._fresh_boundaries.discard(key)
            return True
        return False

    def set_baseline(self, prefix: str, method: str, baseline: Baseline) -> None:
        """Store a baseline at the given prefix for the given method."""
        node = self._resolve(prefix)
        if node is not None:
            node.baselines[method] = baseline

    def lookup_baseline(self, path: str, method: str) -> tuple[str, Baseline] | None:
        """Return ``(prefix, baseline)`` for the nearest ancestor, or ``None``.

        Falls back to a GET baseline at the same prefix if no method-specific
        baseline exists.
        """
        parts = path.rstrip("/").split("/")
        for i in range(len(parts), 0, -1):
            candidate = "/".join(parts[:i]) or "/"
            node = self._resolve(candidate)
            if node is None:
                continue
            if method in node.baselines:
                return candidate, node.baselines[method]
            if "GET" in node.baselines:
                return candidate, node.baselines["GET"]
        # Check root explicitly
        if method in self._root.baselines:
            return "/", self._root.baselines[method]
        if "GET" in self._root.baselines:
            return "/", self._root.baselines["GET"]
        return None

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    async def initialize(self, send_fn) -> None:
        """Establish root baselines (2 probes per method)."""
        for method in _ALTERNATE_METHODS:
            sigs: list[ResponseSignature] = []
            for _ in range(2):
                path = f"/{_random_segment()}"
                try:
                    sig = await send_fn(method, path, None, None)
                    sigs.append(sig)
                except Exception:
                    pass
            if sigs:
                self._root.baselines[method] = build_baseline(sigs)

    # ------------------------------------------------------------------
    # Depth-first walk with automatic prefix probing
    # ------------------------------------------------------------------

    async def walk(self, send_fn) -> AsyncIterator[Route]:
        """Depth-first iteration.  Probes empty intermediate nodes before
        yielding their children's routes."""
        async for route in self._walk(self._root, "", send_fn):
            yield route

    async def _walk(self, node: _Node, prefix: str, send_fn) -> AsyncIterator[Route]:
        # If this node has children but no baseline, probe it to establish one
        if node.children and prefix:
            await self._probe_node(node, prefix, send_fn)

        # Yield this node's routes
        for route in node.routes:
            yield route

        # Recurse into children in insertion order
        for seg in node._insertion_order:
            child_prefix = f"{prefix}/{seg}" if prefix else f"/{seg}"
            async for route in self._walk(node.children[seg], child_prefix, send_fn):
                yield route

    async def _probe_node(self, node: _Node, prefix: str, send_fn) -> None:
        """Probe a node to establish per-method baselines if needed."""
        for method in _ALTERNATE_METHODS:
            if method in node.baselines:
                continue

            # Find nearest ancestor baseline via lookup (all ancestors probed already)
            ancestor_result = self.lookup_baseline(prefix, method)
            if ancestor_result is None:
                continue
            ancestor_prefix, ancestor_baseline = ancestor_result
            # Don't re-probe if lookup already found a baseline at this exact prefix
            if ancestor_prefix == prefix:
                continue

            probe_path = f"{prefix.rstrip('/')}/{_random_segment()}"
            try:
                probe_sig = await send_fn(method, probe_path, None, None)
            except Exception:
                continue

            # Does the probe differ from the ancestor baseline?
            probe_len = len(probe_path.lstrip("/"))
            if matches_baseline(probe_sig, ancestor_baseline, probe_len) is not None:
                continue

            # New handler boundary — second probe for variance detection
            sigs = [probe_sig]
            try:
                extra_path = f"{prefix.rstrip('/')}/{_random_segment()}"
                extra_sig = await send_fn(method, extra_path, None, None)
                sigs.append(extra_sig)
            except Exception:
                pass

            node.baselines[method] = build_baseline(sigs)
            # Mark this as a fresh boundary — the first route here should be
            # reported even if it matches the baseline, since the boundary
            # itself is a discovery (e.g. a 403 "forbidden" handler).
            self._fresh_boundaries.add((prefix, method))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve(self, prefix: str) -> _Node | None:
        """Resolve a prefix path to its tree node."""
        if prefix == "/" or prefix == "":
            return self._root
        segments = _split(prefix)
        node = self._root
        for seg in segments:
            if seg not in node.children:
                return None
            node = node.children[seg]
        return node


    # ------------------------------------------------------------------
    # Debug: ASCII tree representation
    # ------------------------------------------------------------------

    def format_tree(self) -> str:
        """Return an ASCII representation of the tree showing baselines."""
        lines: list[str] = []
        self._format_node(self._root, "/", "", True, lines)
        return "\n".join(lines)

    def _format_node(
        self, node: _Node, label: str, indent: str, last: bool, lines: list[str],
    ) -> None:
        connector = "└── " if last else "├── "
        if not indent:
            # Root node
            bl_info = self._baseline_summary(node)
            lines.append(f"/ {bl_info}" if bl_info else "/")
        else:
            bl_info = self._baseline_summary(node)
            route_info = f" ({len(node.routes)} routes)" if node.routes else ""
            lines.append(f"{indent}{connector}{label}{route_info} {bl_info}".rstrip())

        child_indent = indent + ("    " if last else "│   ")
        children = list(node._insertion_order)
        for i, seg in enumerate(children):
            is_last = i == len(children) - 1
            self._format_node(node.children[seg], seg, child_indent, is_last, lines)

    @staticmethod
    def _baseline_summary(node: _Node) -> str:
        if not node.baselines:
            return ""
        parts = []
        for method, bl in sorted(node.baselines.items()):
            if bl.signatures:
                ref = bl.signatures[0]
                parts.append(f"{method}:{ref.status_code}/{ref.content_type}")
        return f"[{', '.join(parts)}]" if parts else ""


def _split(path: str) -> list[str]:
    """Split a path into segments: ``/api/v1/users`` -> ``["api", "v1", "users"]``."""
    return [s for s in path.split("/") if s]
