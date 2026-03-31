"""Unified scan tree: routes, baselines, and prefix probing in one structure.

Organises routes into a tree by URL path segments.  Each node can hold:
- **Routes** from the wordlist (in insertion order)
- **Baselines** per HTTP method (discovered by probing)

Async iteration is depth-first.  At each node the tree:
1. Probes for handler boundaries (if the node has children and no baseline yet)
2. Yields ``BoundaryProbe`` events for any newly-discovered boundaries
3. Yields the node's routes

This ensures baselines are established before children are scanned, and
boundary discoveries flow through the same classification pipeline as routes.
"""

from __future__ import annotations

import asyncio
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


# ---------------------------------------------------------------------------
# Events yielded during tree walk
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BoundaryProbe:
    """A handler boundary discovered during prefix probing.

    Yielded by the tree walk so the scanner can classify it through the
    same pipeline as normal routes.
    """
    prefix: str
    method: str
    signature: ResponseSignature
    ancestor_signature: ResponseSignature


# ---------------------------------------------------------------------------
# Tree node
# ---------------------------------------------------------------------------

@dataclass
class _Node:
    segment: str
    routes: list[Route] = field(default_factory=list)
    children: dict[str, _Node] = field(default_factory=dict)
    _insertion_order: list[str] = field(default_factory=list)
    baselines: dict[str, Baseline] = field(default_factory=dict)

    def get_or_create(self, segment: str) -> _Node:
        if segment not in self.children:
            self.children[segment] = _Node(segment=segment)
            self._insertion_order.append(segment)
        return self.children[segment]


# ---------------------------------------------------------------------------
# Scan tree
# ---------------------------------------------------------------------------

class ScanTree:
    """Unified tree holding routes and baselines, iterable depth-first.

    Yields :class:`Route` and :class:`BoundaryProbe` objects during walk.
    """

    def __init__(self, routes: list[Route] | None = None) -> None:
        self._root = _Node(segment="")
        self.route_count = 0
        if routes:
            for route in routes:
                self.insert(route)

    def insert(self, route: Route) -> None:
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
    # Baseline access
    # ------------------------------------------------------------------

    def set_baseline(self, prefix: str, method: str, baseline: Baseline) -> None:
        node = self._resolve(prefix)
        if node is not None:
            node.baselines[method] = baseline

    def lookup_baseline(self, path: str, method: str) -> tuple[str, Baseline] | None:
        """Return ``(prefix, baseline)`` for the nearest ancestor, or ``None``.

        Only returns method-specific baselines.  Falls back to GET only at
        root, where all methods are explicitly probed during initialization.
        """
        parts = path.rstrip("/").split("/")
        for i in range(len(parts), 0, -1):
            candidate = "/".join(parts[:i]) or "/"
            node = self._resolve(candidate)
            if node is None:
                continue
            if method in node.baselines:
                return candidate, node.baselines[method]
        if method in self._root.baselines:
            return "/", self._root.baselines[method]
        if "GET" in self._root.baselines:
            return "/", self._root.baselines["GET"]
        return None

    # ------------------------------------------------------------------
    # Initialization (parallel)
    # ------------------------------------------------------------------

    async def initialize(self, send_fn) -> None:
        """Establish root baselines by probing random paths.

        Sends 2 random-path probes per method in parallel to capture the
        default handler response for each HTTP verb.
        """
        async def _probe(method: str, path: str) -> tuple[str, ResponseSignature | None]:
            try:
                sig = await send_fn(method, path, None, None)
                return method, sig
            except Exception:
                return method, None

        tasks = []
        for method in _ALTERNATE_METHODS:
            tasks.append(_probe(method, f"/{_random_segment()}"))
            tasks.append(_probe(method, f"/{_random_segment()}"))

        results = await asyncio.gather(*tasks)

        by_method: dict[str, list[ResponseSignature]] = {}
        for method, sig in results:
            if sig is not None:
                by_method.setdefault(method, []).append(sig)
        for method, sigs in by_method.items():
            if sigs:
                self._root.baselines[method] = build_baseline(sigs)

    # ------------------------------------------------------------------
    # Depth-first walk with parallel prefix probing
    # ------------------------------------------------------------------

    async def walk(self, send_fn, tracker=None) -> AsyncIterator[Route | BoundaryProbe]:
        """Depth-first iteration.  Probes intermediate nodes and yields
        boundary discoveries before yielding routes."""
        async for item in self._walk(self._root, "", send_fn, tracker):
            yield item

    async def _walk(
        self, node: _Node, prefix: str, send_fn, tracker=None,
    ) -> AsyncIterator[Route | BoundaryProbe]:
        # Probe this node for handler boundaries (if it has children)
        if node.children and prefix:
            async for bp in self._probe_node(node, prefix, send_fn, tracker):
                yield bp

        # Yield this node's routes
        for route in node.routes:
            yield route

        # Recurse into children in insertion order
        for seg in node._insertion_order:
            child_prefix = f"{prefix}/{seg}" if prefix else f"/{seg}"
            async for item in self._walk(node.children[seg], child_prefix, send_fn, tracker):
                yield item

    async def _probe_node(
        self, node: _Node, prefix: str, send_fn, tracker=None,
    ) -> AsyncIterator[BoundaryProbe]:
        """Probe a node in parallel for all methods, yield boundary discoveries."""
        # Count methods that actually need probing
        methods_to_probe = [m for m in _ALTERNATE_METHODS
                            if m not in node.baselines
                            and self.lookup_baseline(prefix, m) is not None
                            and (self.lookup_baseline(prefix, m) or (None,))[0] != prefix]
        if methods_to_probe and tracker:
            tracker.plan(len(methods_to_probe))

        async def _probe_method(method: str) -> tuple[str, ResponseSignature | None, Baseline | None]:
            if method in node.baselines:
                return method, None, None
            ancestor_result = self.lookup_baseline(prefix, method)
            if ancestor_result is None:
                return method, None, None
            ancestor_prefix, ancestor_baseline = ancestor_result
            if ancestor_prefix == prefix:
                return method, None, None

            probe_path = f"{prefix.rstrip('/')}/{_random_segment()}"
            try:
                probe_sig = await send_fn(method, probe_path, None, None)
            except Exception:
                return method, None, None

            probe_len = len(probe_path.lstrip("/"))
            if matches_baseline(probe_sig, ancestor_baseline, probe_len) is not None:
                return method, None, None

            return method, probe_sig, ancestor_baseline

        # Fire all method probes in parallel
        results = await asyncio.gather(*[_probe_method(m) for m in _ALTERNATE_METHODS])

        # Collect methods that need a second variance probe
        discoveries = [(m, sig, bl) for m, sig, bl in results if sig is not None]
        if not discoveries:
            return

        # Add variance probes to the total
        if tracker:
            tracker.plan(len(discoveries))

        # Fire all variance probes in parallel
        async def _variance_probe(method: str) -> tuple[str, ResponseSignature | None]:
            extra_path = f"{prefix.rstrip('/')}/{_random_segment()}"
            try:
                sig = await send_fn(method, extra_path, None, None)
                return method, sig
            except Exception:
                return method, None

        variance_results = await asyncio.gather(*[_variance_probe(m) for m, _, _ in discoveries])
        variance_by_method = {m: sig for m, sig in variance_results}

        # Register baselines and yield boundary probes
        for method, probe_sig, ancestor_baseline in discoveries:
            extra_sig = variance_by_method.get(method)
            sigs = [probe_sig, extra_sig] if extra_sig else [probe_sig]
            node.baselines[method] = build_baseline(sigs)
            yield BoundaryProbe(
                prefix=prefix,
                method=method,
                signature=probe_sig,
                ancestor_signature=ancestor_baseline.signatures[0],
            )

    # ------------------------------------------------------------------
    # Debug: ASCII tree representation
    # ------------------------------------------------------------------

    def format_tree(self) -> str:
        lines: list[str] = []
        self._format_node(self._root, "/", "", True, lines)
        return "\n".join(lines)

    def _format_node(
        self, node: _Node, label: str, indent: str, last: bool, lines: list[str],
    ) -> None:
        connector = "└── " if last else "├── "
        if not indent:
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

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _resolve(self, prefix: str) -> _Node | None:
        if prefix == "/" or prefix == "":
            return self._root
        segments = _split(prefix)
        node = self._root
        for seg in segments:
            if seg not in node.children:
                return None
            node = node.children[seg]
        return node


def _split(path: str) -> list[str]:
    return [s for s in path.split("/") if s]
