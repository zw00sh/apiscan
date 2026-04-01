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
from typing import Callable

from apiscan.inference import (
    Baseline,
    ResponseSignature,
    _ALTERNATE_METHODS,
    _random_segment,
    build_baseline,
    matches_baseline,
)
from apiscan.kite import Route

# Top 20 non-leaf path segments from routes-large.kite, by frequency.
# Used by --lookahead to discover N+1 boundaries that require combining
# multiple path segments (e.g. /users/v1 from flat wordlists).
# Top 20 covers the high-value patterns; the long tail adds cost with
# diminishing returns (#1 api=445k occurrences, #20 search=4.3k).
_LOOKAHEAD_SEGMENTS = [
    "api", "v1", "user", "v2", "admin", "users", "app", "rest", "order",
    "auth", "services", "account", "wx", "customer", "product", "sys", "v3",
    "web", "report", "search",
]


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


@dataclass(frozen=True)
class BoundaryGroup:
    """All boundary probes for a single prefix, pushed as one queue item.

    Allows the scanner to collapse per-method boundary probes into a
    single output line instead of N separate findings.
    """
    prefix: str
    probes: tuple[BoundaryProbe, ...]


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

    def __init__(
        self,
        routes: list[Route] | None = None,
        *,
        recurse: bool = False,
        max_depth: int = 2,
        wordlist: list[Route] | None = None,
        on_recurse: Callable[[str, int, int], None] | None = None,
        lookahead: bool = False,
    ) -> None:
        self._root = _Node(segment="")
        self.route_count = 0
        self._recurse = recurse
        self._max_depth = max_depth
        self._wordlist = wordlist or []
        self._seen: set[tuple[str, str]] = set()
        self._skip: set[str] = set()
        self._on_recurse = on_recurse  # (prefix, new_routes, depth)
        self._prefix_depth: dict[str, int] = {}  # prefix → recursion depth
        self._lookahead = lookahead
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
        self._seen.add((route.template_path, route.method))

    def __len__(self) -> int:
        return self.route_count

    def skip_prefix(self, prefix: str) -> None:
        """Mark a prefix to be skipped during walk. Single-threaded asyncio — no locks."""
        self._skip.add(prefix)

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

        Read-only — safe for concurrent callers without locks.
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
    # Prefix probing (unified — called by _walk and by scanner workers)
    # ------------------------------------------------------------------

    async def probe_prefix(
        self, prefix: str, send_fn, tracker=None, depth: int | None = None,
    ) -> BoundaryGroup | None:
        """Probe a prefix for handler boundaries across all methods.

        Resolves or creates the tree node, probes each method against its
        ancestor baseline, stores baselines for deviations, and optionally
        injects recursive routes.  Idempotent — methods already probed at
        this prefix are skipped.

        Called by ``_walk`` (proactively for tree nodes with children) and
        by scanner workers (reactively when a finding deviates from baseline).
        """
        node = self._resolve_or_create(prefix)

        # Infer depth from parent if not provided
        if depth is None:
            depth = self._infer_depth(prefix)

        # Determine which methods need probing (skip already-probed)
        methods_to_probe = [m for m in _ALTERNATE_METHODS
                            if m not in node.baselines
                            and self.lookup_baseline(prefix, m) is not None
                            and (self.lookup_baseline(prefix, m) or (None,))[0] != prefix]
        if not methods_to_probe:
            return None, []

        if tracker:
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

            # Check against ALL ancestor baselines, not just nearest.
            # A response matching any ancestor is falling back to a known
            # handler (e.g. framework default 404), not a new boundary.
            probe_len = len(probe_path.lstrip("/"))
            for bl in self._ancestor_baselines(prefix, method):
                if matches_baseline(probe_sig, bl, probe_len) is not None:
                    return method, None, None

            return method, probe_sig, ancestor_baseline

        # Fire all method probes in parallel
        results = await asyncio.gather(*[_probe_method(m) for m in _ALTERNATE_METHODS])

        # Collect methods that need a second variance probe
        discoveries = [(m, sig, bl) for m, sig, bl in results if sig is not None]
        if not discoveries:
            return None, []

        # Variance probes in parallel
        if tracker:
            tracker.plan(len(discoveries))

        async def _variance_probe(method: str) -> tuple[str, ResponseSignature | None]:
            extra_path = f"{prefix.rstrip('/')}/{_random_segment()}"
            try:
                sig = await send_fn(method, extra_path, None, None)
                return method, sig
            except Exception:
                return method, None

        variance_results = await asyncio.gather(*[_variance_probe(m) for m, _, _ in discoveries])
        variance_by_method = {m: sig for m, sig in variance_results}

        # Register baselines and collect boundary probes.
        # Safe: only one caller probes a given prefix (idempotent skip above).
        probes = []
        for method, probe_sig, ancestor_baseline in discoveries:
            extra_sig = variance_by_method.get(method)
            sigs = [probe_sig, extra_sig] if extra_sig else [probe_sig]
            node.baselines[method] = build_baseline(sigs)
            probes.append(BoundaryProbe(
                prefix=prefix,
                method=method,
                signature=probe_sig,
                ancestor_signature=ancestor_baseline.signatures[0],
            ))

        # Recursion: inject prefixed wordlist into tree.
        # insert() adds to _insertion_order for tree structure / debug.
        # Returns injected routes so the caller can enqueue them.
        injected: list[Route] = []
        if probes and self._recurse and depth < self._max_depth:
            for route in self._wordlist:
                new_path = f"{prefix}{route.template_path}"
                key = (new_path, route.method)
                if key not in self._seen:
                    self._seen.add(key)
                    new_route = Route(
                        template_path=new_path,
                        method=route.method,
                        path_crumbs=route.path_crumbs,
                        header_crumbs=route.header_crumbs,
                        query_crumbs=route.query_crumbs,
                        body_crumbs=route.body_crumbs,
                        content_types=route.content_types,
                        source_api_url=route.source_api_url,
                    )
                    self.insert(new_route)
                    injected.append(new_route)
                    if tracker:
                        tracker.plan(1)
            if injected:
                if tracker and hasattr(tracker, 'plan_routes'):
                    tracker.plan_routes(len(injected))
                if self._on_recurse:
                    self._on_recurse(prefix, len(injected), depth + 1)

        group = BoundaryGroup(prefix=prefix, probes=tuple(probes)) if probes else None
        return group, injected

    def _ancestor_baselines(self, prefix: str, method: str) -> list[Baseline]:
        """Collect all baselines in the ancestor chain for a given method.

        Includes GET fallback at root — many servers return the same default
        404 regardless of method, so a POST probe matching the root GET
        baseline is still a known handler, not a new boundary.
        """
        baselines = []
        parts = prefix.rstrip("/").split("/")
        for i in range(len(parts), 0, -1):
            candidate = "/".join(parts[:i]) or "/"
            node = self._resolve(candidate)
            if node and method in node.baselines:
                baselines.append(node.baselines[method])
        # Include root for this method
        if method in self._root.baselines:
            root_bl = self._root.baselines[method]
            if root_bl not in baselines:
                baselines.append(root_bl)
        # Fall back to GET at root — default 404 often identical across methods
        if "GET" in self._root.baselines:
            get_bl = self._root.baselines["GET"]
            if get_bl not in baselines:
                baselines.append(get_bl)
        return baselines

    def _infer_depth(self, prefix: str) -> int:
        """Infer recursion depth from nearest ancestor with a known depth."""
        parts = prefix.rstrip("/").split("/")
        for i in range(len(parts) - 1, 0, -1):
            ancestor = "/".join(parts[:i]) or "/"
            if ancestor in self._prefix_depth:
                return self._prefix_depth[ancestor] + 1
        return 0

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

    def _resolve_or_create(self, prefix: str) -> _Node:
        """Like _resolve but creates nodes along the path if missing."""
        if prefix == "/" or prefix == "":
            return self._root
        segments = _split(prefix)
        node = self._root
        for seg in segments:
            node = node.get_or_create(seg)
        return node


def _split(path: str) -> list[str]:
    return [s for s in path.split("/") if s]
