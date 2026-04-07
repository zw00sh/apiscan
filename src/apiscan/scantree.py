"""Scan tree: route storage, baseline management, and prefix probing.

Organises routes into a trie by URL path segments.  Each node can hold:
- **Routes** from the wordlist (in insertion order)
- **Baselines** per HTTP method (discovered by probing)

The tree is a data store — scheduling is handled by the priority queue
in :mod:`apiscan.scanner`.  The key method is :meth:`probe_prefix`,
which probes a prefix for handler boundaries and stores baselines.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from apiscan.inference import (
    Baseline,
    ResponseSignature,
    DEFAULT_METHODS,
    _random_segment,
    build_baseline,
    matches_baseline,
)
from apiscan.kite import Route

# Structural path segments for --lookahead boundary discovery.
# Focused on namespace/version/access-control prefixes — the scaffolding
# that indicates different handlers or services.  Resource-level segments
# (users, orders, etc.) are covered by the wordlist + recursion instead.
# Derived from routes-large.kite and httparchive API routes, both positions.
_LOOKAHEAD_SEGMENTS = [
    "api", "v1", "v2", "rest", "admin", "auth", "public", "app", "v3",
    "services", "sys",
]


# ---------------------------------------------------------------------------
# Events from prefix probing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BoundaryProbe:
    """A handler boundary discovered during prefix probing."""
    prefix: str
    method: str
    signature: ResponseSignature
    ancestor_signature: ResponseSignature


@dataclass(frozen=True)
class BoundaryGroup:
    """All boundary probes for a single prefix, collapsed for display."""
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
    """Route trie with baseline storage and prefix probing.

    Data store only — no walk, no scheduling.  The scanner's priority
    queue controls work ordering.
    """

    def __init__(self, routes: list[Route] | None = None) -> None:
        self._root = _Node(segment="")
        self.route_count = 0
        self._seen: set[tuple[str, str]] = set()
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

    def ancestor_baselines(self, prefix: str, method: str) -> list[Baseline]:
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
        if method in self._root.baselines:
            root_bl = self._root.baselines[method]
            if root_bl not in baselines:
                baselines.append(root_bl)
        if "GET" in self._root.baselines:
            get_bl = self._root.baselines["GET"]
            if get_bl not in baselines:
                baselines.append(get_bl)
        return baselines

    # ------------------------------------------------------------------
    # Initialization (parallel)
    # ------------------------------------------------------------------

    async def initialize(self, send_fn, methods: list[str] | None = None) -> None:
        """Establish root baselines by probing random paths.

        Sends 2 random-path probes per method in parallel to capture the
        default handler response for each HTTP verb.
        """
        methods = methods or DEFAULT_METHODS

        async def _probe(method: str, path: str) -> tuple[str, ResponseSignature | None]:
            try:
                sig = await send_fn(method, path, None, None)
                return method, sig
            except Exception:  # send_fn tracks errors; skip failed probes
                return method, None

        tasks = []
        for method in methods:
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
    # Prefix probing — pure probe + report, no scheduling
    # ------------------------------------------------------------------

    async def probe_prefix(
        self, prefix: str, send_fn, tracker=None,
        methods: list[str] | None = None,
    ) -> BoundaryGroup | None:
        """Probe a prefix for handler boundaries across all methods.

        Resolves or creates the tree node, probes each method against its
        ancestor baselines, stores baselines for deviations.  Idempotent —
        methods already probed at this prefix are skipped.

        Returns a :class:`BoundaryGroup` if any boundaries were found,
        or ``None``.  Does NOT handle recursion or scheduling — the caller
        decides what to do with the result.
        """
        methods = methods or DEFAULT_METHODS
        node = self._resolve_or_create(prefix)

        # Determine which methods need probing (skip already-probed)
        methods_to_probe = [m for m in methods
                            if m not in node.baselines
                            and self.lookup_baseline(prefix, m) is not None
                            and (self.lookup_baseline(prefix, m) or (None,))[0] != prefix]
        if not methods_to_probe:
            return None

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
            except Exception:  # send_fn tracks errors; skip failed probes
                return method, None, None

            # Check against ALL ancestor baselines, not just nearest.
            # A response matching any ancestor is falling back to a known
            # handler (e.g. framework default 404), not a new boundary.
            probe_len = len(probe_path.lstrip("/"))
            for bl in self.ancestor_baselines(prefix, method):
                if matches_baseline(probe_sig, bl, probe_len) is not None:
                    return method, None, None

            return method, probe_sig, ancestor_baseline

        # Fire all method probes in parallel
        results = await asyncio.gather(*[_probe_method(m) for m in methods])

        # Collect methods that need a second variance probe
        discoveries = [(m, sig, bl) for m, sig, bl in results if sig is not None]
        if not discoveries:
            return None

        # Variance probes in parallel
        if tracker:
            tracker.plan(len(discoveries))

        async def _variance_probe(method: str) -> tuple[str, ResponseSignature | None]:
            extra_path = f"{prefix.rstrip('/')}/{_random_segment()}"
            try:
                sig = await send_fn(method, extra_path, None, None)
                return method, sig
            except Exception:  # send_fn tracks errors; skip failed probes
                return method, None

        variance_results = await asyncio.gather(*[_variance_probe(m) for m, _, _ in discoveries])
        variance_by_method = {m: sig for m, sig in variance_results}

        # Register baselines and collect boundary probes.
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

        return BoundaryGroup(prefix=prefix, probes=tuple(probes)) if probes else None

    # ------------------------------------------------------------------
    # Debug: ASCII tree representation
    # ------------------------------------------------------------------

    def format_tree(self, debug: bool) -> str:
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
