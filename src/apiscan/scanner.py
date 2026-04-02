"""Async HTTP scanning engine with dependency-aware scheduling.

Work is scheduled via a DAG built from ``graphlib.TopologicalSorter``.
Each work item declares its dependencies (e.g. a route depends on its
prefix probe) and the sorter releases items as their deps complete.

Baseline management is handled by :mod:`apiscan.scantree`.
Response classification is handled by :mod:`apiscan.inference`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from graphlib import TopologicalSorter
from typing import Any, Callable

import httpx

logger = logging.getLogger(__name__)

from apiscan.inference import (
    Baseline,
    Finding,
    InferenceEngine,
    ResponseSignature,
    _random_segment,
    build_baseline,
    compute_signature,
    matches_baseline,
)
from apiscan.kite import Route
from apiscan.output import ScanResult
from apiscan.scantree import BoundaryGroup, ScanTree, _LOOKAHEAD_SEGMENTS


# ---------------------------------------------------------------------------
# Work items
# ---------------------------------------------------------------------------

@dataclass
class _ProbeWork:
    """Probe a prefix for handler boundaries."""
    prefix: str = ""
    depth: int = 0


@dataclass
class _RouteWork:
    """Scan a route against its baseline."""
    route: Route = None


@dataclass
class _LookaheadWork:
    """Lightweight GET probe for a single lookahead segment."""
    prefix: str = ""
    segment: str = ""


# Transient errors that a worker should swallow (network, timeout, server).
# Programming errors (TypeError, KeyError, AttributeError, etc.) propagate.
_TRANSIENT_ERRORS = (httpx.HTTPError, OSError, TimeoutError)


# ---------------------------------------------------------------------------
# Work queue — dependency-aware scheduling via TopologicalSorter
# ---------------------------------------------------------------------------

_STAGE_ORDER = ["probing", "wordlist", "recursing", "lookahead"]


class _WorkQueue:
    """Dependency-aware work queue backed by ``graphlib.TopologicalSorter``.

    Items are declared with ``add(key, item, *deps)`` before calling
    ``prepare()``.  Workers pull ready items via ``get()`` and signal
    completion with ``item_done(key)``, which releases dependents.

    Dynamic work (recursion, lookahead, redirects) whose dependencies
    are already satisfied is added via ``enqueue_dynamic()``.
    """

    def __init__(self) -> None:
        self._ts = TopologicalSorter()
        self._ready: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        self._items: dict[str, Any] = {}
        self._inflight = 0
        self._done = asyncio.Event()
        self._done.set()
        self._stage_counts: dict[str, int] = {}
        # Virtual nodes: auto-complete when deps are met (no work item).
        self._virtual: set[str] = set()
        # Manual gates: become ready when deps are met, but require
        # explicit item_done() from scan logic to complete.
        self._manual_gates: set[str] = set()
        # Keys added via enqueue_dynamic / enqueue_recursive_batch (not in main sorter).
        self._dynamic_keys: set[str] = set()
        # Post-prepare dynamic sorters for recursive batches.
        self._dynamic_sorters: list[TopologicalSorter] = []
        # Skip callback: if set, checked before releasing dependents.
        self.skip_fn: Callable[[str, Any], bool] | None = None
        self.skipped = 0

    def add(self, key: str, item: Any, *deps: str) -> None:
        """Declare a work item with dependencies (before prepare)."""
        self._items[key] = item
        self._ts.add(key, *deps)

    def add_manual_gate(self, key: str, *deps: str) -> None:
        """Declare a gate node completed explicitly via ``item_done``.

        Unlike regular items, manual gates do NOT get pushed to the
        worker queue.  They become ready when their deps are met, but
        require scan logic to call ``item_done(key)`` to complete them
        and release their dependents.
        """
        self._manual_gates.add(key)
        self._ts.add(key, *deps)

    def prepare(self) -> None:
        """Finalise the static graph and push initially-ready items."""
        self._ts.prepare()
        self._push_ready()

    def _push_ready(self) -> None:
        recurse = False
        for key in self._ts.get_ready():
            if key in self._manual_gates:
                # Gate is ready but needs explicit item_done().
                self._inflight += 1
                self._done.clear()
                continue
            item = self._items.get(key)
            if item is None:
                self._ts.done(key)
                recurse = True
                continue
            if self.skip_fn and self.skip_fn(key, item):
                self.skipped += 1
                self._ts.done(key)
                recurse = True
                continue
            stage = self._stage_for_key(key)
            self._stage_counts[stage] = self._stage_counts.get(stage, 0) + 1
            self._inflight += 1
            self._done.clear()
            self._ready.put_nowait((key, item))
        if recurse:
            self._push_ready()

    @staticmethod
    def _stage_for_key(key: str) -> str:
        if key.startswith("probe:"):
            return "probing"
        if key.startswith("route:"):
            return "wordlist"
        if key.startswith("lookahead:"):
            return "lookahead"
        if key.startswith("recurse-route:") or key.startswith("recurse-probe:"):
            return "recursing"
        return "wordlist"

    @property
    def stage(self) -> str:
        """Stage with the most active work items."""
        best = ""
        best_count = 0
        for s, count in self._stage_counts.items():
            if count > best_count:
                best = s
                best_count = count
        return best

    @property
    def ready_count(self) -> int:
        """Items ready to be pulled by workers."""
        return self._ready.qsize()

    @property
    def blocked_count(self) -> int:
        """Items waiting on unsatisfied dependencies."""
        # Total items minus ready minus completed
        return max(0, self._inflight - self._ready.qsize())

    async def get(self) -> tuple[str, Any]:
        """Pull the next ready item. Returns ``(key, item)``."""
        return await self._ready.get()

    def item_done(self, key: str) -> None:
        """Mark *key* complete and release its dependents."""
        stage = self._stage_for_key(key)
        self._stage_counts[stage] = max(0, self._stage_counts.get(stage, 0) - 1)
        self._inflight -= 1
        if key not in self._dynamic_keys:
            self._ts.done(key)
            self._push_ready()
        # Also check dynamic sorters
        for ds in self._dynamic_sorters:
            try:
                ds.done(key)
            except ValueError:
                continue
            for dk in ds.get_ready():
                item = self._items.get(dk)
                if item is None:
                    continue
                if self.skip_fn and self.skip_fn(dk, item):
                    self.skipped += 1
                    ds.done(dk)
                    continue
                s = self._stage_for_key(dk)
                self._stage_counts[s] = self._stage_counts.get(s, 0) + 1
                self._inflight += 1
                self._done.clear()
                self._ready.put_nowait((dk, item))
        if self._inflight == 0:
            self._done.set()

    def enqueue_dynamic(self, key: str, item: Any, stage: str = "wordlist") -> None:
        """Add work whose dependencies are already satisfied."""
        self._items[key] = item
        self._dynamic_keys.add(key)
        self._stage_counts[stage] = self._stage_counts.get(stage, 0) + 1
        self._inflight += 1
        self._done.clear()
        self._ready.put_nowait((key, item))

    def enqueue_recursive_batch(
        self, items: list[tuple[str, Any, list[str]]],
    ) -> None:
        """Add a batch of items with internal dependencies.

        Each entry is ``(key, item, dep_keys)``.  A mini sorter resolves
        internal ordering; items with no deps go straight to the ready queue.
        """
        if not items:
            return
        mini = TopologicalSorter()
        for key, item, deps in items:
            self._items[key] = item
            self._dynamic_keys.add(key)
            mini.add(key, *deps)
        mini.prepare()
        for key in mini.get_ready():
            item = self._items[key]
            if self.skip_fn and self.skip_fn(key, item):
                self.skipped += 1
                mini.done(key)
                continue
            self._stage_counts["recursing"] = self._stage_counts.get("recursing", 0) + 1
            self._inflight += 1
            self._done.clear()
            self._ready.put_nowait((key, item))
        if mini.is_active():
            self._dynamic_sorters.append(mini)

    async def wait(self) -> None:
        """Block until all work (static + dynamic) is complete."""
        await self._done.wait()


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._interval - (now - self._last))
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


# ---------------------------------------------------------------------------
# Request tracker
# ---------------------------------------------------------------------------

class RequestTracker:
    """Tracks planned and completed HTTP requests."""

    def __init__(self, initial_planned: int = 0, on_tick: Callable[[], None] | None = None) -> None:
        self.sent = 0
        self.planned = initial_planned
        self.routes_planned = 0
        self.queue_size: Callable[[], int] | None = None
        self.stage: Callable[[], str] | None = None
        self.skipped_fn: Callable[[], int] | None = None
        self.blocked_fn: Callable[[], int] | None = None
        self._on_tick = on_tick

    def plan(self, n: int) -> None:
        self.planned += n

    def plan_routes(self, n: int) -> None:
        self.routes_planned += n

    def tick(self) -> None:
        self.sent += 1
        if self._on_tick:
            self._on_tick()


# ---------------------------------------------------------------------------
# Result building
# ---------------------------------------------------------------------------

def _finding_to_result(
    finding: Finding,
    base_url: str,
    *,
    redirect_location: str | None = None,
    request_headers: dict[str, str] | None = None,
    request_body: str | None = None,
) -> ScanResult:
    path = finding.route.template_path
    return ScanResult(
        url=f"{base_url}{path}",
        method=finding.route.method,
        path=path,
        status_code=finding.signature.status_code,
        content_length=finding.signature.content_length,
        word_count=finding.signature.word_count,
        line_count=finding.signature.line_count,
        redirect_location=redirect_location,
        reason=finding.reason,
        confidence=finding.confidence,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
        request_headers=request_headers,
        request_body=request_body,
        signature=finding.signature,
    )


# ---------------------------------------------------------------------------
# Main scan engine
# ---------------------------------------------------------------------------

async def scan(
    target_url: str,
    routes: list[Route],
    *,
    concurrency: int = 10,
    rate_limit: float | None = None,
    on_phase: Callable[[str, int], None] | None = None,
    timeout: float = 10.0,
    max_redirects: int = 3,
    status_blacklist: set[int] | None = None,
    status_whitelist: set[int] | None = None,
    quarantine_threshold: int = 50,
    extra_headers: dict[str, str] | None = None,
    on_result: Callable[[ScanResult], None] | None = None,
    on_progress: Callable[[int], None] | None = None,
    on_filtered: Callable[[str, str, int, str], None] | None = None,
    on_debug: Callable[[str], None] | None = None,
    on_recurse: Callable[[str, int, int], None] | None = None,
    tracker: RequestTracker | None = None,
    recurse: bool = False,
    max_depth: int = 2,
    lookahead: bool = False,
    methods: list[str] | None = None,
    skip_wildcard_siblings: bool = True,
) -> tuple[list[ScanResult], ScanTree]:
    """Scan *target_url* with the given routes. Returns (findings, tree)."""
    from apiscan.inference import DEFAULT_METHODS
    methods = methods or DEFAULT_METHODS
    base_url = target_url.rstrip("/")
    limiter = RateLimiter(rate_limit) if rate_limit else None
    results: list[ScanResult] = []
    if tracker is None:
        tracker = RequestTracker()

    tree = ScanTree(routes)

    tracker.plan(len(methods) * 2 + len(tree))
    tracker.plan_routes(len(tree))

    def _inference_filtered(route, path, sig, reason):
        if on_filtered:
            on_filtered(route.method, path, sig.status_code, reason)

    engine = InferenceEngine(
        tree=tree,
        status_blacklist=status_blacklist,
        status_whitelist=status_whitelist,
        on_filtered=_inference_filtered,
        on_debug=on_debug,
        tracker=tracker,
        methods=methods,
    )

    async with httpx.AsyncClient(
        follow_redirects=True,
        max_redirects=max_redirects,
        verify=False,
        headers=extra_headers or {},
    ) as client:

        async def send_fn(
            method: str,
            path: str,
            headers: dict[str, str] | None = None,
            body: str | None = None,
        ) -> ResponseSignature:
            url = f"{base_url}{path}"
            if limiter:
                await limiter.acquire()
            resp = await client.request(
                method, url,
                headers=headers or {},
                content=body.encode() if body else None,
                timeout=timeout,
            )
            tracker.tick()
            return compute_signature(
                resp.status_code, dict(resp.headers), resp.content, path,
            )

        await tree.initialize(send_fn, methods=methods)

        # -- Build work graph --------------------------------------------

        wq = _WorkQueue()
        tracker.queue_size = lambda: wq._inflight
        tracker.stage = lambda: wq.stage
        tracker.skipped_fn = lambda: wq.skipped
        tracker.blocked_fn = lambda: wq.blocked_count
        segment_gates = _build_work_graph(tree, wq)

        probed_prefixes: set[str] = set()
        prefix_depth: dict[str, int] = {}
        conn_failures = 0
        conn_lock = asyncio.Lock()
        wordlist = routes

        # Segment-prefix wildcard tracking
        segment_prefix_handlers: dict[tuple[str, str], Baseline] = {}
        suppressed_indices: set[int] = set()

        def _split_path_segment(path: str) -> tuple[str, str]:
            """Split '/foo/bar' into ('/foo', 'bar')."""
            parts = path.rstrip("/").rsplit("/", 1)
            if len(parts) == 2:
                return (parts[0] or "/", parts[1])
            return ("/", parts[0].lstrip("/"))

        if skip_wildcard_siblings:
            def _should_skip(key: str, item: Any) -> bool:
                """Skip probes/routes covered by a known wildcard handler."""
                if isinstance(item, _ProbeWork):
                    path = item.prefix
                elif isinstance(item, _RouteWork):
                    path = item.route.template_path
                else:
                    return False
                parent, segment = _split_path_segment(path)
                for (hp, hs) in segment_prefix_handlers:
                    if hp == parent and segment.startswith(hs) and segment != hs:
                        return True
                return False
            wq.skip_fn = _should_skip

        def _is_segment_suppressed(path: str, sig: ResponseSignature) -> bool:
            """Check if this path+sig is covered by a known prefix handler."""
            parent, segment = _split_path_segment(path)
            path_len = len(path.lstrip("/"))
            for (hp, hs), bl in segment_prefix_handlers.items():
                if hp == parent and segment.startswith(hs) and segment != hs:
                    if matches_baseline(sig, bl, path_len) is not None:
                        return True
            return False

        async def _check_segment_prefix(finding: Finding) -> bool:
            """Probe to detect if this finding is a segment-prefix handler.

            Returns True if suppressed, False if the finding should be emitted.
            Completes the ``segment:{path}`` gate node to release superset
            siblings when this path is a gate.
            """
            path = finding.route.template_path
            parent, segment = _split_path_segment(path)
            key = (parent, segment)
            is_gate = path in segment_gates

            def _complete_gate() -> None:
                if is_gate:
                    wq.item_done(f"segment:{path}")
                    segment_gates.discard(path)

            if _is_segment_suppressed(path, finding.signature):
                _complete_gate()
                return True

            # Probe {path}{random} to see if this is a prefix handler
            suffix = _random_segment()[:8]
            probe_path = f"{path}{suffix}"
            tracker.plan(1)
            try:
                probe_sig = await send_fn("GET", probe_path, None, None)
            except Exception:
                _complete_gate()
                return False

            finding_bl = build_baseline([finding.signature])
            probe_len = len(probe_path.lstrip("/"))
            if matches_baseline(probe_sig, finding_bl, probe_len) is None:
                _complete_gate()
                return False  # not a prefix handler

            # Register as prefix handler
            segment_prefix_handlers[key] = finding_bl

            # Retroactively sweep already-emitted results
            for i, existing in enumerate(results):
                if i in suppressed_indices:
                    continue
                if existing.signature is None:
                    continue
                ep, eseg = _split_path_segment(existing.path)
                if ep == parent and eseg.startswith(segment) and eseg != segment:
                    elen = len(existing.path.lstrip("/"))
                    if matches_baseline(existing.signature, finding_bl, elen) is not None:
                        suppressed_indices.add(i)

            _complete_gate()
            return False  # the handler itself is emitted

        # -- Helpers ------------------------------------------------------

        def _emit(finding: Finding, **kw) -> None:
            result = _finding_to_result(finding, base_url, **kw)
            results.append(result)
            if on_result:
                on_result(result)

        async def _emit_boundary(group: BoundaryGroup) -> None:
            findings = []
            for probe in group.probes:
                finding = engine.classify_boundary(probe)
                if finding is not None:
                    findings.append(finding)
            if not findings:
                return
            method_statuses = [f"{f.route.method}={f.signature.status_code}" for f in findings]
            primary = findings[0]
            boundary_finding = Finding(
                route=Route(template_path=group.prefix, method="*"),
                signature=primary.signature,
                reason=f"boundary: {', '.join(method_statuses)}",
                confidence=primary.confidence,
            )
            if await _check_segment_prefix(boundary_finding):
                return
            _emit(boundary_finding)

        def _inject_recursive(prefix: str, depth: int) -> None:
            if not recurse or depth >= max_depth:
                return
            items: list[tuple[str, Any, list[str]]] = []
            seen_sub: set[str] = set()
            for route in wordlist:
                new_path = f"{prefix}{route.template_path}"
                route_key_pair = (new_path, route.method)
                if route_key_pair not in tree._seen:
                    new_route = Route(template_path=new_path, method=route.method)
                    tree.insert(new_route)
                    tracker.plan(1)
                    tracker.plan_routes(1)
                    parts = new_path.rstrip("/").rsplit("/", 1)
                    sub_prefix = parts[0] if len(parts) > 1 and parts[0] else "/"
                    route_key = f"recurse-route:{new_path}:{route.method}"
                    if sub_prefix != prefix and sub_prefix not in seen_sub and sub_prefix not in probed_prefixes:
                        seen_sub.add(sub_prefix)
                        probe_key = f"recurse-probe:{sub_prefix}"
                        items.append((probe_key, _ProbeWork(prefix=sub_prefix, depth=depth + 1), []))
                        items.append((route_key, _RouteWork(route=new_route), [probe_key]))
                    else:
                        items.append((route_key, _RouteWork(route=new_route), []))
            if items:
                wq.enqueue_recursive_batch(items)
                route_count = sum(1 for k, _, _ in items if k.startswith("recurse-route:"))
                if on_recurse:
                    on_recurse(prefix, route_count, depth + 1)

        # -- Work handlers ------------------------------------------------

        async def _handle_probe(work: _ProbeWork, key: str) -> None:
            if work.prefix in probed_prefixes:
                return
            probed_prefixes.add(work.prefix)
            prefix_depth[work.prefix] = work.depth

            group = await tree.probe_prefix(work.prefix, send_fn, tracker, methods=methods)
            if group:
                await _emit_boundary(group)
                _inject_recursive(work.prefix, work.depth)
            else:
                # No boundary — complete segment gate if this is one
                if work.prefix in segment_gates:
                    wq.item_done(f"segment:{work.prefix}")
                    segment_gates.discard(work.prefix)

            if not group and lookahead and not tree._resolve(work.prefix).children:
                for i, seg in enumerate(_LOOKAHEAD_SEGMENTS):
                    la_key = f"lookahead:{work.prefix}/{seg}"
                    wq.enqueue_dynamic(la_key, _LookaheadWork(prefix=work.prefix, segment=seg), stage="lookahead")

        async def _handle_lookahead(work: _LookaheadWork) -> None:
            sub_prefix = f"{work.prefix}/{work.segment}"
            sub_node = tree._resolve(sub_prefix)
            if sub_node and "GET" in sub_node.baselines:
                return
            ancestor_baselines = tree.ancestor_baselines(work.prefix, "GET")
            if not ancestor_baselines:
                return
            tracker.plan(1)
            probe_path = f"{sub_prefix}/{_random_segment()}"
            try:
                sig = await send_fn("GET", probe_path, None, None)
            except Exception:
                return
            path_len = len(probe_path.lstrip("/"))
            for bl in ancestor_baselines:
                if matches_baseline(sig, bl, path_len) is not None:
                    return
            depth = 0
            parts = sub_prefix.rstrip("/").split("/")
            for i in range(len(parts) - 1, 0, -1):
                ancestor = "/".join(parts[:i]) or "/"
                if ancestor in prefix_depth:
                    depth = prefix_depth[ancestor] + 1
                    break
            la_probe_key = f"recurse-probe:{sub_prefix}"
            wq.enqueue_dynamic(la_probe_key, _ProbeWork(prefix=sub_prefix, depth=depth), stage="probing")

        async def _handle_route(work: _RouteWork, key: str) -> None:
            nonlocal conn_failures
            route = work.route
            async with conn_lock:
                if conn_failures >= quarantine_threshold:
                    if on_progress:
                        on_progress(0)
                    return

            path = route.template_path
            url = f"{base_url}{path}"
            if len(url) > 2000:
                url = url[:2000]

            headers: dict[str, str] = {}
            body_str: str | None = None

            if limiter:
                await limiter.acquire()
            try:
                resp = await client.request(
                    route.method, url,
                    headers=headers,
                    content=body_str.encode() if body_str else None,
                    timeout=timeout,
                )
            except Exception:
                async with conn_lock:
                    conn_failures += 1
                if on_progress:
                    on_progress(0)
                return

            async with conn_lock:
                conn_failures = 0
            tracker.tick()

            sig = compute_signature(
                resp.status_code, dict(resp.headers), resp.content, path,
            )

            findings = await engine.process(route, sig, path, send_fn)

            if not findings:
                # No findings — complete segment gate if applicable
                if path in segment_gates:
                    wq.item_done(f"segment:{path}")
                    segment_gates.discard(path)
                if on_progress:
                    on_progress(0)
                return

            group = await tree.probe_prefix(path, send_fn, tracker, methods=methods)
            if group:
                await _emit_boundary(group)
                _inject_recursive(path, prefix_depth.get(path, 0))

            redirect_location = str(resp.url) if resp.history else None
            if resp.history:
                final_url = str(resp.url)
                if final_url.startswith(base_url):
                    redir_path = final_url[len(base_url):]
                    if redir_path and redir_path.startswith("/"):
                        if (redir_path, route.method) not in tree._seen:
                            tree.insert(Route(template_path=redir_path, method=route.method))
                            tracker.plan(1)
                            redir_key = f"redir-route:{redir_path}:{route.method}"
                            wq.enqueue_dynamic(redir_key, _RouteWork(
                                route=Route(template_path=redir_path, method=route.method)))

            emitted = 0
            for finding in findings:
                if await _check_segment_prefix(finding):
                    continue
                _emit(finding, redirect_location=redirect_location,
                      request_headers=headers, request_body=body_str)
                emitted += 1

            if on_progress:
                on_progress(emitted)

        # -- Worker dispatch ----------------------------------------------

        if on_phase:
            on_phase("scanning", len(tree))

        wq.prepare()

        async def _worker() -> None:
            while True:
                try:
                    key, item = await wq.get()
                except asyncio.CancelledError:
                    return
                try:
                    if isinstance(item, _ProbeWork):
                        await _handle_probe(item, key)
                    elif isinstance(item, _RouteWork):
                        await _handle_route(item, key)
                    elif isinstance(item, _LookaheadWork):
                        await _handle_lookahead(item)
                except asyncio.CancelledError:
                    wq.item_done(key)
                    raise
                except _TRANSIENT_ERRORS:
                    logger.debug("Transient error processing %s", type(item).__name__, exc_info=True)
                except Exception:
                    logger.exception("Bug in worker processing %s", type(item).__name__)
                    raise
                wq.item_done(key)

        workers = [asyncio.create_task(_worker()) for _ in range(concurrency)]

        try:
            await wq.wait()
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    # Final sweep: remove segment-prefix duplicates discovered during the scan.
    if segment_prefix_handlers:
        results = [
            r for r in results
            if r.signature is None
            or not _is_segment_suppressed(r.path, r.signature)
        ]

    return results, tree


# ---------------------------------------------------------------------------
# Work graph construction
# ---------------------------------------------------------------------------

def _build_work_graph(tree: ScanTree, wq: _WorkQueue) -> set[str]:
    """Traverse the tree and declare all work items + dependency edges.

    Returns the set of paths that have a ``segment:{path}`` manual gate
    (i.e. paths that are segment-prefix gates with superset siblings).
    """
    segment_gates: set[str] = set()

    def _visit(node, prefix: str, parent_prefix: str) -> None:
        if not prefix:
            # Root node: routes have no prefix dependency
            for route in sorted(node.routes, key=lambda r: r.template_path):
                key = f"route:{route.template_path}:{route.method}"
                wq.add(key, _RouteWork(route=route))
        else:
            probe_key = f"probe:{prefix}"

            if parent_prefix == "":
                # First-level prefix: no parent probe dependency
                wq.add(probe_key, _ProbeWork(prefix=prefix, depth=0))
            else:
                parent_probe = f"probe:{parent_prefix}"
                wq.add(probe_key, _ProbeWork(prefix=prefix, depth=0), parent_probe)

            for route in sorted(node.routes, key=lambda r: r.template_path):
                route_key = f"route:{route.template_path}:{route.method}"
                wq.add(route_key, _RouteWork(route=route), probe_key)

        # Visit children in sorted order, detecting segment-prefix gates
        sorted_segs = sorted(node.children)
        gate_map: dict[str, str] = {}  # later_path -> gate_path
        for i, seg in enumerate(sorted_segs):
            gate_path = f"{prefix}/{seg}" if prefix else f"/{seg}"
            for later in sorted_segs[i + 1:]:
                if later.startswith(seg) and later != seg:
                    later_path = f"{prefix}/{later}" if prefix else f"/{later}"
                    gate_map[later_path] = gate_path

        # Create segment: manual gate nodes for gates.
        # No dependency on probe — the gate is completed explicitly
        # by _check_segment_prefix or _handle_probe/_handle_route
        # fallback paths.  The probe→gate ordering is implicit: the
        # probe handler calls _check_segment_prefix which completes
        # the gate.
        for later_path, gate_path in gate_map.items():
            if gate_path not in segment_gates:
                segment_gates.add(gate_path)
                wq.add_manual_gate(f"segment:{gate_path}")

        for seg in sorted_segs:
            child_prefix = f"{prefix}/{seg}" if prefix else f"/{seg}"
            child_node = node.children[seg]

            if child_prefix in gate_map:
                # Deferred: probe depends on gate's segment: node
                gate_path = gate_map[child_prefix]
                probe_key = f"probe:{child_prefix}"
                segment_key = f"segment:{gate_path}"
                if parent_prefix == "":
                    wq.add(probe_key, _ProbeWork(prefix=child_prefix, depth=0), segment_key)
                else:
                    parent_probe = f"probe:{parent_prefix}"
                    wq.add(probe_key, _ProbeWork(prefix=child_prefix, depth=0), segment_key, parent_probe)
                for route in sorted(child_node.routes, key=lambda r: r.template_path):
                    route_key = f"route:{route.template_path}:{route.method}"
                    wq.add(route_key, _RouteWork(route=route), probe_key)
                # Recurse into deferred node's children
                for subseg in sorted(child_node.children):
                    sub_prefix = f"{child_prefix}/{subseg}"
                    _visit(child_node.children[subseg], sub_prefix, child_prefix)
            else:
                _visit(child_node, child_prefix, prefix)

    _visit(tree._root, "", "")
    return segment_gates
