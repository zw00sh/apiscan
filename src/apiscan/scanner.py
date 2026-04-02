"""Async HTTP scanning engine with priority queue scheduling.

Work is scheduled via a single ``asyncio.PriorityQueue``:

- Priority 0: Original wordlist routes (direct hits)
- Priority 1: Prefix probes (boundary detection)
- Priority 2: Recursive routes under confirmed boundaries
- Priority 3+i: Lookahead probes by segment popularity

Baseline management is handled by :mod:`apiscan.scantree`.
Response classification is handled by :mod:`apiscan.inference`.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import time
from dataclasses import dataclass
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
# Work queue — wraps PriorityQueue with inflight tracking
# ---------------------------------------------------------------------------

class _WorkQueue:
    """Single entry point for scheduling and completing work items.

    Items are stored as ``(priority, order, item)`` tuples so that
    ``heapq`` never compares the work-item dataclasses directly.
    """

    _STAGE_NAMES = {0: "wordlist", 1: "probing", 2: "recursing", 3: "lookahead"}

    def __init__(self) -> None:
        self._pq: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._order = itertools.count()
        self._inflight = 0
        self._done = asyncio.Event()
        self._done.set()  # no work yet → "done"
        self._priority_counts: dict[int, int] = {}

    @property
    def stage(self) -> str:
        """Lowest priority level with active work (queued or processing)."""
        for p in sorted(self._priority_counts):
            if self._priority_counts[p] > 0:
                return self._STAGE_NAMES.get(p, self._STAGE_NAMES[3])
        return ""

    def enqueue(self, priority: int, item: Any) -> None:
        self._inflight += 1
        self._priority_counts[priority] = self._priority_counts.get(priority, 0) + 1
        self._done.clear()
        self._pq.put_nowait((priority, next(self._order), item))

    async def get(self) -> tuple[int, Any]:
        """Pull the next item. Returns ``(priority, item)``."""
        priority, _, item = await self._pq.get()
        return priority, item

    def item_done(self, priority: int) -> None:
        self._priority_counts[priority] -= 1
        self._inflight -= 1
        if self._inflight == 0:
            self._done.set()

    async def wait(self) -> None:
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

        # -- Scheduler state ---------------------------------------------

        wq = _WorkQueue()
        tracker.queue_size = lambda: wq._inflight
        tracker.stage = lambda: wq.stage
        pending_routes: dict[str, list[tuple[int, _RouteWork]]] = {}
        pending_children: dict[str, list[_ProbeWork]] = {}
        probed_prefixes: set[str] = set()
        prefix_depth: dict[str, int] = {}
        skip_prefixes: set[str] = set()
        conn_failures = 0
        wordlist = routes

        # Segment-prefix wildcard tracking
        segment_prefix_handlers: dict[tuple[str, str], Baseline] = {}
        suppressed_indices: set[int] = set()

        # Segment-prefix parking: superset segments (e.g. /auth.cgi when
        # /auth exists) are held until the gate's _check_segment_prefix
        # completes.  Maps gate path -> list of parked (priority, work).
        pending_segment: dict[str, list[tuple[int, Any]]] = {}
        # Maps deferred path -> gate path it's waiting on
        _segment_deferred: dict[str, str] = {}

        def _init_segment_deps(node, prefix: str) -> None:
            sorted_segs = sorted(node.children)
            for i, seg in enumerate(sorted_segs):
                gate_path = f"{prefix}/{seg}" if prefix else f"/{seg}"
                has_supersets = False
                for later in sorted_segs[i + 1:]:
                    if later.startswith(seg) and later != seg:
                        later_path = f"{prefix}/{later}" if prefix else f"/{later}"
                        _segment_deferred[later_path] = gate_path
                        has_supersets = True
                if has_supersets:
                    pending_segment.setdefault(gate_path, [])
                _init_segment_deps(node.children[seg], gate_path)
        _init_segment_deps(tree._root, "")

        def _split_path_segment(path: str) -> tuple[str, str]:
            """Split '/foo/bar' into ('/foo', 'bar')."""
            parts = path.rstrip("/").rsplit("/", 1)
            if len(parts) == 2:
                return (parts[0] or "/", parts[1])
            return ("/", parts[0].lstrip("/"))

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

            Returns True if the finding should be suppressed (covered by
            an existing prefix handler).  Returns False if the finding
            should be emitted (it may itself be registered as a handler).

            When this path is a gate (has superset siblings parked behind
            it), releases them after the probe completes — whether or not
            it turns out to be a prefix handler.
            """
            path = finding.route.template_path
            parent, segment = _split_path_segment(path)
            key = (parent, segment)
            is_gate = path in pending_segment

            # Already covered by a known prefix handler?
            if _is_segment_suppressed(path, finding.signature):
                if is_gate:
                    _release_segment_siblings(path)
                return True

            # Probe {path}{random} to see if this is a prefix handler
            suffix = _random_segment()[:8]
            probe_path = f"{path}{suffix}"
            tracker.plan(1)
            try:
                probe_sig = await send_fn("GET", probe_path, None, None)
            except Exception:
                if is_gate:
                    _release_segment_siblings(path)
                return False

            finding_bl = build_baseline([finding.signature])
            probe_len = len(probe_path.lstrip("/"))
            if matches_baseline(probe_sig, finding_bl, probe_len) is None:
                if is_gate:
                    _release_segment_siblings(path)
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

            if is_gate:
                _release_segment_siblings(path)
            return False  # the handler itself is emitted

        # -- Helpers ------------------------------------------------------

        def _release_segment_siblings(gate_path: str) -> None:
            """Release work items parked behind a segment-prefix gate."""
            for pri, item in pending_segment.pop(gate_path, []):
                wq.enqueue(pri, item)

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

        def _is_skipped(prefix: str) -> bool:
            return any(prefix.startswith(sp) for sp in skip_prefixes)

        def _release_routes(prefix: str) -> None:
            if prefix in pending_routes:
                for priority, item in pending_routes.pop(prefix):
                    wq.enqueue(priority, item)

        def _release_children(prefix: str) -> None:
            if prefix in pending_children:
                for item in pending_children.pop(prefix):
                    wq.enqueue(1, item)

        def _inject_recursive(prefix: str, depth: int) -> None:
            if not recurse or depth >= max_depth:
                return
            injected = 0
            seen_sub: set[str] = set()
            for route in wordlist:
                new_path = f"{prefix}{route.template_path}"
                key = (new_path, route.method)
                if key not in tree._seen:
                    new_route = Route(template_path=new_path, method=route.method)
                    tree.insert(new_route)
                    wq.enqueue(2, _RouteWork(route=new_route))
                    tracker.plan(1)
                    tracker.plan_routes(1)
                    injected += 1
                    # Enqueue probe for this route's parent prefix
                    parts = new_path.rstrip("/").rsplit("/", 1)
                    sub_prefix = parts[0] if len(parts) > 1 and parts[0] else "/"
                    if sub_prefix != prefix and sub_prefix not in seen_sub and sub_prefix not in probed_prefixes:
                        seen_sub.add(sub_prefix)
                        wq.enqueue(1, _ProbeWork(prefix=sub_prefix, depth=depth + 1))
            if injected and on_recurse:
                on_recurse(prefix, injected, depth + 1)

        # -- Work handlers ------------------------------------------------

        async def _handle_probe(work: _ProbeWork) -> None:
            if work.prefix in probed_prefixes or _is_skipped(work.prefix):
                _release_routes(work.prefix)
                _release_children(work.prefix)
                return
            probed_prefixes.add(work.prefix)
            prefix_depth[work.prefix] = work.depth

            group = await tree.probe_prefix(work.prefix, send_fn, tracker, methods=methods)
            if group:
                await _emit_boundary(group)
                _inject_recursive(work.prefix, work.depth)
            else:
                # No boundary — if this was a segment gate, release
                # parked siblings (the gate isn't a prefix handler).
                if work.prefix in pending_segment:
                    _release_segment_siblings(work.prefix)
            if not group and lookahead and not tree._resolve(work.prefix).children:
                for i, seg in enumerate(_LOOKAHEAD_SEGMENTS):
                    wq.enqueue(3 + i, _LookaheadWork(prefix=work.prefix, segment=seg))

            _release_routes(work.prefix)
            _release_children(work.prefix)

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
            wq.enqueue(1, _ProbeWork(prefix=sub_prefix, depth=depth))

        async def _handle_route(work: _RouteWork) -> None:
            nonlocal conn_failures
            route = work.route
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
                conn_failures += 1
                if on_progress:
                    on_progress(0)
                return

            conn_failures = 0
            tracker.tick()

            sig = compute_signature(
                resp.status_code, dict(resp.headers), resp.content, path,
            )

            findings = await engine.process(route, sig, path, send_fn)

            if not findings:
                if path in pending_segment:
                    _release_segment_siblings(path)
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
                            wq.enqueue(0, _RouteWork(
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

        async def _worker() -> None:
            while True:
                try:
                    priority, item = await wq.get()
                except asyncio.CancelledError:
                    return
                try:
                    if isinstance(item, _ProbeWork):
                        await _handle_probe(item)
                    elif isinstance(item, _RouteWork):
                        await _handle_route(item)
                    elif isinstance(item, _LookaheadWork):
                        await _handle_lookahead(item)
                except asyncio.CancelledError:
                    wq.item_done(priority)
                    raise
                except _TRANSIENT_ERRORS:
                    logger.debug("Transient error processing %s", type(item).__name__, exc_info=True)
                except Exception:
                    logger.exception("Bug in worker processing %s", type(item).__name__)
                    raise
                wq.item_done(priority)

        # Seed the priority queue
        _seed_queue(tree, wq, pending_routes, pending_children,
                    segment_deferred=_segment_deferred,
                    pending_segment=pending_segment)

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
    # Concurrent workers may emit findings before their prefix handler is
    # registered, so we do one last pass over all results.
    if segment_prefix_handlers:
        results = [
            r for r in results
            if r.signature is None
            or not _is_segment_suppressed(r.path, r.signature)
        ]

    return results, tree


# ---------------------------------------------------------------------------
# Queue seeding
# ---------------------------------------------------------------------------

def _seed_queue(
    tree: ScanTree,
    wq: _WorkQueue,
    pending_routes: dict[str, list[tuple[int, _RouteWork]]],
    pending_children: dict[str, list[_ProbeWork]],
    segment_deferred: dict[str, str] | None = None,
    pending_segment: dict[str, list[tuple[int, Any]]] | None = None,
) -> None:
    """Traverse the tree and enqueue initial work items.

    Segments that are supersets of a sibling (e.g. ``auth.cgi`` when
    ``auth`` exists) are parked in ``pending_segment`` behind the
    shorter sibling's gate path, released when the gate's segment-prefix
    check completes.
    """
    deferred = segment_deferred or {}

    def _visit(node, prefix: str, parent_prefix: str) -> None:
        if prefix:
            for route in sorted(node.routes, key=lambda r: r.template_path):
                pending_routes.setdefault(prefix, []).append(
                    (0, _RouteWork(route=route)))
            gate = deferred.get(prefix)
            if gate and pending_segment is not None:
                # Park this probe behind the gate — released when
                # the gate's _check_segment_prefix completes.
                pending_segment.setdefault(gate, []).append(
                    (1, _ProbeWork(prefix=prefix, depth=0)))
            elif parent_prefix == "":
                wq.enqueue(1, _ProbeWork(prefix=prefix, depth=0))
            else:
                pending_children.setdefault(parent_prefix, []).append(
                    _ProbeWork(prefix=prefix, depth=0))
        else:
            for route in sorted(node.routes, key=lambda r: r.template_path):
                wq.enqueue(0, _RouteWork(route=route))
        for seg in sorted(node.children):
            child_prefix = f"{prefix}/{seg}" if prefix else f"/{seg}"
            _visit(node.children[seg], child_prefix, prefix)

    _visit(tree._root, "", "")
