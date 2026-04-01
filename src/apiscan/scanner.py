"""Async HTTP scanning engine.

Thin transport layer — sends requests, manages concurrency and rate limiting.
Baseline management is handled by :mod:`apiscan.scantree`.
Response classification is handled by :mod:`apiscan.inference`.

Work is scheduled via a priority queue:
  Priority 0: Original wordlist routes
  Priority 1: Prefix probes (boundary detection)
  Priority 2: Recursive routes under confirmed boundaries
  Priority 3+i: Lookahead probes by segment popularity
"""

from __future__ import annotations

import asyncio
import itertools
import time
from typing import Callable

import httpx

from apiscan.inference import (
    Finding,
    InferenceEngine,
    ResponseSignature,
    _ALTERNATE_METHODS,
    _random_segment,
    compute_signature,
    matches_baseline,
)
from apiscan.kite import Route, render_body, render_headers, render_path, render_query
from apiscan.output import ScanResult
from apiscan.scantree import BoundaryGroup, ScanTree, _LOOKAHEAD_SEGMENTS


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
# Request tracker — single object shared across tree, inference, and scanner
# ---------------------------------------------------------------------------

class RequestTracker:
    """Tracks planned and completed HTTP requests.

    Passed to the scan tree and inference engine so they can call
    :meth:`plan` before sending batches.  The scanner calls :meth:`tick`
    after each completed request.  The progress tracker reads
    :attr:`sent` and :attr:`planned` directly.
    """

    def __init__(self, initial_planned: int = 0, on_tick: Callable[[], None] | None = None) -> None:
        self.sent = 0
        self.planned = initial_planned
        self.routes_planned = 0
        self._on_tick = on_tick

    def plan(self, n: int) -> None:
        """Register *n* additional requests that will be sent."""
        self.planned += n

    def plan_routes(self, n: int) -> None:
        """Register *n* additional routes (for progress display)."""
        self.routes_planned += n

    def tick(self) -> None:
        """Record one completed HTTP request."""
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
    url = f"{base_url}{path}"
    return ScanResult(
        url=url,
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
    )


# ---------------------------------------------------------------------------
# Priority queue seeding — synchronous tree traversal, no HTTP
# ---------------------------------------------------------------------------

def _seed_queue(
    tree: ScanTree,
    pq: asyncio.PriorityQueue,
    order: itertools.count,
    pending_routes: dict[str, list[tuple[int, Route]]],
    pending_children: dict[str, list[tuple[str, int]]],
    tracker: RequestTracker,
) -> None:
    """Walk the tree synchronously and enqueue initial work items.

    Only depth-1 prefix probes are enqueued immediately (their parent is
    root, which is already probed).  Deeper probes are parked in
    *pending_children* and released when their parent probe completes.
    This preserves the baseline invariant: parent baselines exist before
    child probes fire.

    Routes are parked in *pending_routes* and released when their
    prefix probe completes.  Root routes are enqueued immediately.
    """
    def _visit(node, prefix: str, parent_prefix: str) -> None:
        if prefix:
            # Park routes for this prefix
            for route in node.routes:
                pending_routes.setdefault(prefix, []).append((0, route))
            # Only enqueue probe if parent is root (already probed).
            # Deeper probes are parked until parent completes.
            if parent_prefix == "":
                pq.put_nowait((1, next(order), ("probe", prefix, 0)))
            else:
                pending_children.setdefault(parent_prefix, []).append((prefix, 0))
        else:
            # Root routes enqueued immediately
            for route in node.routes:
                pq.put_nowait((0, next(order), ("route", route)))
        # Recurse into children
        for seg in node._insertion_order:
            child_prefix = f"{prefix}/{seg}" if prefix else f"/{seg}"
            _visit(node.children[seg], child_prefix, prefix)

    _visit(tree._root, "", "")


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
    on_recurse: Callable[[str, int, int], None] | None = None,
    tracker: RequestTracker | None = None,
    recurse: bool = False,
    max_depth: int = 2,
    lookahead: bool = False,
) -> tuple[list[ScanResult], ScanTree]:
    """Scan *target_url* with the given routes. Returns (findings, tree)."""
    base_url = target_url.rstrip("/")
    limiter = RateLimiter(rate_limit) if rate_limit else None
    results: list[ScanResult] = []
    if tracker is None:
        tracker = RequestTracker()

    tree = ScanTree(routes, recurse=recurse, max_depth=max_depth, wordlist=routes,
                    on_recurse=on_recurse, lookahead=lookahead)

    # Initial planned: root init (10) + 1 per route
    tracker.plan(10 + len(tree))
    tracker.plan_routes(len(tree))

    def _inference_filtered(route, path, sig, reason):
        if on_filtered:
            on_filtered(route.method, path, sig.status_code, reason)

    engine = InferenceEngine(
        tree=tree,
        status_blacklist=status_blacklist,
        status_whitelist=status_whitelist,
        on_filtered=_inference_filtered,
        tracker=tracker,
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

        # Initialize root baselines
        await tree.initialize(send_fn)

        # -- Priority queue scheduler ------------------------------------

        pq: asyncio.PriorityQueue = asyncio.PriorityQueue()
        order = itertools.count()
        pending_routes: dict[str, list[tuple[int, Route]]] = {}
        pending_children: dict[str, list[tuple[str, int]]] = {}  # parent → [(child_prefix, depth)]
        probed_prefixes: set[str] = set()

        # Connection failure tracking.
        # Shared across concurrent workers — the race between await points
        # is benign for a threshold heuristic (worst case: one extra request).
        conn_failures = 0

        def _emit(finding: Finding, **kw) -> None:
            result = _finding_to_result(finding, base_url, **kw)
            results.append(result)
            if on_result:
                on_result(result)

        def _handle_boundary_group(group: BoundaryGroup) -> None:
            findings = []
            for probe in group.probes:
                finding = engine.classify_boundary(probe)
                if finding is not None:
                    findings.append(finding)
            if not findings:
                return
            method_statuses = []
            for f in findings:
                method_statuses.append(f"{f.route.method}={f.signature.status_code}")
            collapsed_reason = f"boundary: {', '.join(method_statuses)}"
            primary = findings[0]
            collapsed = Finding(
                route=Route(template_path=group.prefix, method="*"),
                signature=primary.signature,
                reason=collapsed_reason,
                confidence=primary.confidence,
            )
            _emit(collapsed)

        def _release_routes(prefix: str) -> None:
            """Enqueue routes that were waiting for this prefix's probe."""
            if prefix in pending_routes:
                for priority, route in pending_routes.pop(prefix):
                    pq.put_nowait((priority, next(order), ("route", route)))

        def _release_children(prefix: str) -> None:
            """Enqueue child probes that were waiting for this prefix."""
            if prefix in pending_children:
                for child_prefix, child_depth in pending_children.pop(prefix):
                    pq.put_nowait((1, next(order), ("probe", child_prefix, child_depth)))

        async def _handle_probe(prefix: str, depth: int) -> None:
            """Probe a prefix for handler boundaries, release waiting routes."""
            if prefix in probed_prefixes:
                _release_routes(prefix)
                return
            probed_prefixes.add(prefix)
            tree._prefix_depth[prefix] = depth

            group, injected = await tree.probe_prefix(prefix, send_fn, tracker, depth)
            if group:
                _handle_boundary_group(group)
                # Enqueue recursive routes at priority 2
                for route in injected:
                    pq.put_nowait((2, next(order), ("route", route)))
                # Enqueue probes for recursive sub-prefixes
                seen_sub: set[str] = set()
                for route in injected:
                    parts = route.template_path.rstrip("/").rsplit("/", 1)
                    sub_prefix = parts[0] if len(parts) > 1 and parts[0] else "/"
                    if sub_prefix != prefix and sub_prefix not in seen_sub and sub_prefix not in probed_prefixes:
                        seen_sub.add(sub_prefix)
                        pq.put_nowait((1, next(order), ("probe", sub_prefix, depth + 1)))
            elif lookahead and not tree._resolve(prefix).children:
                # No boundary at this leaf — enqueue lookahead probes
                for i, seg in enumerate(_LOOKAHEAD_SEGMENTS):
                    pq.put_nowait((3 + i, next(order), ("lookahead", prefix, seg, i)))

            _release_routes(prefix)
            _release_children(prefix)

        async def _handle_lookahead(prefix: str, segment: str, seg_index: int) -> None:
            """Lightweight GET probe for a single lookahead segment."""
            sub_prefix = f"{prefix}/{segment}"
            # Skip if already probed
            sub_node = tree._resolve(sub_prefix)
            if sub_node and "GET" in sub_node.baselines:
                return
            # Check against all ancestor baselines
            ancestor_baselines = tree._ancestor_baselines(prefix, "GET")
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
            # Hit — enqueue full probe for this sub-prefix
            pq.put_nowait((1, next(order), ("probe", sub_prefix, tree._infer_depth(sub_prefix))))

        async def _handle_route(route: Route) -> None:
            nonlocal conn_failures
            if conn_failures >= quarantine_threshold:
                if on_progress:
                    on_progress(0)
                return

            path = render_path(route)
            query = render_query(route)
            url = f"{base_url}{path}"
            if query:
                url += f"?{query}"
            if len(url) > 2000:
                url = url[:2000]

            headers = render_headers(route)
            body_str = render_body(route) if route.method != "GET" else None
            if body_str and not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = "application/json"

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

            result = await engine.process(route, sig, path, send_fn)

            if result is None:
                if on_progress:
                    on_progress(0)
                return

            # This path deviates from baseline — probe it as a potential
            # handler boundary. probe_prefix is idempotent (skips methods
            # already probed at this prefix).
            group, reactive_injected = await tree.probe_prefix(path, send_fn, tracker)
            if group:
                _handle_boundary_group(group)
                for injected_route in reactive_injected:
                    pq.put_nowait((2, next(order), ("route", injected_route)))

            redirect_location = str(resp.url) if resp.history else None

            # If redirected within scope, add the target path to the tree
            # for independent probing — the server revealed a real path.
            if resp.history:
                final_url = str(resp.url)
                if final_url.startswith(base_url):
                    redir_path = final_url[len(base_url):]
                    if redir_path and redir_path.startswith("/"):
                        redir_key = (redir_path, route.method)
                        if redir_key not in tree._seen:
                            tree.insert(Route(
                                template_path=redir_path, method=route.method,
                            ))
                            tracker.plan(1)
                            pq.put_nowait((0, next(order), ("route", Route(
                                template_path=redir_path, method=route.method,
                            ))))

            all_findings = result if isinstance(result, list) else [result]
            for finding in all_findings:
                _emit(
                    finding,
                    redirect_location=redirect_location,
                    request_headers=headers,
                    request_body=body_str,
                )

            if on_progress:
                on_progress(len(all_findings))

        # -- Worker dispatch ----------------------------------------------

        if on_phase:
            on_phase("scanning", len(tree))

        async def _worker() -> None:
            while True:
                _, _, item = await pq.get()
                try:
                    kind = item[0]
                    if kind == "probe":
                        _, prefix, depth = item
                        await _handle_probe(prefix, depth)
                    elif kind == "route":
                        _, route = item
                        await _handle_route(route)
                    elif kind == "lookahead":
                        _, prefix, segment, seg_index = item
                        await _handle_lookahead(prefix, segment, seg_index)
                finally:
                    pq.task_done()

        # Seed the priority queue from the tree structure
        _seed_queue(tree, pq, order, pending_routes, pending_children, tracker)

        workers = [asyncio.create_task(_worker()) for _ in range(concurrency)]

        try:
            await pq.join()
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    return results, tree
