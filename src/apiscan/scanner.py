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
    Finding,
    InferenceEngine,
    ResponseSignature,
    _random_segment,
    compute_signature,
    matches_baseline,
)
from apiscan.kite import Route, render_body, render_headers, render_path, render_query
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

    def __init__(self) -> None:
        self._pq: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._order = itertools.count()
        self._inflight = 0
        self._done = asyncio.Event()
        self._done.set()  # no work yet → "done"

    def enqueue(self, priority: int, item: Any) -> None:
        self._inflight += 1
        self._done.clear()
        self._pq.put_nowait((priority, next(self._order), item))

    async def get(self) -> Any:
        """Pull the next item. Raises ``CancelledError`` on shutdown."""
        _, _, item = await self._pq.get()
        return item

    def item_done(self) -> None:
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

    tree = ScanTree(routes)

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

        await tree.initialize(send_fn)

        # -- Scheduler state ---------------------------------------------

        wq = _WorkQueue()
        pending_routes: dict[str, list[tuple[int, _RouteWork]]] = {}
        pending_children: dict[str, list[_ProbeWork]] = {}
        probed_prefixes: set[str] = set()
        prefix_depth: dict[str, int] = {}
        skip_prefixes: set[str] = set()
        conn_failures = 0
        wordlist = routes

        # -- Helpers ------------------------------------------------------

        def _emit(finding: Finding, **kw) -> None:
            result = _finding_to_result(finding, base_url, **kw)
            results.append(result)
            if on_result:
                on_result(result)

        def _emit_boundary(group: BoundaryGroup) -> None:
            findings = []
            for probe in group.probes:
                finding = engine.classify_boundary(probe)
                if finding is not None:
                    findings.append(finding)
            if not findings:
                return
            method_statuses = [f"{f.route.method}={f.signature.status_code}" for f in findings]
            primary = findings[0]
            _emit(Finding(
                route=Route(template_path=group.prefix, method="*"),
                signature=primary.signature,
                reason=f"boundary: {', '.join(method_statuses)}",
                confidence=primary.confidence,
            ))

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
                    new_route = Route(
                        template_path=new_path, method=route.method,
                        path_crumbs=route.path_crumbs,
                        header_crumbs=route.header_crumbs,
                        query_crumbs=route.query_crumbs,
                        body_crumbs=route.body_crumbs,
                        content_types=route.content_types,
                        source_api_url=route.source_api_url,
                    )
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

            group = await tree.probe_prefix(work.prefix, send_fn, tracker)
            if group:
                _emit_boundary(group)
                _inject_recursive(work.prefix, work.depth)
            elif lookahead and not tree._resolve(work.prefix).children:
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

            group = await tree.probe_prefix(path, send_fn, tracker)
            if group:
                _emit_boundary(group)
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

            all_findings = result if isinstance(result, list) else [result]
            for finding in all_findings:
                _emit(finding, redirect_location=redirect_location,
                      request_headers=headers, request_body=body_str)

            if on_progress:
                on_progress(len(all_findings))

        # -- Worker dispatch ----------------------------------------------

        if on_phase:
            on_phase("scanning", len(tree))

        async def _worker() -> None:
            while True:
                try:
                    item = await wq.get()
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
                    wq.item_done()
                    raise
                except _TRANSIENT_ERRORS:
                    logger.debug("Transient error processing %s", type(item).__name__, exc_info=True)
                except Exception:
                    logger.exception("Bug in worker processing %s", type(item).__name__)
                    raise
                wq.item_done()

        # Seed the priority queue
        _seed_queue(tree, wq, pending_routes, pending_children)

        workers = [asyncio.create_task(_worker()) for _ in range(concurrency)]

        try:
            await wq.wait()
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    return results, tree


# ---------------------------------------------------------------------------
# Queue seeding
# ---------------------------------------------------------------------------

def _seed_queue(
    tree: ScanTree,
    wq: _WorkQueue,
    pending_routes: dict[str, list[tuple[int, _RouteWork]]],
    pending_children: dict[str, list[_ProbeWork]],
) -> None:
    """Traverse the tree and enqueue initial work items."""

    def _visit(node, prefix: str, parent_prefix: str) -> None:
        if prefix:
            for route in node.routes:
                pending_routes.setdefault(prefix, []).append(
                    (0, _RouteWork(route=route)))
            if parent_prefix == "":
                wq.enqueue(1, _ProbeWork(prefix=prefix, depth=0))
            else:
                pending_children.setdefault(parent_prefix, []).append(
                    _ProbeWork(prefix=prefix, depth=0))
        else:
            for route in node.routes:
                wq.enqueue(0, _RouteWork(route=route))
        for seg in node._insertion_order:
            child_prefix = f"{prefix}/{seg}" if prefix else f"/{seg}"
            _visit(node.children[seg], child_prefix, prefix)

    _visit(tree._root, "", "")
