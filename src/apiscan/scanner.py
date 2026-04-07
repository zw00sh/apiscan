"""Async HTTP scanning engine with dependency-aware scheduling.

Work is scheduled via a dependency-tracking DAG (see :mod:`apiscan.workqueue`).
Each work item declares its dependencies (e.g. a route depends on its
prefix probe) and the queue releases items as their deps complete.

Baseline management is handled by :mod:`apiscan.scantree`.
Response classification is handled by :mod:`apiscan.inference`.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Any, Callable

import httpx

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
from apiscan.workqueue import LookaheadWork, ProbeWork, RouteWork, WorkQueue


# Transient errors that a worker should swallow (network, timeout, server).
# Programming errors (TypeError, KeyError, AttributeError, etc.) propagate.
_TRANSIENT_ERRORS = (httpx.HTTPError, OSError, TimeoutError)


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
        self.errors = 0
        self.planned = initial_planned
        self.routes_planned = 0
        self.queue_size: Callable[[], int] | None = None
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
# Path helpers
# ---------------------------------------------------------------------------

def _split_path_segment(path: str) -> tuple[str, str]:
    """Split '/foo/bar' into ('/foo', 'bar')."""
    parts = path.rstrip("/").rsplit("/", 1)
    if len(parts) == 2:
        return (parts[0] or "/", parts[1])
    return ("/", parts[0].lstrip("/"))


# ---------------------------------------------------------------------------
# Segment-prefix wildcard tracker
# ---------------------------------------------------------------------------

class SegmentPrefixTracker:
    """Detects and suppresses segment-prefix wildcard handlers.

    A segment-prefix handler is a route like ``/static`` that also handles
    ``/static.html``, ``/staticfiles``, etc.  When detected, sibling paths
    that share the prefix and return the same response are suppressed.
    """

    def __init__(self) -> None:
        self.handlers: dict[tuple[str, str], Baseline] = {}
        self._suppressed: set[int] = set()
        self.gates: set[str] = set()

    def should_skip(self, key: str, item: Any) -> bool:
        """WorkQueue skip_fn: skip probes/routes covered by a known wildcard."""
        if isinstance(item, ProbeWork):
            path = item.prefix
        elif isinstance(item, RouteWork):
            path = item.route.template_path
        else:
            return False
        parent, segment = _split_path_segment(path)
        for (hp, hs) in self.handlers:
            if hp == parent and segment.startswith(hs) and segment != hs:
                return True
        return False

    def is_suppressed(self, path: str, sig: ResponseSignature) -> bool:
        """Check if path+sig is covered by a known prefix handler."""
        parent, segment = _split_path_segment(path)
        path_len = len(path.lstrip("/"))
        for (hp, hs), bl in self.handlers.items():
            if hp == parent and segment.startswith(hs) and segment != hs:
                if matches_baseline(sig, bl, path_len) is not None:
                    return True
        return False

    def complete_gate(self, path: str, wq: WorkQueue) -> None:
        """Complete a segment gate node if *path* is a gate."""
        if path in self.gates:
            wq.item_done(f"segment:{path}")
            self.gates.discard(path)

    async def check(
        self,
        finding: Finding,
        results: list[ScanResult],
        send_fn: Callable,
        tracker: RequestTracker,
        wq: WorkQueue,
    ) -> bool:
        """Probe *finding* to detect if it is a segment-prefix handler.

        Returns True if the finding should be suppressed, False if it
        should be emitted.  Completes the ``segment:{path}`` gate node
        to release superset siblings.
        """
        path = finding.route.template_path
        parent, segment = _split_path_segment(path)
        handler_key = (parent, segment)

        if self.is_suppressed(path, finding.signature):
            self.complete_gate(path, wq)
            return True

        # Probe {path}{random} to see if this is a prefix handler
        suffix = _random_segment()[:8]
        probe_path = f"{path}{suffix}"
        tracker.plan(1)
        try:
            probe_sig = await send_fn("GET", probe_path, None, None)
        except Exception:  # send_fn tracks errors; skip failed probes
            self.complete_gate(path, wq)
            return False

        finding_bl = build_baseline([finding.signature])
        probe_len = len(probe_path.lstrip("/"))
        if matches_baseline(probe_sig, finding_bl, probe_len) is None:
            self.complete_gate(path, wq)
            return False  # not a prefix handler

        # Register as prefix handler
        self.handlers[handler_key] = finding_bl

        # Retroactively sweep already-emitted results
        for i, existing in enumerate(results):
            if i in self._suppressed:
                continue
            if existing.signature is None:
                continue
            ep, eseg = _split_path_segment(existing.path)
            if ep == parent and eseg.startswith(segment) and eseg != segment:
                elen = len(existing.path.lstrip("/"))
                if matches_baseline(existing.signature, finding_bl, elen) is not None:
                    self._suppressed.add(i)

        self.complete_gate(path, wq)
        return False  # the handler itself is emitted

    def sweep(self, results: list[ScanResult]) -> list[ScanResult]:
        """Final pass: remove results covered by prefix handlers."""
        if not self.handlers:
            return results
        return [
            r for i, r in enumerate(results)
            if i not in self._suppressed
            and (r.signature is None or not self.is_suppressed(r.path, r.signature))
        ]


# ---------------------------------------------------------------------------
# Scan session
# ---------------------------------------------------------------------------

class ScanSession:
    """Encapsulates one scan run.

    Config and callbacks are stored as instance attributes. Mutable scan
    state (results, connection failures, prefix tracking, etc.) lives on
    the instance so that former closures become regular methods.
    """

    def __init__(
        self,
        target_url: str,
        routes: list[Route],
        *,
        concurrency: int = 10,
        rate_limit: float | None = None,
        timeout: float = 10.0,
        max_redirects: int = 3,
        status_blacklist: set[int] | None = None,
        status_whitelist: set[int] | None = None,
        error_threshold: int = 50,
        extra_headers: dict[str, str] | None = None,
        on_result: Callable[[ScanResult], None] | None = None,
        on_progress: Callable[[int], None] | None = None,
        on_filtered: Callable[[str, str, int, str], None] | None = None,
        on_debug: Callable[[str], None] | None = None,
        tracker: RequestTracker | None = None,
        recurse: bool = False,
        recurse_all: bool = False,
        max_depth: int = 2,
        lookahead: bool = False,
        methods: list[str] | None = None,
        skip_wildcard_siblings: bool = True,
    ) -> None:
        from apiscan.inference import DEFAULT_METHODS

        self._base_url = target_url.rstrip("/")
        self._wordlist = routes
        self._concurrency = concurrency
        self._timeout = timeout
        self._max_redirects = max_redirects
        self._error_threshold = error_threshold
        self._extra_headers = extra_headers or {}
        self._on_result = on_result
        self._on_progress = on_progress
        self._on_filtered = on_filtered
        self._on_debug = on_debug
        self._recurse = recurse
        self._recurse_all = recurse_all
        self._max_depth = max_depth
        self._lookahead = lookahead
        self._methods = methods or DEFAULT_METHODS
        self._skip_wildcard_siblings = skip_wildcard_siblings
        self._status_blacklist = status_blacklist
        self._status_whitelist = status_whitelist

        self._limiter = RateLimiter(rate_limit) if rate_limit else None
        self._tracker = tracker or RequestTracker()

        # Mutable state — populated during run()
        self._results: list[ScanResult] = []
        self._tree: ScanTree | None = None
        self._engine: InferenceEngine | None = None
        self._wq: WorkQueue | None = None
        self._client: httpx.AsyncClient | None = None
        self._consecutive_errors = 0
        self._total_errors = 0
        self._aborted = False
        self._probed_prefixes: set[str] = set()
        self._prefix_depth: dict[str, int] = {}
        self._prefixes = SegmentPrefixTracker()
        self._recurse_suffixes: list[Route] | None = None

    # -- Public entry point --------------------------------------------------

    async def run(self) -> tuple[list[ScanResult], ScanTree]:
        """Execute the scan. Returns ``(findings, tree)``."""
        self._tree = ScanTree(self._wordlist)

        if self._recurse and not self._recurse_all:
            self._recurse_suffixes = self._compute_recurse_suffixes()

        self._tracker.plan(len(self._methods) * 2 + len(self._tree))
        self._tracker.plan_routes(len(self._tree))

        self._engine = InferenceEngine(
            tree=self._tree,
            status_blacklist=self._status_blacklist,
            status_whitelist=self._status_whitelist,
            on_filtered=lambda route, path, sig, reason: (
                self._on_filtered(route.method, path, sig.status_code, reason)
                if self._on_filtered else None
            ),
            on_debug=self._on_debug,
            tracker=self._tracker,
            methods=self._methods,
        )

        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=self._max_redirects,
            verify=False,
            headers=self._extra_headers,
        ) as self._client:
            await self._tree.initialize(self._send, methods=self._methods)
            if self._aborted:
                return self._results, self._tree

            self._wq = WorkQueue()
            self._tracker.queue_size = lambda: self._wq._inflight
            self._tracker.skipped_fn = lambda: self._wq.skipped
            self._tracker.blocked_fn = lambda: self._wq.blocked_count
            self._prefixes.gates = _build_work_graph(self._tree, self._wq)

            if self._skip_wildcard_siblings:
                self._wq.skip_fn = self._prefixes.should_skip

            self._wq.prepare()

            workers = [asyncio.create_task(self._worker()) for _ in range(self._concurrency)]
            try:
                await self._wq.wait()
            except (asyncio.CancelledError, KeyboardInterrupt):
                pass
            finally:
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

        self._client = None
        self._results = self._prefixes.sweep(self._results)
        return self._results, self._tree

    # -- HTTP transport ------------------------------------------------------

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> httpx.Response:
        """Raw HTTP request with error tracking and backoff."""
        if self._limiter:
            await self._limiter.acquire()
        errors_before = self._consecutive_errors
        if errors_before > 1:
            delay = min(errors_before * 0.25, 5.0)
            await asyncio.sleep(delay)
        try:
            resp = await self._client.request(
                method, url,
                headers=headers or {},
                content=body.encode() if body else None,
                timeout=self._timeout,
            )
        except _TRANSIENT_ERRORS:
            self._total_errors += 1
            self._tracker.errors += 1
            self._consecutive_errors += 1
            self._warn_on_errors()
            if self._consecutive_errors >= self._error_threshold:
                self._aborted = True
                if self._wq:
                    self._wq.drain()
            raise
        if errors_before >= 5:
            print(f"\033[2K\r  connection restored after {errors_before} errors",
                  file=sys.stderr)
        self._consecutive_errors = 0
        self._tracker.tick()
        return resp

    async def _send(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> ResponseSignature:
        """Send request and return ResponseSignature."""
        url = f"{self._base_url}{path}"
        resp = await self._request(method, url, headers, body)
        return compute_signature(
            resp.status_code, dict(resp.headers), resp.content, path,
        )

    def _warn_on_errors(self) -> None:
        """Print escalating warnings to stderr."""
        n = self._consecutive_errors
        msg = None
        if n == 5:
            msg = f"  warning: {n} consecutive connection errors"
        elif n == 20:
            msg = f"  warning: {n} consecutive errors, backing off"
        elif n == self._error_threshold:
            msg = f"  error: {n} consecutive errors, aborting scan"
        if msg:
            # Erase progress bar line, print warning, let progress redraw
            print(f"\033[2K\r{msg}", file=sys.stderr)

    # -- Result emission -----------------------------------------------------

    def _emit(self, finding: Finding, recurse_info: str | None = None, **kw) -> None:
        result = _finding_to_result(finding, self._base_url, **kw)
        if recurse_info:
            result.recurse_info = recurse_info
        self._results.append(result)
        if self._on_result:
            self._on_result(result)

    async def _emit_boundary(self, group: BoundaryGroup, recurse_info: str | None = None) -> None:
        findings = []
        for probe in group.probes:
            finding = self._engine.classify_boundary(probe)
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
        if await self._prefixes.check(
            boundary_finding, self._results, self._send, self._tracker, self._wq,
        ):
            return
        self._emit(boundary_finding, recurse_info=recurse_info)

    # -- Recursion -----------------------------------------------------------

    def _compute_recurse_suffixes(self) -> list[Route]:
        """Extract unique endpoint suffixes by stripping structural prefixes.

        Structural prefixes are internal tree nodes (path prefixes shared by
        multiple wordlist entries, like ``/api`` or ``/api/v1``).  Stripping
        them collapses ``/api/v1/users`` and ``/api/v2/users`` to ``/users``.
        """
        structural: set[str] = set()

        def _walk(node, prefix: str) -> None:
            if node.children:
                if prefix:
                    structural.add(prefix)
                for seg, child in node.children.items():
                    _walk(child, f"{prefix}/{seg}")

        _walk(self._tree._root, "")

        seen: set[tuple[str, str]] = set()
        suffixes: list[Route] = []
        for route in self._wordlist:
            path = route.template_path
            parts = path.strip("/").split("/")
            best = ""
            current = ""
            for part in parts[:-1]:
                current = f"{current}/{part}"
                if current in structural:
                    best = current
            suffix = path[len(best):] if best else path
            key = (suffix, route.method)
            if key not in seen:
                seen.add(key)
                suffixes.append(Route(template_path=suffix, method=route.method))
        return suffixes

    def _inject_recursive(self, prefix: str, depth: int) -> str | None:
        """Inject recursive routes and return info string, or None."""
        if not self._recurse or depth >= self._max_depth:
            return None
        wordlist = self._recurse_suffixes if self._recurse_suffixes is not None else self._wordlist
        items: list[tuple[str, Any, list[str]]] = []
        seen_sub: set[str] = set()
        stripped = 0
        injected = 0
        deduped = 0
        for route in wordlist:
            route_path = route.template_path
            if prefix != "/" and route_path.startswith(prefix):
                route_path = route_path[len(prefix):]
                stripped += 1
            new_path = f"{prefix}{route_path}"
            route_key_pair = (new_path, route.method)
            if route_key_pair not in self._tree._seen:
                injected += 1
                new_route = Route(template_path=new_path, method=route.method)
                self._tree.insert(new_route)
                self._tracker.plan(1)
                self._tracker.plan_routes(1)
                parts = new_path.rstrip("/").rsplit("/", 1)
                sub_prefix = parts[0] if len(parts) > 1 and parts[0] else "/"
                route_key = f"recurse-route:{new_path}:{route.method}"
                if sub_prefix != prefix and sub_prefix not in seen_sub and sub_prefix not in self._probed_prefixes:
                    seen_sub.add(sub_prefix)
                    probe_key = f"recurse-probe:{sub_prefix}"
                    items.append((probe_key, ProbeWork(prefix=sub_prefix, depth=depth + 1), []))
                    items.append((route_key, RouteWork(route=new_route), [probe_key]))
                else:
                    items.append((route_key, RouteWork(route=new_route), []))
            else:
                deduped += 1
        if self._on_debug and (stripped or injected or deduped):
            self._on_debug(f"recurse {prefix}: {stripped} stripped, {injected} injected, {deduped} deduped")
        if items:
            self._wq.enqueue_recursive_batch(items)
            return f"recurse (depth {depth + 1}, {injected} new)"
        return None

    # -- Work handlers -------------------------------------------------------

    async def _handle_probe(self, work: ProbeWork, key: str) -> None:
        if work.prefix in self._probed_prefixes:
            return
        self._probed_prefixes.add(work.prefix)
        self._prefix_depth[work.prefix] = work.depth

        group = await self._tree.probe_prefix(work.prefix, self._send, self._tracker, methods=self._methods)
        if group:
            recurse_info = self._inject_recursive(work.prefix, work.depth)
            await self._emit_boundary(group, recurse_info=recurse_info)
        else:
            self._prefixes.complete_gate(work.prefix, self._wq)

        if not group and self._lookahead and not self._tree._resolve(work.prefix).children:
            for i, seg in enumerate(_LOOKAHEAD_SEGMENTS):
                la_key = f"lookahead:{work.prefix}/{seg}"
                self._wq.enqueue_dynamic(la_key, LookaheadWork(prefix=work.prefix, segment=seg))

    async def _handle_lookahead(self, work: LookaheadWork) -> None:
        sub_prefix = f"{work.prefix}/{work.segment}"
        sub_node = self._tree._resolve(sub_prefix)
        if sub_node and "GET" in sub_node.baselines:
            return
        ancestor_baselines = self._tree.ancestor_baselines(work.prefix, "GET")
        if not ancestor_baselines:
            return
        self._tracker.plan(1)
        probe_path = f"{sub_prefix}/{_random_segment()}"
        try:
            sig = await self._send("GET", probe_path, None, None)
        except Exception:  # _send tracks errors; skip failed probes
            return
        path_len = len(probe_path.lstrip("/"))
        for bl in ancestor_baselines:
            if matches_baseline(sig, bl, path_len) is not None:
                return
        depth = 0
        parts = sub_prefix.rstrip("/").split("/")
        for i in range(len(parts) - 1, 0, -1):
            ancestor = "/".join(parts[:i]) or "/"
            if ancestor in self._prefix_depth:
                depth = self._prefix_depth[ancestor] + 1
                break
        la_probe_key = f"recurse-probe:{sub_prefix}"
        self._wq.enqueue_dynamic(la_probe_key, ProbeWork(prefix=sub_prefix, depth=depth))

    async def _handle_route(self, work: RouteWork, key: str) -> None:
        route = work.route
        path = route.template_path
        url = f"{self._base_url}{path}"
        if len(url) > 2000:
            url = url[:2000]

        headers: dict[str, str] = {}
        body_str: str | None = None

        try:
            resp = await self._request(route.method, url, headers, body_str)
        except _TRANSIENT_ERRORS:
            if self._on_progress:
                self._on_progress(0)
            return

        # Use the initial status code for redirected responses so the
        # output shows 301/302 instead of the final 200.
        initial_status = resp.history[0].status_code if resp.history else resp.status_code
        sig = compute_signature(
            initial_status, dict(resp.headers), resp.content, path,
        )

        findings = await self._engine.process(route, sig, path, self._send)

        if not findings:
            self._prefixes.complete_gate(path, self._wq)
            if self._on_progress:
                self._on_progress(0)
            return

        group = await self._tree.probe_prefix(path, self._send, self._tracker, methods=self._methods)
        if group:
            recurse_info = self._inject_recursive(path, self._prefix_depth.get(path, 0))
            await self._emit_boundary(group, recurse_info=recurse_info)

        redirect_location = str(resp.url) if resp.history else None
        if resp.history:
            final_url = str(resp.url)
            if final_url.startswith(self._base_url):
                redir_path = final_url[len(self._base_url):]
                if redir_path and redir_path.startswith("/"):
                    if (redir_path, route.method) not in self._tree._seen:
                        self._tree.insert(Route(template_path=redir_path, method=route.method))
                        self._tracker.plan(1)
                        redir_key = f"redir-route:{redir_path}:{route.method}"
                        self._wq.enqueue_dynamic(redir_key, RouteWork(
                            route=Route(template_path=redir_path, method=route.method)))

        emitted = 0
        for finding in findings:
            if await self._prefixes.check(
                finding, self._results, self._send, self._tracker, self._wq,
            ):
                continue
            self._emit(finding, redirect_location=redirect_location,
                       request_headers=headers, request_body=body_str)
            emitted += 1

        if self._on_progress:
            self._on_progress(emitted)

    # -- Worker dispatch -----------------------------------------------------

    async def _worker(self) -> None:
        while True:
            try:
                key, item = await self._wq.get()
            except asyncio.CancelledError:
                return
            if self._aborted:
                return
            try:
                if isinstance(item, ProbeWork):
                    await self._handle_probe(item, key)
                elif isinstance(item, RouteWork):
                    await self._handle_route(item, key)
                elif isinstance(item, LookaheadWork):
                    await self._handle_lookahead(item)
            except asyncio.CancelledError:
                self._wq.item_done(key)
                raise
            except _TRANSIENT_ERRORS:
                pass
            except Exception:
                raise
            self._wq.item_done(key)


# ---------------------------------------------------------------------------
# Public scan function (thin wrapper)
# ---------------------------------------------------------------------------

async def scan(
    target_url: str,
    routes: list[Route],
    *,
    concurrency: int = 10,
    rate_limit: float | None = None,
    timeout: float = 10.0,
    max_redirects: int = 3,
    status_blacklist: set[int] | None = None,
    status_whitelist: set[int] | None = None,
    error_threshold: int = 50,
    extra_headers: dict[str, str] | None = None,
    on_result: Callable[[ScanResult], None] | None = None,
    on_progress: Callable[[int], None] | None = None,
    on_filtered: Callable[[str, str, int, str], None] | None = None,
    on_debug: Callable[[str], None] | None = None,
    tracker: RequestTracker | None = None,
    recurse: bool = False,
    recurse_all: bool = False,
    max_depth: int = 2,
    lookahead: bool = False,
    methods: list[str] | None = None,
    skip_wildcard_siblings: bool = True,
) -> tuple[list[ScanResult], ScanTree]:
    """Scan *target_url* with the given routes. Returns (findings, tree)."""
    session = ScanSession(
        target_url,
        routes,
        concurrency=concurrency,
        rate_limit=rate_limit,
        timeout=timeout,
        max_redirects=max_redirects,
        status_blacklist=status_blacklist,
        status_whitelist=status_whitelist,
        error_threshold=error_threshold,
        extra_headers=extra_headers,
        on_result=on_result,
        on_progress=on_progress,
        on_filtered=on_filtered,
        on_debug=on_debug,
        tracker=tracker,
        recurse=recurse,
        recurse_all=recurse_all,
        max_depth=max_depth,
        lookahead=lookahead,
        methods=methods,
        skip_wildcard_siblings=skip_wildcard_siblings,
    )
    return await session.run()


# ---------------------------------------------------------------------------
# Work graph construction
# ---------------------------------------------------------------------------

def _build_work_graph(tree: ScanTree, wq: WorkQueue) -> set[str]:
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
                wq.add(key, RouteWork(route=route))
        else:
            probe_key = f"probe:{prefix}"

            if parent_prefix == "":
                # First-level prefix: no parent probe dependency
                wq.add(probe_key, ProbeWork(prefix=prefix, depth=0))
            else:
                parent_probe = f"probe:{parent_prefix}"
                wq.add(probe_key, ProbeWork(prefix=prefix, depth=0), parent_probe)

            for route in sorted(node.routes, key=lambda r: r.template_path):
                route_key = f"route:{route.template_path}:{route.method}"
                wq.add(route_key, RouteWork(route=route), probe_key)

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
                    wq.add(probe_key, ProbeWork(prefix=child_prefix, depth=0), segment_key)
                else:
                    parent_probe = f"probe:{parent_prefix}"
                    wq.add(probe_key, ProbeWork(prefix=child_prefix, depth=0), segment_key, parent_probe)
                for route in sorted(child_node.routes, key=lambda r: r.template_path):
                    route_key = f"route:{route.template_path}:{route.method}"
                    wq.add(route_key, RouteWork(route=route), probe_key)
                # Recurse into deferred node's children
                for subseg in sorted(child_node.children):
                    sub_prefix = f"{child_prefix}/{subseg}"
                    _visit(child_node.children[subseg], sub_prefix, child_prefix)
            else:
                _visit(child_node, child_prefix, prefix)

    _visit(tree._root, "", "")
    return segment_gates
