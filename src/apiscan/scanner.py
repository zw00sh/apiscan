"""Async HTTP scanning engine with dependency-aware scheduling.

Work is scheduled via a dependency-tracking DAG (see :mod:`apiscan.workqueue`).
Each work item declares its dependencies (e.g. a route depends on its
prefix probe) and the queue releases items as their deps complete.

Baseline management is handled by :mod:`apiscan.scantree`.
Response classification is handled by :mod:`apiscan.inference`.
"""

from __future__ import annotations

import asyncio
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
# Main scan engine
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
    quarantine_threshold: int = 50,
    extra_headers: dict[str, str] | None = None,
    on_result: Callable[[ScanResult], None] | None = None,
    on_progress: Callable[[int], None] | None = None,
    on_filtered: Callable[[str, str, int, str], None] | None = None,
    on_debug: Callable[[str], None] | None = None,
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

        wq = WorkQueue()
        tracker.queue_size = lambda: wq._inflight
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
                if isinstance(item, ProbeWork):
                    path = item.prefix
                elif isinstance(item, RouteWork):
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

        def _emit(finding: Finding, recurse_info: str | None = None, **kw) -> None:
            result = _finding_to_result(finding, base_url, **kw)
            if recurse_info:
                result.recurse_info = recurse_info
            results.append(result)
            if on_result:
                on_result(result)

        async def _emit_boundary(group: BoundaryGroup, recurse_info: str | None = None) -> None:
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
            _emit(boundary_finding, recurse_info=recurse_info)

        def _inject_recursive(prefix: str, depth: int) -> str | None:
            """Inject recursive routes and return info string, or None."""
            if not recurse or depth >= max_depth:
                return None
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
                if route_key_pair not in tree._seen:
                    injected += 1
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
                        items.append((probe_key, ProbeWork(prefix=sub_prefix, depth=depth + 1), []))
                        items.append((route_key, RouteWork(route=new_route), [probe_key]))
                    else:
                        items.append((route_key, RouteWork(route=new_route), []))
                else:
                    deduped += 1
            if on_debug and (stripped or injected or deduped):
                on_debug(f"recurse {prefix}: {stripped} stripped, {injected} injected, {deduped} deduped")
            if items:
                wq.enqueue_recursive_batch(items)
                return f"recurse (depth {depth + 1}, {injected} new)"
            return None

        # -- Work handlers ------------------------------------------------

        async def _handle_probe(work: ProbeWork, key: str) -> None:
            if work.prefix in probed_prefixes:
                return
            probed_prefixes.add(work.prefix)
            prefix_depth[work.prefix] = work.depth

            group = await tree.probe_prefix(work.prefix, send_fn, tracker, methods=methods)
            if group:
                recurse_info = _inject_recursive(work.prefix, work.depth)
                await _emit_boundary(group, recurse_info=recurse_info)
            else:
                # No boundary — complete segment gate if this is one
                if work.prefix in segment_gates:
                    wq.item_done(f"segment:{work.prefix}")
                    segment_gates.discard(work.prefix)

            if not group and lookahead and not tree._resolve(work.prefix).children:
                for i, seg in enumerate(_LOOKAHEAD_SEGMENTS):
                    la_key = f"lookahead:{work.prefix}/{seg}"
                    wq.enqueue_dynamic(la_key, LookaheadWork(prefix=work.prefix, segment=seg))

        async def _handle_lookahead(work: LookaheadWork) -> None:
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
            wq.enqueue_dynamic(la_probe_key, ProbeWork(prefix=sub_prefix, depth=depth))

        async def _handle_route(work: RouteWork, key: str) -> None:
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

            # Use the initial status code for redirected responses so the
            # output shows 301/302 instead of the final 200.
            initial_status = resp.history[0].status_code if resp.history else resp.status_code
            sig = compute_signature(
                initial_status, dict(resp.headers), resp.content, path,
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
                recurse_info = _inject_recursive(path, prefix_depth.get(path, 0))
                await _emit_boundary(group, recurse_info=recurse_info)

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
                            wq.enqueue_dynamic(redir_key, RouteWork(
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

        wq.prepare()

        async def _worker() -> None:
            while True:
                try:
                    key, item = await wq.get()
                except asyncio.CancelledError:
                    return
                try:
                    if isinstance(item, ProbeWork):
                        await _handle_probe(item, key)
                    elif isinstance(item, RouteWork):
                        await _handle_route(item, key)
                    elif isinstance(item, LookaheadWork):
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
