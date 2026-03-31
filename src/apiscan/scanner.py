"""Async HTTP scanning engine.

Thin transport layer — sends requests, manages concurrency and rate limiting.
Route ordering and baseline management are handled by :mod:`apiscan.scantree`.
Response classification is handled by :mod:`apiscan.inference`.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable

import httpx

from apiscan.inference import (
    Finding,
    InferenceEngine,
    ResponseSignature,
    compute_signature,
)
from apiscan.kite import Route, render_body, render_headers, render_path, render_query
from apiscan.output import ScanResult
from apiscan.scantree import BoundaryProbe, ScanTree


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
        self._on_tick = on_tick

    def plan(self, n: int) -> None:
        """Register *n* additional requests that will be sent."""
        self.planned += n

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
    tracker: RequestTracker | None = None,
) -> tuple[list[ScanResult], ScanTree]:
    """Scan *target_url* with the given routes. Returns (findings, tree)."""
    base_url = target_url.rstrip("/")
    limiter = RateLimiter(rate_limit) if rate_limit else None
    results: list[ScanResult] = []
    if tracker is None:
        tracker = RequestTracker()

    tree = ScanTree(routes)

    # Initial planned: root init (10) + 1 per route
    tracker.plan(10 + len(tree))

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

        # Connection failure tracking
        conn_failures = 0

        def _emit(finding: Finding, **kw) -> None:
            result = _finding_to_result(finding, base_url, **kw)
            results.append(result)
            if on_result:
                on_result(result)

        def _handle_boundary(probe: BoundaryProbe) -> None:
            finding = engine.classify_boundary(probe)
            if finding is not None:
                _emit(finding)

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

            redirect_location = str(resp.url) if resp.history else None
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

        # -- Tree-driven orchestration ------------------------------------

        if on_phase:
            on_phase("scanning", len(tree))

        async def _worker(queue: asyncio.Queue) -> None:
            while True:
                item = await queue.get()
                try:
                    if isinstance(item, BoundaryProbe):
                        _handle_boundary(item)
                    else:
                        await _handle_route(item)
                finally:
                    queue.task_done()

        queue: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 2)
        workers = [asyncio.create_task(_worker(queue)) for _ in range(concurrency)]

        try:
            async for item in tree.walk(send_fn, tracker):
                await queue.put(item)
            await queue.join()
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    return results, tree
