"""Async HTTP scanning engine.

Thin transport layer — sends requests, manages concurrency and rate limiting.
All response classification is delegated to :mod:`apiscan.inference`.
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


# ---------------------------------------------------------------------------
# Complexity phasing (unchanged from previous implementation)
# ---------------------------------------------------------------------------

def route_complexity(route: Route) -> int:
    """Total crumb count across all parameter locations."""
    return (len(route.path_crumbs) + len(route.query_crumbs)
            + len(route.body_crumbs) + len(route.header_crumbs))


def group_by_complexity(routes: list[Route]) -> list[tuple[str, list[Route]]]:
    """Split routes into per-complexity phases, sorted alphabetically within each."""
    buckets: dict[int, list[Route]] = {}
    for r in routes:
        c = route_complexity(r)
        buckets.setdefault(c, []).append(r)
    phases: list[tuple[str, list[Route]]] = []
    for complexity in sorted(buckets):
        phase_routes = sorted(buckets[complexity], key=lambda r: r.template_path)
        label = f"{complexity} mutations"
        phases.append((label, phase_routes))
    return phases


# ---------------------------------------------------------------------------
# Rate limiter (unchanged)
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
) -> list[ScanResult]:
    """Scan *target_url* with the given routes. Returns list of findings."""
    base_url = target_url.rstrip("/")
    limiter = RateLimiter(rate_limit) if rate_limit else None
    results: list[ScanResult] = []

    def _inference_filtered(route, path, sig, reason):
        if on_filtered:
            on_filtered(route.method, path, sig.status_code, reason)

    engine = InferenceEngine(
        status_blacklist=status_blacklist,
        status_whitelist=status_whitelist,
        on_filtered=_inference_filtered,
    )

    async with httpx.AsyncClient(
        follow_redirects=True,
        max_redirects=max_redirects,
        verify=False,
        headers=extra_headers or {},
    ) as client:

        # -- send_fn: the bridge between inference and HTTP ------------------

        async def send_fn(
            method: str,
            path: str,
            headers: dict[str, str] | None = None,
            body: str | None = None,
        ) -> ResponseSignature:
            """Send a request and return a ``ResponseSignature``."""
            url = f"{base_url}{path}"
            if limiter:
                await limiter.acquire()
            resp = await client.request(
                method, url,
                headers=headers or {},
                content=body.encode() if body else None,
                timeout=timeout,
            )
            return compute_signature(
                resp.status_code,
                dict(resp.headers),
                resp.content,
                path,
            )

        # -- Initialize inference engine with root baseline ------------------

        await engine.initialize(send_fn)

        # -- Connection failure tracking -------------------------------------

        conn_failures = 0

        # -- Per-route scan --------------------------------------------------

        async def _scan_route(route: Route) -> None:
            nonlocal conn_failures
            if conn_failures >= quarantine_threshold:
                if on_progress:
                    on_progress(0)
                return

            # Render request from route crumbs
            path = render_path(route)
            query = render_query(route)
            url = f"{base_url}{path}"
            if query:
                url += f"?{query}"
            # Cap URL length to avoid 414 errors
            if len(url) > 2000:
                url = url[:2000]

            headers = render_headers(route)
            body_str = render_body(route) if route.method != "GET" else None
            if body_str and not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = "application/json"

            # Send initial probe
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

            sig = compute_signature(
                resp.status_code,
                dict(resp.headers),
                resp.content,
                path,
            )

            # Delegate classification to inference engine
            finding = await engine.process(route, sig, path, send_fn)

            if finding is None:
                if on_progress:
                    on_progress(0)
                return

            # Build ScanResult from Finding
            redirect_location = None
            if resp.history:
                redirect_location = str(resp.url)

            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            result = ScanResult(
                url=url,
                method=route.method,
                path=path,
                status_code=sig.status_code,
                content_length=sig.content_length,
                word_count=sig.word_count,
                line_count=sig.line_count,
                redirect_location=redirect_location,
                reason=finding.reason,
                confidence=finding.confidence,
                timestamp=ts,
                request_headers=headers,
                request_body=body_str,
            )
            results.append(result)
            if on_result:
                on_result(result)
            if on_progress:
                on_progress(1)

        # -- Phase-based orchestration ---------------------------------------
        # Routes are fed through a bounded worker pool so each route completes
        # fully (including verification probes) before a new one starts.
        # This prevents semaphore starvation where thousands of initial probes
        # block verification probes from completing.

        async def _worker(queue: asyncio.Queue) -> None:
            while True:
                route = await queue.get()
                try:
                    await _scan_route(route)
                finally:
                    queue.task_done()

        phases = group_by_complexity(routes)
        for phase_label, phase_routes in phases:
            if on_phase:
                on_phase(phase_label, len(phase_routes))

            queue: asyncio.Queue[Route] = asyncio.Queue(maxsize=concurrency * 2)
            workers = [asyncio.create_task(_worker(queue)) for _ in range(concurrency)]

            try:
                for route in phase_routes:
                    await queue.put(route)
                await queue.join()
            except (asyncio.CancelledError, KeyboardInterrupt):
                pass
            finally:
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

    return results
