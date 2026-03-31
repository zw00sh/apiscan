"""Async HTTP scanning engine with baseline detection and response validation."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Callable
from uuid import uuid4

import httpx

from apiscan.kite import Route, render_body, render_headers, render_path, render_query


# ---------------------------------------------------------------------------
# Baseline / wildcard detection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WildcardResponse:
    status_code: int
    content_length: int
    adjusted_content_length: int
    adjustment_scale: int
    word_count: int
    line_count: int


def compute_baseline(body: bytes, path: str) -> WildcardResponse:
    """Compute wildcard response characteristics from a preflight probe."""
    # Strip leading slash for replacement calculation
    basepath = path.lstrip("/")
    status_code = -1  # filled by caller
    content_length = len(body)
    word_count = body.count(b" ")
    line_count = body.count(b"\n")
    if content_length > 0:
        word_count += 1
        line_count += 1

    adjusted_body = body.replace(basepath.encode(), b"")
    adjusted_content_length = len(adjusted_body)
    diff = content_length - adjusted_content_length
    scale = 0
    if diff > 0 and len(basepath) > 0:
        scale = diff // len(basepath)

    return WildcardResponse(
        status_code=status_code,
        content_length=content_length,
        adjusted_content_length=adjusted_content_length,
        adjustment_scale=scale,
        word_count=word_count,
        line_count=line_count,
    )


def _make_baseline(status: int, body: bytes, path: str) -> WildcardResponse:
    bl = compute_baseline(body, path)
    # Replace the placeholder status_code
    return WildcardResponse(
        status_code=status,
        content_length=bl.content_length,
        adjusted_content_length=bl.adjusted_content_length,
        adjustment_scale=bl.adjustment_scale,
        word_count=bl.word_count,
        line_count=bl.line_count,
    )


def _preflight_probes(prefix: str) -> list[tuple[str, str]]:
    """Generate preflight probe (method, path) pairs for a given prefix."""
    rand = lambda: uuid4().hex[:16]
    base = prefix.rstrip("/")
    return [
        ("GET", f"{base}/{rand()}/{rand()}"),
        ("GET", f"{base}/"),
        ("GET", f"{base}/{rand()}"),
        ("POST", f"{base}/"),
        ("PUT", f"{base}/{rand()}"),
        ("DELETE", f"{base}/{rand()}"),
    ]


async def run_preflight(
    client: httpx.AsyncClient, base_url: str, prefix: str,
    timeout: float, semaphore: asyncio.Semaphore,
    rate_limiter: RateLimiter | None = None,
) -> list[WildcardResponse]:
    """Send preflight probes and collect unique baselines."""
    baselines: list[WildcardResponse] = []
    seen: set[WildcardResponse] = set()
    probes = _preflight_probes(prefix)

    async def _probe(method: str, path: str) -> None:
        async with semaphore:
            if rate_limiter:
                await rate_limiter.acquire()
            try:
                resp = await client.request(method, f"{base_url}{path}", timeout=timeout)
                bl = _make_baseline(resp.status_code, resp.content, path)
                if bl not in seen:
                    seen.add(bl)
                    baselines.append(bl)
            except Exception:
                pass

    await asyncio.gather(*[_probe(m, p) for m, p in probes])
    return baselines


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def matches_wildcard(
    status: int, content_length: int, words: int, lines: int,
    path_len: int, baselines: list[WildcardResponse],
) -> bool:
    """Return True if response matches a baseline (should be filtered)."""
    for bl in baselines:
        if status != bl.status_code and abs(status - bl.status_code) >= 50:
            continue
        # Status is in range -- check body metrics
        if content_length == bl.content_length:
            return True
        expected = bl.adjusted_content_length + (bl.adjustment_scale * path_len)
        if content_length == expected:
            return True
        if words == bl.word_count and lines == bl.line_count:
            return True
    return False


def is_known_bad_site(
    status: int, content_length: int, words: int, lines: int,
    headers: dict[str, str],
) -> bool:
    """Filter known false-positive patterns from Google Cloud and AWS API Gateway."""
    # Google bad request (method/body mismatch)
    if status == 400 and content_length == 1555 and words == 82 and lines == 12:
        return True
    # AWS API Gateway patterns
    if status == 403:
        is_aws = "x-amzn-requestid" in {k.lower() for k in headers}
        if is_aws or (lines == 1 and words == 6 and content_length == 54):
            if lines == 1 and words in (6, 13, 28):
                return True
    return False


def should_filter_status(
    status: int,
    blacklist: set[int] | None,
    whitelist: set[int] | None,
) -> bool:
    if whitelist and status not in whitelist:
        return True
    if blacklist and status in blacklist:
        return True
    return False


# ---------------------------------------------------------------------------
# Route grouping
# ---------------------------------------------------------------------------

def group_by_depth(routes: list[Route], depth: int = 1) -> dict[str, list[Route]]:
    """Group routes by path prefix at the given depth."""
    groups: dict[str, list[Route]] = {}
    for route in routes:
        path = route.template_path
        if not path.startswith("/"):
            path = "/" + path
        hits = 0
        prefix = path
        for i, ch in enumerate(path):
            if ch == "/":
                hits += 1
            if hits == depth + 1:
                prefix = path[:i]
                break
        groups.setdefault(prefix, []).append(route)
    return groups


# ---------------------------------------------------------------------------
# Complexity phasing
# ---------------------------------------------------------------------------

# Routes are scanned in phases ordered by complexity (total crumb count).
# Simpler routes run first for faster early results.
COMPLEXITY_PHASES = [
    ("A", 0, 0),       # bare paths, no crumbs
    ("B", 1, 5),       # light params
    ("C", 6, 20),      # moderate
    ("D", 21, 10_000), # heavy
]


def route_complexity(route: Route) -> int:
    """Total crumb count across all parameter locations."""
    return (len(route.path_crumbs) + len(route.query_crumbs)
            + len(route.body_crumbs) + len(route.header_crumbs))


def group_by_complexity(routes: list[Route]) -> list[tuple[str, list[Route]]]:
    """Split routes into complexity phases. Seeded shuffle within each phase."""
    phases: list[tuple[str, list[Route]]] = []
    for label, lo, hi in COMPLEXITY_PHASES:
        phase_routes = [r for r in routes if lo <= route_complexity(r) <= hi]
        if phase_routes:
            random.Random(42).shuffle(phase_routes)
            phases.append((label, phase_routes))
    return phases


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
# Main scan engine
# ---------------------------------------------------------------------------

from apiscan.output import ScanResult


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
    unsafe: bool = False,
    extra_headers: dict[str, str] | None = None,
    on_result: Callable[[ScanResult], None] | None = None,
    on_progress: Callable[[int], None] | None = None,
) -> list[ScanResult]:
    """Scan target_url with the given routes. Returns list of findings."""
    base_url = target_url.rstrip("/")
    semaphore = asyncio.Semaphore(concurrency)
    limiter = RateLimiter(rate_limit) if rate_limit else None
    results: list[ScanResult] = []

    async with httpx.AsyncClient(
        follow_redirects=True,
        max_redirects=max_redirects,
        verify=False,
        headers=extra_headers or {},
    ) as client:
        # Root preflight for baseline
        root_baselines = await run_preflight(
            client, base_url, "/", timeout, semaphore, limiter,
        )

        # Consecutive connection failure counter (not filtered responses)
        conn_failures = 0

        async def _scan_route(route: Route, baselines: list[WildcardResponse]) -> None:
            nonlocal conn_failures
            if conn_failures >= quarantine_threshold:
                if on_progress:
                    on_progress(0)
                return

            send_method = route.method
            original_method = route.method
            if not unsafe and route.method != "GET":
                send_method = "GET"

            path = render_path(route)
            query = render_query(route)
            url = f"{base_url}{path}"
            if query:
                url += f"?{query}"

            # Cap URL length to avoid 414 errors. Most servers reject URLs over
            # ~8KB; we use 2000 as a practical limit that covers all common servers.
            if len(url) > 2000:
                url = url[:2000]

            headers = render_headers(route)
            body_str = render_body(route) if send_method != "GET" else None
            if body_str and not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = "application/json"

            async with semaphore:
                if limiter:
                    await limiter.acquire()
                try:
                    resp = await client.request(
                        send_method, url,
                        headers=headers,
                        content=body_str.encode() if body_str else None,
                        timeout=timeout,
                    )
                except Exception:
                    conn_failures += 1
                    if on_progress:
                        on_progress(0)
                    return

            # Connection succeeded — reset failure counter
            conn_failures = 0

            body = resp.content
            status = resp.status_code
            content_length = len(body)
            words = body.count(b" ") + (1 if body else 0)
            lines = body.count(b"\n") + (1 if body else 0)
            resp_headers = dict(resp.headers)
            path_len = len(path.lstrip("/"))

            # Validator chain — filtered responses are normal, not quarantine-worthy
            if should_filter_status(status, status_blacklist, status_whitelist):
                if on_progress:
                    on_progress(0)
                return

            if is_known_bad_site(status, content_length, words, lines, resp_headers):
                if on_progress:
                    on_progress(0)
                return

            if matches_wildcard(status, content_length, words, lines, path_len, baselines):
                if on_progress:
                    on_progress(0)
                return

            # Passed all validators — it's a finding
            redirect_location = None
            if resp.history:
                redirect_location = str(resp.url)

            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            result = ScanResult(
                url=url,
                method=send_method,
                path=path,
                status_code=status,
                content_length=content_length,
                word_count=words,
                line_count=lines,
                redirect_location=redirect_location,
                original_method=original_method,
                timestamp=ts,
                request_headers=headers,
                request_body=body_str,
            )
            results.append(result)
            if on_result:
                on_result(result)
            if on_progress:
                on_progress(1)

        # Cache preflight baselines per prefix so we don't re-probe across phases
        prefix_cache: dict[str, list[WildcardResponse]] = {}

        async def _get_baselines(prefix: str) -> list[WildcardResponse]:
            if prefix in prefix_cache:
                return prefix_cache[prefix]
            prefix_baselines = await run_preflight(
                client, base_url, prefix, timeout, semaphore, limiter,
            )
            seen = set(root_baselines)
            merged = list(root_baselines)
            for bl in prefix_baselines:
                if bl not in seen:
                    seen.add(bl)
                    merged.append(bl)
            prefix_cache[prefix] = merged
            return merged

        # Scan in complexity phases: bare paths first, then progressively heavier
        phases = group_by_complexity(routes)
        for phase_label, phase_routes in phases:
            if on_phase:
                on_phase(phase_label, len(phase_routes))

            groups = group_by_depth(phase_routes, depth=1)
            all_tasks: list[asyncio.Task] = []

            for prefix, group_routes in groups.items():
                baselines = await _get_baselines(prefix)
                for route in group_routes:
                    all_tasks.append(asyncio.create_task(_scan_route(route, baselines)))

            try:
                for task in asyncio.as_completed(all_tasks):
                    await task
            except (asyncio.CancelledError, KeyboardInterrupt):
                for task in all_tasks:
                    task.cancel()
                await asyncio.gather(*all_tasks, return_exceptions=True)
                break

    return results
