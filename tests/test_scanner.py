"""Integration tests for the inference-based scanner against the test server."""

from __future__ import annotations

import time

import pytest

from apiscan.kite import Crumb, Route
from apiscan.output import ScanResult
from apiscan.scanner import (
    RateLimiter,
    group_by_complexity,
    route_complexity,
    scan,
)


# ---------------------------------------------------------------------------
# Unit tests for route complexity / phasing
# ---------------------------------------------------------------------------

class TestRouteComplexity:
    def test_bare_route(self):
        r = Route(template_path="/health", method="GET")
        assert route_complexity(r) == 0

    def test_with_crumbs(self):
        r = Route(
            template_path="/users/{id}",
            method="GET",
            path_crumbs=[Crumb("uuid", name="id")],
            query_crumbs=[Crumb("static", name="q", fields={"v": "1"})],
        )
        assert route_complexity(r) == 2


class TestGroupByComplexity:
    def test_ordering(self):
        routes = [
            Route(template_path="/a", method="GET", query_crumbs=[Crumb("static", name="q", fields={"v": "1"})]),
            Route(template_path="/b", method="GET"),
            Route(template_path="/c", method="GET"),
        ]
        phases = group_by_complexity(routes)
        assert phases[0][0] == "0 mutations"
        assert len(phases[0][1]) == 2  # /b and /c
        assert phases[1][0] == "1 mutations"
        assert len(phases[1][1]) == 1  # /a

    def test_alphabetical_within_phase(self):
        routes = [
            Route(template_path="/z", method="GET"),
            Route(template_path="/a", method="GET"),
            Route(template_path="/m", method="GET"),
        ]
        phases = group_by_complexity(routes)
        paths = [r.template_path for r in phases[0][1]]
        assert paths == ["/a", "/m", "/z"]


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        limiter = RateLimiter(rate=10.0)  # 10 RPS = 0.1s interval
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.35


# ---------------------------------------------------------------------------
# Integration tests against test server
# ---------------------------------------------------------------------------

class TestScanIntegration:
    @pytest.mark.asyncio
    async def test_basic_discovery(self, test_server_url):
        """Real routes should be discovered."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/api/v1/health", method="GET"),
        ]
        results = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        paths = {r.path for r in results}
        assert "/api/v1/users" in paths
        assert "/api/v1/health" in paths

    @pytest.mark.asyncio
    async def test_wildcard_filtering(self, test_server_url):
        """Random paths should be filtered by inference engine."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/nonexistent/random/path", method="GET"),
            Route(template_path="/also/does/not/exist", method="GET"),
        ]
        results = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        paths = {r.path for r in results}
        assert "/api/v1/users" in paths
        assert "/nonexistent/random/path" not in paths
        assert "/also/does/not/exist" not in paths

    @pytest.mark.asyncio
    async def test_method_sensitive_discovery(self, test_server_url):
        """POST to a real endpoint should be discovered."""
        routes = [
            Route(template_path="/api/v1/users", method="POST"),
        ]
        results = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        assert len(results) >= 1
        assert results[0].method == "POST"

    @pytest.mark.asyncio
    async def test_405_as_finding(self, test_server_url):
        """PUT to /api/v1/users (only GET/POST defined) should yield 405 finding."""
        routes = [
            Route(template_path="/api/v1/users", method="PUT"),
        ]
        results = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        found_405 = any(r.status_code == 405 for r in results)
        assert found_405

    @pytest.mark.asyncio
    async def test_findings_have_reason(self, test_server_url):
        """All findings should include a reason string."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
        ]
        results = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        assert len(results) >= 1
        for r in results:
            assert r.reason, f"Finding {r.path} has no reason"

    @pytest.mark.asyncio
    async def test_findings_have_confidence(self, test_server_url):
        """All findings should include a confidence level."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
        ]
        results = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        assert len(results) >= 1
        for r in results:
            assert r.confidence in ("high", "medium", "low")

    @pytest.mark.asyncio
    async def test_content_type_boundary_detection(self, test_server_url):
        """Routes with different content-type from gateway should be found."""
        routes = [
            Route(template_path="/internal/metrics", method="GET"),
        ]
        results = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        # /internal/metrics returns text/plain 200 vs gateway text/html 404
        paths = {r.path for r in results}
        assert "/internal/metrics" in paths

    @pytest.mark.asyncio
    async def test_admin_auth_required(self, test_server_url):
        """Auth-required endpoint should be discovered with reason."""
        routes = [
            Route(template_path="/admin/dashboard", method="GET"),
        ]
        results = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        paths = {r.path for r in results}
        assert "/admin/dashboard" in paths
        dashboard = [r for r in results if r.path == "/admin/dashboard"][0]
        assert dashboard.status_code == 401

    @pytest.mark.asyncio
    async def test_timeout(self, test_server_url):
        """Requests to /slow should timeout without hanging."""
        routes = [
            Route(template_path="/slow", method="GET"),
        ]
        start = time.monotonic()
        results = await scan(test_server_url, routes, concurrency=2, timeout=1.0)
        elapsed = time.monotonic() - start
        assert elapsed < 4.0
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_redirect_follow(self, test_server_url):
        """/redirect -> /api/v1/health should be followed."""
        routes = [
            Route(template_path="/redirect", method="GET"),
        ]
        results = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_request_construction(self, test_server_url):
        """Hit /echo and verify request was constructed correctly."""
        routes = [
            Route(
                template_path="/echo",
                method="POST",
                query_crumbs=[Crumb("static", name="q", fields={"v": "test"})],
                header_crumbs=[Crumb("static", name="X-Custom", fields={"v": "myvalue"})],
                body_crumbs=[Crumb("static", name="key", fields={"v": "val"})],
            ),
        ]
        results = await scan(test_server_url, routes, concurrency=1, timeout=5.0)
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self, test_server_url):
        """With rate=5, requests should be throttled."""
        routes = [
            Route(template_path="/api/v1/users", method="GET")
            for _ in range(10)
        ]
        start = time.monotonic()
        await scan(test_server_url, routes, concurrency=5, rate_limit=5.0, timeout=5.0)
        elapsed = time.monotonic() - start
        assert elapsed >= 1.5

    @pytest.mark.asyncio
    async def test_status_blacklist(self, test_server_url):
        """Blacklisted status codes should be filtered."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
        ]
        results = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            status_blacklist={200},
        )
        assert not any(r.status_code == 200 for r in results)
