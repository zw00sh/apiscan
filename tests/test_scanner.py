"""Integration tests for the scanner against the test server."""

from __future__ import annotations

import time

import pytest

from apiscan.kite import Crumb, Route
from apiscan.output import ScanResult
from apiscan.scanner import RateLimiter, scan


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        limiter = RateLimiter(rate=10.0)
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.35


class TestScanIntegration:
    @pytest.mark.asyncio
    async def test_basic_discovery(self, test_server_url):
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/api/v1/health", method="GET"),
        ]
        results, _ = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        paths = {r.path for r in results}
        assert "/api/v1/users" in paths
        assert "/api/v1/health" in paths

    @pytest.mark.asyncio
    async def test_wildcard_filtering(self, test_server_url):
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/nonexistent/random/path", method="GET"),
            Route(template_path="/also/does/not/exist", method="GET"),
        ]
        results, _ = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        paths = {r.path for r in results}
        assert "/api/v1/users" in paths
        assert "/nonexistent/random/path" not in paths

    @pytest.mark.asyncio
    async def test_method_sensitive_discovery(self, test_server_url):
        routes = [Route(template_path="/api/v1/users", method="POST")]
        results, _ = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        assert len(results) >= 1
        # Should be reported with POST method (either directly or via alternate method)
        methods = {r.method for r in results}
        assert "POST" in methods

    @pytest.mark.asyncio
    async def test_405_as_finding(self, test_server_url):
        routes = [Route(template_path="/api/v1/users", method="PUT")]
        results, _ = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        found_405 = any(r.status_code == 405 for r in results)
        assert found_405

    @pytest.mark.asyncio
    async def test_findings_have_reason(self, test_server_url):
        routes = [Route(template_path="/api/v1/users", method="GET")]
        results, _ = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        assert len(results) >= 1
        for r in results:
            assert r.reason

    @pytest.mark.asyncio
    async def test_findings_have_confidence(self, test_server_url):
        routes = [Route(template_path="/api/v1/users", method="GET")]
        results, _ = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        assert len(results) >= 1
        for r in results:
            assert r.confidence in ("high", "medium", "low")

    @pytest.mark.asyncio
    async def test_content_type_boundary_detection(self, test_server_url):
        routes = [Route(template_path="/internal/metrics", method="GET")]
        results, _ = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        paths = {r.path for r in results}
        assert "/internal/metrics" in paths

    @pytest.mark.asyncio
    async def test_admin_auth_required(self, test_server_url):
        routes = [Route(template_path="/admin/dashboard", method="GET")]
        results, _ = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        paths = {r.path for r in results}
        assert "/admin/dashboard" in paths
        dashboard = [r for r in results if r.path == "/admin/dashboard"][0]
        assert dashboard.status_code == 401

    @pytest.mark.asyncio
    async def test_timeout(self, test_server_url):
        routes = [Route(template_path="/slow", method="GET")]
        start = time.monotonic()
        results, _ = await scan(test_server_url, routes, concurrency=2, timeout=1.0)
        assert time.monotonic() - start < 4.0
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_redirect_follow(self, test_server_url):
        routes = [Route(template_path="/redirect", method="GET")]
        results, _ = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_request_construction(self, test_server_url):
        routes = [
            Route(
                template_path="/echo", method="POST",
                query_crumbs=[Crumb("static", name="q", fields={"v": "test"})],
                header_crumbs=[Crumb("static", name="X-Custom", fields={"v": "myvalue"})],
                body_crumbs=[Crumb("static", name="key", fields={"v": "val"})],
            ),
        ]
        results, _ = await scan(test_server_url, routes, concurrency=1, timeout=5.0)
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self, test_server_url):
        routes = [Route(template_path="/api/v1/users", method="GET") for _ in range(10)]
        start = time.monotonic()
        await scan(test_server_url, routes, concurrency=5, rate_limit=5.0, timeout=5.0)
        assert time.monotonic() - start >= 1.5

    @pytest.mark.asyncio
    async def test_status_blacklist(self, test_server_url):
        routes = [Route(template_path="/api/v1/users", method="GET")]
        results, _ = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            status_blacklist={200},
        )
        assert not any(r.status_code == 200 for r in results)

    @pytest.mark.asyncio
    async def test_admin_wildcard_children_filtered(self, test_server_url):
        """Children of a wildcard handler should be filtered."""
        routes = [
            Route(template_path="/admin/dashboard", method="GET"),
            Route(template_path="/admin/settings", method="GET"),
            Route(template_path="/admin/logs", method="GET"),
        ]
        results, _ = await scan(test_server_url, routes, concurrency=1, timeout=5.0)
        paths = {r.path for r in results}
        assert "/admin/dashboard" in paths
        assert "/admin/settings" not in paths
        assert "/admin/logs" not in paths

    @pytest.mark.asyncio
    async def test_boundary_probe_reported(self, test_server_url):
        """Handler boundaries discovered during probing should appear as findings."""
        routes = [
            Route(template_path="/admin/dashboard", method="GET"),
        ]
        results, tree = await scan(test_server_url, routes, concurrency=1, timeout=5.0)
        # The /admin boundary should be reported (403 json vs 404 html root)
        boundary_results = [r for r in results if "probe:" in r.reason]
        assert len(boundary_results) >= 1
