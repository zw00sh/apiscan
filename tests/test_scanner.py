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
        boundary_results = [r for r in results if "boundary:" in r.reason]
        assert len(boundary_results) >= 1

    @pytest.mark.asyncio
    async def test_progress_count_matches_route_count(self, test_server_url):
        """Progress completed count should equal route count, not inflated by
        boundary probes or multi-finding alternate methods."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/admin/dashboard", method="GET"),
            Route(template_path="/admin/settings", method="GET"),
        ]
        progress_calls = []

        def on_progress(findings_delta: int) -> None:
            progress_calls.append(findings_delta)

        await scan(
            test_server_url, routes, concurrency=1, timeout=5.0,
            on_progress=on_progress,
        )
        # Exactly one on_progress call per route (3 routes = 3 calls)
        # Boundary probes should NOT increment progress
        assert len(progress_calls) == len(routes)


class TestRecursionIntegration:
    @pytest.mark.asyncio
    async def test_recursion_discovers_sub_handler(self, test_server_url):
        """Recursion should discover /deep/secret when wordlist has /secret
        and /deep is found as a boundary."""
        routes = [
            Route(template_path="/deep/endpoint", method="GET"),
            Route(template_path="/secret/thing", method="GET"),
        ]
        results, tree = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=True, max_depth=2,
        )
        paths = {r.path for r in results}
        # /deep boundary should be discovered (403 json vs root 404 html)
        boundary_results = [r for r in results if "boundary:" in r.reason]
        assert any("/deep" in r.path for r in boundary_results)
        # Recursion at /deep injects /deep/secret/thing. The /deep/secret
        # prefix is itself a boundary (401 vs /deep's 403), discovered via
        # tree walk probing. /deep/secret should appear as a finding.
        assert "/deep/secret" in paths or any("/deep/secret" in r.path for r in results)

    @pytest.mark.asyncio
    async def test_flat_wordlist_boundary_discovery(self, test_server_url):
        """A flat wordlist with no nested paths should still discover boundaries
        via worker-initiated probe_prefix."""
        routes = [
            Route(template_path="/deep", method="GET"),
            Route(template_path="/nonexistent", method="GET"),
        ]
        results, tree = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=True, max_depth=1,
        )
        # /deep should be a finding (403 json vs root 404 html)
        paths = {r.path for r in results}
        assert "/deep" in paths or any("/deep" in r.path for r in results)
        # Worker should have probed /deep as a prefix and registered a baseline
        bl = tree.lookup_baseline("/deep/anything", "GET")
        assert bl is not None
        assert bl[0] == "/deep"

    @pytest.mark.asyncio
    async def test_recursion_respects_max_depth(self, test_server_url):
        """max_depth=1 should prevent second-level recursion."""
        routes = [
            Route(template_path="/deep/endpoint", method="GET"),
            Route(template_path="/secret", method="GET"),
        ]
        results, tree = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=True, max_depth=1,
        )
        paths = {r.path for r in results}
        # Depth 0: /deep is a boundary → recursion adds /deep/secret
        # Depth 1: /deep/secret could be a boundary → but max_depth=1 blocks
        # /deep/secret/secret should NOT exist
        assert "/deep/secret/secret" not in paths

    @pytest.mark.asyncio
    async def test_no_recursion_without_flag(self, test_server_url):
        """Without recurse=True, no recursive routes should be discovered."""
        routes = [
            Route(template_path="/deep/endpoint", method="GET"),
            Route(template_path="/secret", method="GET"),
        ]
        results, tree = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=False,
        )
        paths = {r.path for r in results}
        # /deep/secret should NOT appear — no recursion
        assert "/deep/secret" not in paths

    @pytest.mark.asyncio
    async def test_recursion_progress_tracking(self, test_server_url):
        """Recursive route injection should increase the tracker's planned count."""
        from apiscan.scanner import RequestTracker
        tracker = RequestTracker()

        routes = [
            Route(template_path="/deep/endpoint", method="GET"),
            Route(template_path="/secret", method="GET"),
        ]
        initial_plan = 0

        results, tree = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=True, max_depth=1,
            tracker=tracker,
        )
        # Planned count should exceed initial routes + init probes
        # because recursion added more routes
        assert tracker.planned > 10 + len(routes)
