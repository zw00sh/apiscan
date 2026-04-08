"""Integration tests for the scanner against the test server."""

from __future__ import annotations

import time

import pytest

from apiscan.kite import Route
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
        boundary_results = [r for r in results if r.is_boundary]
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
            recurse=True, recurse_all=True, max_depth=2,
        )
        paths = {r.path for r in results}
        # /deep boundary should be discovered (403 json vs root 404 html)
        boundary_results = [r for r in results if r.is_boundary]
        assert any("/deep" in r.path for r in boundary_results)
        # Recursion at /deep injects /deep/secret/thing (full path, via
        # recurse_all). The /deep/secret prefix is itself a boundary
        # (401 vs /deep's 403), discovered via tree walk probing.
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

    @pytest.mark.asyncio
    async def test_recursive_alternate_method_discovery(self, test_server_url):
        """Recursive routes should discover POST endpoints via alternate
        method probing when GET matches baseline.

        /deep/secret/* returns 401 for everything. With recursion,
        /deep/secret/endpoint is injected. GET matches the /deep/secret
        baseline (401), but alternate method probing may reveal different
        behavior on POST/PUT/DELETE.
        """
        routes = [
            Route(template_path="/deep/endpoint", method="GET"),
            Route(template_path="/secret", method="GET"),
            Route(template_path="/endpoint", method="GET"),
        ]
        results, tree = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=True, max_depth=2,
        )
        # The /deep boundary and /deep/secret sub-boundary should be found
        boundary_paths = {r.path for r in results if r.is_boundary}
        assert "/deep" in boundary_paths or any("/deep" in p for p in boundary_paths)

    @pytest.mark.asyncio
    async def test_results_before_recursion_completes(self, test_server_url):
        """Original wordlist findings should be emitted, not blocked by recursion."""
        routes = [
            Route(template_path="/internal/metrics", method="GET"),
            Route(template_path="/deep/endpoint", method="GET"),
        ]
        result_order: list[str] = []

        def on_result(result: ScanResult) -> None:
            result_order.append(result.path)

        await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=True, max_depth=1,
            on_result=on_result,
        )
        # /internal/metrics is a direct finding (content-type boundary).
        # It should appear in results regardless of recursion.
        assert "/internal/metrics" in result_order

    @pytest.mark.asyncio
    async def test_baseline_exists_before_route_classification(self, test_server_url):
        """Routes should be classified against a baseline that exists,
        not against None. This verifies the probe-before-scan invariant."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/api/v1/health", method="GET"),
        ]
        results, tree = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
        )
        # All results should have a reason (not "no baseline available")
        for r in results:
            assert "no baseline" not in r.reason, f"{r.path} had no baseline"

    @pytest.mark.asyncio
    async def test_reactive_boundary_probe_on_finding(self, test_server_url):
        """When a flat wordlist route deviates from baseline, the scanner
        should reactively probe it as a prefix and register a baseline."""
        routes = [
            Route(template_path="/admin/dashboard", method="GET"),
        ]
        results, tree = await scan(
            test_server_url, routes, concurrency=1, timeout=5.0,
        )
        # /admin/dashboard deviates (401 json vs root 404 html).
        # The worker should reactively probe /admin/dashboard as a prefix.
        # Whether or not it's a boundary, the route itself should be a finding.
        paths = {r.path for r in results}
        assert "/admin/dashboard" in paths


class TestRecursionPrefixStripping:
    @pytest.mark.asyncio
    async def test_no_prefix_stacking(self, test_server_url):
        """Recursion should not produce /deep/deep/endpoint from a wordlist
        entry /deep/endpoint when /deep is a boundary."""
        routes = [
            Route(template_path="/deep/endpoint", method="GET"),
            Route(template_path="/endpoint", method="GET"),
        ]
        results, tree = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=True, max_depth=2,
        )
        paths = {r.path for r in results}
        assert "/deep/deep/endpoint" not in paths, \
            f"/deep/deep/endpoint should not exist (prefix-stripped), got: {paths}"
        # But /deep should still be found as a boundary
        assert any("/deep" in r.path for r in results if r.is_boundary)

    @pytest.mark.asyncio
    async def test_debug_shows_strip_counts(self, test_server_url):
        """on_debug should receive a message with strip/inject/dedup counts."""
        routes = [
            Route(template_path="/deep/endpoint", method="GET"),
            Route(template_path="/endpoint", method="GET"),
        ]
        debug_msgs: list[str] = []
        results, tree = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=True, max_depth=1,
            on_debug=lambda msg: debug_msgs.append(msg),
        )
        recurse_msgs = [m for m in debug_msgs if "recurse" in m and "stripped" in m]
        assert len(recurse_msgs) >= 1, f"Expected recurse debug msg, got: {debug_msgs}"
        msg = recurse_msgs[0]
        assert "stripped" in msg
        assert "injected" in msg


class TestSmartRecursionIntegration:
    @pytest.mark.asyncio
    async def test_smart_recurse_fewer_requests(self, test_server_url):
        """Smart recursion should plan fewer requests than recurse_all."""
        from apiscan.scanner import RequestTracker

        routes = [
            Route(template_path="/deep/endpoint", method="GET"),
            Route(template_path="/api/v1/endpoint", method="GET"),
            Route(template_path="/endpoint", method="GET"),
        ]

        tracker_smart = RequestTracker()
        await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=True, recurse_all=False, max_depth=1,
            tracker=tracker_smart,
        )

        tracker_full = RequestTracker()
        await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            recurse=True, recurse_all=True, max_depth=1,
            tracker=tracker_full,
        )

        assert tracker_smart.planned < tracker_full.planned, \
            f"Smart ({tracker_smart.planned}) should plan fewer than full ({tracker_full.planned})"


class TestSegmentPrefixSuppression:
    @pytest.mark.asyncio
    async def test_segment_prefix_suppresses_siblings(self, test_server_url):
        """When /static is a finding and /static{random} returns the same
        response, /static.html and /staticfiles should be suppressed."""
        routes = [
            Route(template_path="/static", method="GET"),
            Route(template_path="/static.html", method="GET"),
            Route(template_path="/staticfiles", method="GET"),
        ]
        results, _ = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
        )
        paths = {r.path for r in results}
        # /static itself should be a finding (the real handler)
        assert any(r.path == "/static" for r in results), \
            f"Expected /static finding, got: {paths}"
        # /static.html and /staticfiles should be suppressed (same handler)
        assert "/static.html" not in paths, \
            f"/static.html should be suppressed, got: {paths}"
        assert "/staticfiles" not in paths, \
            f"/staticfiles should be suppressed, got: {paths}"

    @pytest.mark.asyncio
    async def test_wildcard_siblings_skipped_by_default(self, test_server_url):
        """With default skip_wildcard_siblings=True, /staticmap is skipped
        even though it has a different response — the hint tells the
        operator to re-run with --no-skip-wildcard-siblings."""
        routes = [
            Route(template_path="/static", method="GET"),
            Route(template_path="/staticmap", method="GET"),
        ]
        results, _ = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
        )
        paths = {r.path for r in results}
        assert "/staticmap" not in paths, \
            f"/staticmap should be skipped by default, got: {paths}"

    @pytest.mark.asyncio
    async def test_no_skip_wildcard_siblings_preserves_different_handler(self, test_server_url):
        """With skip_wildcard_siblings=False, /staticmap survives because
        its response differs from the /static wildcard handler."""
        routes = [
            Route(template_path="/static", method="GET"),
            Route(template_path="/staticmap", method="GET"),
        ]
        results, _ = await scan(
            test_server_url, routes, concurrency=2, timeout=5.0,
            skip_wildcard_siblings=False,
        )
        paths = {r.path for r in results}
        assert "/staticmap" in paths, \
            f"Expected /staticmap to survive with skip disabled, got: {paths}"
