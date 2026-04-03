"""Unit tests for ScanSession and SegmentPrefixTracker classes."""

from __future__ import annotations

import pytest

from apiscan.inference import Baseline, ResponseSignature, build_baseline
from apiscan.kite import Route
from apiscan.output import ScanResult
from apiscan.scanner import (
    ScanSession,
    SegmentPrefixTracker,
    _split_path_segment,
    scan,
)
from apiscan.scantree import ScanTree
from apiscan.workqueue import LookaheadWork, ProbeWork, RouteWork, WorkQueue


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sig(
    status_code: int = 200,
    content_type: str = "application/json",
    content_length: int = 100,
    word_count: int = 10,
    line_count: int = 1,
) -> ResponseSignature:
    return ResponseSignature(
        status_code=status_code,
        content_type=content_type,
        content_length=content_length,
        adjusted_content_length=content_length,
        adjustment_scale=0,
        word_count=word_count,
        line_count=line_count,
        header_names=frozenset(),
    )


def _result(path: str = "/test", sig: ResponseSignature | None = None) -> ScanResult:
    return ScanResult(
        url=f"http://example.com{path}",
        method="GET",
        path=path,
        status_code=200,
        content_length=100,
        word_count=10,
        line_count=1,
        redirect_location=None,
        reason="test",
        confidence="high",
        timestamp="2025-01-01T00:00:00",
        signature=sig,
    )


# ---------------------------------------------------------------------------
# _split_path_segment (module-level pure function)
# ---------------------------------------------------------------------------

class TestSplitPathSegment:
    def test_two_segments(self):
        assert _split_path_segment("/foo/bar") == ("/foo", "bar")

    def test_single_segment(self):
        assert _split_path_segment("/foo") == ("/", "foo")

    def test_three_segments(self):
        assert _split_path_segment("/a/b/c") == ("/a/b", "c")

    def test_trailing_slash(self):
        assert _split_path_segment("/foo/bar/") == ("/foo", "bar")


# ---------------------------------------------------------------------------
# SegmentPrefixTracker
# ---------------------------------------------------------------------------

class TestSegmentPrefixTrackerShouldSkip:
    def _tracker_with_static(self) -> SegmentPrefixTracker:
        t = SegmentPrefixTracker()
        bl = build_baseline([_sig(status_code=403, content_length=50)])
        t.handlers[("/", "static")] = bl
        return t

    def test_skip_probe_matching_prefix(self):
        t = self._tracker_with_static()
        assert t.should_skip("x", ProbeWork(prefix="/staticfiles")) is True

    def test_no_skip_probe_different_prefix(self):
        t = self._tracker_with_static()
        assert t.should_skip("x", ProbeWork(prefix="/other")) is False

    def test_no_skip_exact_segment(self):
        t = self._tracker_with_static()
        assert t.should_skip("x", ProbeWork(prefix="/static")) is False

    def test_skip_route_matching_prefix(self):
        t = self._tracker_with_static()
        route = Route(template_path="/staticfiles", method="GET")
        assert t.should_skip("x", RouteWork(route=route)) is True

    def test_no_skip_lookahead(self):
        t = self._tracker_with_static()
        assert t.should_skip("x", LookaheadWork(prefix="/", segment="static")) is False


class TestSegmentPrefixTrackerIsSuppressed:
    def _tracker_with_static(self) -> SegmentPrefixTracker:
        t = SegmentPrefixTracker()
        bl = build_baseline([_sig(status_code=403, content_length=50, word_count=5, line_count=1)])
        t.handlers[("/", "static")] = bl
        return t

    def test_matching_sig_suppressed(self):
        t = self._tracker_with_static()
        sig = _sig(status_code=403, content_length=50, word_count=5, line_count=1)
        assert t.is_suppressed("/staticfiles", sig) is True

    def test_different_sig_not_suppressed(self):
        t = self._tracker_with_static()
        sig = _sig(status_code=200, content_length=999, word_count=50, line_count=10)
        assert t.is_suppressed("/staticfiles", sig) is False

    def test_exact_segment_not_suppressed(self):
        t = self._tracker_with_static()
        sig = _sig(status_code=403, content_length=50, word_count=5, line_count=1)
        assert t.is_suppressed("/static", sig) is False


class TestSegmentPrefixTrackerSweep:
    def test_removes_suppressed_indices(self):
        t = SegmentPrefixTracker()
        # Need at least one handler for sweep to activate
        t.handlers[("/", "x")] = build_baseline([_sig()])
        t._suppressed = {1}
        results = [_result("/a"), _result("/b"), _result("/c")]
        swept = t.sweep(results)
        assert len(swept) == 2
        assert swept[0].path == "/a"
        assert swept[1].path == "/c"

    def test_removes_dynamically_suppressed(self):
        t = SegmentPrefixTracker()
        sig = _sig(status_code=403, content_length=50, word_count=5, line_count=1)
        bl = build_baseline([sig])
        t.handlers[("/", "static")] = bl
        results = [
            _result("/static", sig),       # exact segment — kept
            _result("/staticfiles", sig),   # sibling — suppressed
            _result("/other", sig),         # different parent — kept
        ]
        swept = t.sweep(results)
        assert len(swept) == 2
        paths = {r.path for r in swept}
        assert "/static" in paths
        assert "/other" in paths

    def test_no_handlers_returns_all(self):
        t = SegmentPrefixTracker()
        results = [_result("/a"), _result("/b")]
        assert t.sweep(results) == results


# ---------------------------------------------------------------------------
# ScanSession — transient error bug fix
# ---------------------------------------------------------------------------

class TestTransientErrorHandling:
    @pytest.mark.asyncio
    async def test_transient_error_no_crash(self, test_server_url):
        """Scanning a route that times out should not crash with NameError.

        Previously, the _worker caught _TRANSIENT_ERRORS and called
        logger.debug() — but logger was undefined, causing NameError.
        """
        routes = [Route(template_path="/slow", method="GET")]
        # timeout=0.5 ensures /slow (5s delay) times out
        results, _ = await scan(test_server_url, routes, concurrency=1, timeout=0.5)
        # Should complete without NameError, returning 0 findings
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# ScanSession — _inject_recursive
# ---------------------------------------------------------------------------

class TestInjectRecursive:
    def _make_session(self, routes, *, recurse=True, max_depth=2):
        session = ScanSession(
            "http://example.com",
            routes,
            recurse=recurse,
            max_depth=max_depth,
        )
        session._tree = ScanTree(routes)
        session._wq = WorkQueue()
        session._wq.prepare()
        return session

    def test_prefix_stripping(self):
        routes = [
            Route(template_path="/api/users", method="GET"),
            Route(template_path="/health", method="GET"),
        ]
        session = self._make_session(routes)
        info = session._inject_recursive("/api", 0)
        assert info is not None
        # /health should be injected as /api/health
        assert ("/api/health", "GET") in session._tree._seen
        # /api/users already exists (from wordlist), so prefix-stripping
        # produces the same path — it's deduped, not doubled
        assert ("/api/api/users", "GET") not in session._tree._seen

    def test_depth_gating(self):
        routes = [Route(template_path="/a", method="GET")]
        session = self._make_session(routes, max_depth=2)
        result = session._inject_recursive("/x", 2)
        assert result is None

    def test_returns_none_without_flag(self):
        routes = [Route(template_path="/a", method="GET")]
        session = self._make_session(routes, recurse=False)
        result = session._inject_recursive("/x", 0)
        assert result is None


# ---------------------------------------------------------------------------
# Smart recursion (structural prefix stripping)
# ---------------------------------------------------------------------------

class TestSmartRecursion:
    def _make_session(self, routes, *, recurse=True, recurse_all=False, max_depth=2):
        session = ScanSession(
            "http://example.com",
            routes,
            recurse=recurse,
            recurse_all=recurse_all,
            max_depth=max_depth,
        )
        session._tree = ScanTree(routes)
        session._wq = WorkQueue()
        session._wq.prepare()
        return session

    def test_compute_recurse_suffixes(self):
        """Structural prefixes like /api and /api/v1 should be stripped."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/api/v1/health", method="GET"),
            Route(template_path="/login", method="GET"),
        ]
        session = self._make_session(routes)
        suffixes = session._compute_recurse_suffixes()
        suffix_paths = {r.template_path for r in suffixes}
        assert "/users" in suffix_paths
        assert "/health" in suffix_paths
        assert "/login" in suffix_paths
        # structural prefixes should not appear as full paths
        assert "/api/v1/users" not in suffix_paths
        assert "/api/v1/health" not in suffix_paths

    def test_suffix_dedup(self):
        """/api/v1/users, /api/v2/users, /users all collapse to /users."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/api/v2/users", method="GET"),
            Route(template_path="/users", method="GET"),
        ]
        session = self._make_session(routes)
        suffixes = session._compute_recurse_suffixes()
        suffix_paths = [r.template_path for r in suffixes]
        assert suffix_paths.count("/users") == 1

    def test_smart_inject_fewer_routes(self):
        """Smart recursion should inject fewer routes than the full wordlist."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/api/v1/health", method="GET"),
            Route(template_path="/login", method="GET"),
            Route(template_path="/health", method="GET"),
        ]
        session = self._make_session(routes)
        session._recurse_suffixes = session._compute_recurse_suffixes()
        info = session._inject_recursive("/boundary", 0)
        assert info is not None
        # /api/v1/users -> /users, /api/v1/health -> /health, /login, /health (dedup)
        # Should inject 3 unique: /boundary/users, /boundary/health, /boundary/login
        assert "3 new" in info

    def test_recurse_all_injects_full_wordlist(self):
        """recurse_all=True should inject all paths, not stripped suffixes."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/api/v1/health", method="GET"),
            Route(template_path="/login", method="GET"),
            Route(template_path="/health", method="GET"),
        ]
        session = self._make_session(routes, recurse_all=True)
        # recurse_all means _recurse_suffixes is None → uses full wordlist
        session._recurse_suffixes = None
        info = session._inject_recursive("/boundary", 0)
        assert info is not None
        assert "4 new" in info

    def test_flat_wordlist_no_stripping(self):
        """All single-segment paths — smart recursion is a no-op."""
        routes = [
            Route(template_path="/users", method="GET"),
            Route(template_path="/login", method="GET"),
            Route(template_path="/health", method="GET"),
        ]
        session = self._make_session(routes)
        suffixes = session._compute_recurse_suffixes()
        assert len(suffixes) == len(routes)


# ---------------------------------------------------------------------------
# ScanSession.run() matches scan() — integration
# ---------------------------------------------------------------------------

class TestScanSessionIntegration:
    @pytest.mark.asyncio
    async def test_run_matches_scan(self, test_server_url):
        """ScanSession.run() should produce identical results to scan()."""
        routes = [
            Route(template_path="/api/v1/users", method="GET"),
            Route(template_path="/api/v1/health", method="GET"),
        ]
        scan_results, _ = await scan(test_server_url, routes, concurrency=2, timeout=5.0)
        session = ScanSession(test_server_url, routes, concurrency=2, timeout=5.0)
        session_results, _ = await session.run()

        scan_paths = {(r.path, r.method) for r in scan_results}
        session_paths = {(r.path, r.method) for r in session_results}
        assert scan_paths == session_paths

    @pytest.mark.asyncio
    async def test_scan_returns_tuple(self, test_server_url):
        """Regression guard: scan() returns (list[ScanResult], ScanTree)."""
        routes = [Route(template_path="/api/v1/users", method="GET")]
        result = await scan(test_server_url, routes, concurrency=1, timeout=5.0)
        assert isinstance(result, tuple)
        assert isinstance(result[0], list)
        assert isinstance(result[1], ScanTree)
