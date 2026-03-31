"""Unit tests for the inference engine (no HTTP, mock send_fn)."""

from __future__ import annotations

import asyncio

import pytest

from apiscan.inference import (
    Baseline,
    Finding,
    InferenceEngine,
    ResponseSignature,
    build_baseline,
    compute_signature,
    is_known_bad_site,
    matches_baseline,
)
from apiscan.kite import Route
from apiscan.scantree import ScanTree


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sig(
    status_code: int = 404,
    content_type: str = "text/html",
    content_length: int = 50,
    adjusted_content_length: int = 40,
    adjustment_scale: int = 1,
    word_count: int = 10,
    line_count: int = 2,
    header_names: frozenset[str] | None = None,
) -> ResponseSignature:
    return ResponseSignature(
        status_code=status_code,
        content_type=content_type,
        content_length=content_length,
        adjusted_content_length=adjusted_content_length,
        adjustment_scale=adjustment_scale,
        word_count=word_count,
        line_count=line_count,
        header_names=header_names or frozenset(),
    )


def _baseline(*sigs: ResponseSignature) -> Baseline:
    return build_baseline(list(sigs))


# ---------------------------------------------------------------------------
# compute_signature
# ---------------------------------------------------------------------------

class TestComputeSignature:
    def test_basic(self):
        body = b"404 Not Found: /somepath"
        sig = compute_signature(404, {"content-type": "text/html"}, body, "/somepath")
        assert sig.status_code == 404
        assert sig.content_type == "text/html"
        assert sig.content_length == len(body)
        assert sig.word_count == body.count(b" ") + 1

    def test_content_type_parsing(self):
        sig = compute_signature(200, {"content-type": "application/json; charset=utf-8"}, b"{}", "/")
        assert sig.content_type == "application/json"

    def test_path_adjustment(self):
        body = b"error: testpath not found at testpath"
        sig = compute_signature(404, {}, body, "/testpath")
        assert sig.adjustment_scale == 2
        adjusted = body.replace(b"testpath", b"")
        assert sig.adjusted_content_length == len(adjusted)

    def test_header_names_lowercase(self):
        sig = compute_signature(200, {"Content-Type": "text/html", "X-Request-Id": "abc"}, b"", "/")
        assert "content-type" in sig.header_names
        assert "x-request-id" in sig.header_names

    def test_empty_body(self):
        sig = compute_signature(204, {}, b"", "/")
        assert sig.content_length == 0
        assert sig.word_count == 0
        assert sig.line_count == 0


# ---------------------------------------------------------------------------
# build_baseline
# ---------------------------------------------------------------------------

class TestBuildBaseline:
    def test_single_signature(self):
        sig = _sig()
        bl = _baseline(sig)
        assert len(bl.signatures) == 1
        # All comparable fields should be stable with single sig
        assert "status_code" in bl.stable_fields
        assert "content_type" in bl.stable_fields

    def test_stable_detection(self):
        s1 = _sig(status_code=404, content_length=50)
        s2 = _sig(status_code=404, content_length=50)
        bl = _baseline(s1, s2)
        assert "status_code" in bl.stable_fields
        assert "content_length" in bl.stable_fields

    def test_unstable_detection(self):
        s1 = _sig(content_length=50)
        s2 = _sig(content_length=75)
        bl = _baseline(s1, s2)
        assert "content_length" not in bl.stable_fields
        # Status should still be stable
        assert "status_code" in bl.stable_fields

    def test_empty(self):
        bl = build_baseline([])
        assert len(bl.signatures) == 0
        assert len(bl.stable_fields) == 0


# ---------------------------------------------------------------------------
# matches_baseline
# ---------------------------------------------------------------------------

class TestMatchesBaseline:
    def test_exact_length_match(self):
        bl = _baseline(_sig())
        assert matches_baseline(_sig(), bl, 10)

    def test_scaled_length_match(self):
        ref = _sig(adjusted_content_length=40, adjustment_scale=2)
        bl = _baseline(ref)
        candidate = _sig(content_length=40 + 2 * 8)  # path_len=8
        assert matches_baseline(candidate, bl, 8)

    def test_word_line_match(self):
        bl = _baseline(_sig(word_count=10, line_count=2))
        candidate = _sig(content_length=999, word_count=10, line_count=2)
        assert matches_baseline(candidate, bl, 5)

    def test_no_match(self):
        bl = _baseline(_sig())
        candidate = _sig(status_code=200, content_type="application/json",
                        content_length=100, word_count=5, line_count=1)
        assert not matches_baseline(candidate, bl, 5)

    def test_different_status_no_match(self):
        bl = _baseline(_sig(status_code=404))
        candidate = _sig(status_code=200, content_length=50)
        assert not matches_baseline(candidate, bl, 5)

    def test_403_vs_404_no_match(self):
        """403 and 404 are semantically distinct — must not match."""
        bl = _baseline(_sig(status_code=404, content_length=50))
        candidate = _sig(status_code=403, content_length=50)
        assert not matches_baseline(candidate, bl, 5)

    def test_content_type_change_breaks_match(self):
        bl = _baseline(_sig(content_type="text/html"))
        candidate = _sig(content_type="application/json", content_length=50)
        assert not matches_baseline(candidate, bl, 5)

    def test_unstable_field_ignored(self):
        s1 = _sig(content_length=50)
        s2 = _sig(content_length=75)
        bl = _baseline(s1, s2)
        # content_length is unstable, so exact match shouldn't trigger
        # but word/line count is stable and matches
        candidate = _sig(content_length=50, word_count=10, line_count=2)
        assert matches_baseline(candidate, bl, 5)

    def test_empty_baseline(self):
        bl = Baseline()
        assert not matches_baseline(_sig(), bl, 5)


# ---------------------------------------------------------------------------
# BaselineTree
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# is_known_bad_site
# ---------------------------------------------------------------------------

class TestKnownBadSites:
    def test_google_bad_request(self):
        sig = _sig(status_code=400, content_length=1555, word_count=82, line_count=12)
        assert is_known_bad_site(sig)

    def test_aws_gateway(self):
        sig = _sig(status_code=403, content_length=54, word_count=6, line_count=1,
                  header_names=frozenset({"x-amzn-requestid"}))
        assert is_known_bad_site(sig)

    def test_normal_response(self):
        sig = _sig(status_code=200, content_length=100, word_count=10, line_count=5)
        assert not is_known_bad_site(sig)


# ---------------------------------------------------------------------------
# InferenceEngine
# ---------------------------------------------------------------------------

def _make_engine(**kw) -> tuple[ScanTree, InferenceEngine]:
    """Create a ScanTree + InferenceEngine pair for testing."""
    tree = ScanTree()
    engine = InferenceEngine(tree=tree, **kw)
    return tree, engine


class TestInferenceEngine:
    @pytest.mark.asyncio
    async def test_baseline_match_returns_none(self):
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(_sig(status_code=404, content_type="text/html",
                                                      content_length=50)))
        route = Route(template_path="/random/path", method="GET")
        sig = _sig(status_code=404, content_type="text/html", content_length=50)

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="text/html", content_length=50)

        result = await engine.process(route, sig, "/random/path", mock_send)
        assert result is None

    @pytest.mark.asyncio
    async def test_status_deviation_returns_finding(self):
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(_sig(status_code=404, content_type="text/html")))

        route = Route(template_path="/api/v1/users", method="GET")
        sig = _sig(status_code=200, content_type="application/json",
                  content_length=100, word_count=5, line_count=1)

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=405, content_type="application/json",
                       content_length=30, word_count=3, line_count=1)

        result = await engine.process(route, sig, "/api/v1/users", mock_send)
        assert result is not None
        assert isinstance(result, Finding)
        assert "status:" in result.reason

    @pytest.mark.asyncio
    async def test_handler_boundary_filters_children(self):
        """When a prefix baseline is set, children matching it are filtered."""
        tree, engine = _make_engine()
        # Insert a route so the /api/v1 node exists in the tree
        tree.insert(Route(template_path="/api/v1/users", method="GET"))
        tree.set_baseline("/", "GET", _baseline(_sig(status_code=404, content_type="text/html")))
        # Simulate tree.walk having probed /api/v1 as a handler boundary
        tree.set_baseline("/api/v1", "GET", _baseline(
            _sig(status_code=404, content_type="application/json",
                 content_length=25, word_count=3, line_count=1)))

        route = Route(template_path="/api/v1/users", method="GET")
        candidate_sig = _sig(status_code=404, content_type="application/json",
                            content_length=25, word_count=3, line_count=1)

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(route, candidate_sig, "/api/v1/users", mock_send)
        assert result is None

    @pytest.mark.asyncio
    async def test_method_sensitive_405(self):
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(_sig(status_code=404, content_type="text/html")))

        route = Route(template_path="/api/v1/users", method="GET")
        sig = _sig(status_code=200, content_type="application/json",
                  content_length=100, word_count=5, line_count=1)

        async def mock_send(method, path, headers=None, body=None):
            if method != "GET":
                return _sig(status_code=405)
            return _sig(status_code=404, content_type="text/html")

        result = await engine.process(route, sig, "/api/v1/users", mock_send)
        assert result is not None
        assert "405" in result.reason
        assert result.confidence == "high"

    @pytest.mark.asyncio
    async def test_content_type_change_high_confidence(self):
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(_sig(content_type="text/html")))

        route = Route(template_path="/api/health", method="GET")
        sig = _sig(status_code=200, content_type="application/json",
                  content_length=20, word_count=2, line_count=1)

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="text/html")

        result = await engine.process(route, sig, "/api/health", mock_send)
        assert result is not None
        assert "content-type:" in result.reason
        assert result.confidence == "high"

    @pytest.mark.asyncio
    async def test_status_blacklist(self):
        tree, engine = _make_engine(status_blacklist={500, 502})
        tree.set_baseline("/", "GET", _baseline(_sig()))

        route = Route(template_path="/error", method="GET")
        sig = _sig(status_code=500)

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(route, sig, "/error", mock_send)
        assert result is None

    @pytest.mark.asyncio
    async def test_status_whitelist(self):
        tree, engine = _make_engine(status_whitelist={200, 301})
        tree.set_baseline("/", "GET", _baseline(_sig()))

        route = Route(template_path="/auth", method="GET")
        sig = _sig(status_code=401)

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(route, sig, "/auth", mock_send)
        assert result is None

    @pytest.mark.asyncio
    async def test_known_bad_site_filtered(self):
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(_sig()))

        route = Route(template_path="/api", method="GET")
        sig = _sig(status_code=400, content_length=1555, word_count=82, line_count=12)

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(route, sig, "/api", mock_send)
        assert result is None

    @pytest.mark.asyncio
    async def test_new_headers_in_reason(self):
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(_sig(header_names=frozenset({"content-type", "date"}))))

        route = Route(template_path="/admin/dashboard", method="GET")
        sig = _sig(status_code=401, content_type="application/json",
                  content_length=60, word_count=4, line_count=1,
                  header_names=frozenset({"content-type", "date", "x-request-id"}))

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="text/html")

        result = await engine.process(route, sig, "/admin/dashboard", mock_send)
        assert result is not None
        assert "x-request-id" in result.reason
