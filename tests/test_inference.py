"""Unit tests for the inference engine (no HTTP, mock send_fn)."""

from __future__ import annotations

import asyncio

import pytest

from apiscan.inference import (
    Baseline,
    BaselineTree,
    Finding,
    InferenceEngine,
    ResponseSignature,
    build_baseline,
    compute_signature,
    is_known_bad_site,
    matches_baseline,
)
from apiscan.kite import Route


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

class TestBaselineTree:
    def test_root_lookup(self):
        tree = BaselineTree()
        bl = _baseline(_sig())
        tree.set("/", "GET", bl)
        result = tree.lookup("/api/v1/users", "GET")
        assert result is not None
        assert result[0] == "/"

    def test_nearest_ancestor(self):
        tree = BaselineTree()
        root_bl = _baseline(_sig(content_type="text/html"))
        api_bl = _baseline(_sig(content_type="application/json"))
        tree.set("/", "GET", root_bl)
        tree.set("/api/v1", "GET", api_bl)
        result = tree.lookup("/api/v1/users", "GET")
        assert result is not None
        assert result[0] == "/api/v1"

    def test_deeper_prefix_wins(self):
        tree = BaselineTree()
        tree.set("/", "GET", _baseline(_sig()))
        tree.set("/api", "GET", _baseline(_sig()))
        tree.set("/api/v1", "GET", _baseline(_sig()))
        result = tree.lookup("/api/v1/users/123", "GET")
        assert result[0] == "/api/v1"

    def test_no_match(self):
        tree = BaselineTree()
        assert tree.lookup("/anything", "GET") is None

    def test_exact_path_match(self):
        tree = BaselineTree()
        tree.set("/admin", "GET", _baseline(_sig()))
        result = tree.lookup("/admin", "GET")
        assert result is not None
        assert result[0] == "/admin"

    def test_method_specific_baseline(self):
        tree = BaselineTree()
        get_bl = _baseline(_sig(content_type="text/html"))
        post_bl = _baseline(_sig(content_type="application/json"))
        tree.set("/", "GET", get_bl)
        tree.set("/", "POST", post_bl)
        get_result = tree.lookup("/api/users", "GET")
        post_result = tree.lookup("/api/users", "POST")
        assert get_result[1].signatures[0].content_type == "text/html"
        assert post_result[1].signatures[0].content_type == "application/json"

    def test_method_fallback_to_get(self):
        tree = BaselineTree()
        tree.set("/", "GET", _baseline(_sig()))
        # PUT has no baseline, should fall back to GET
        result = tree.lookup("/api/users", "PUT")
        assert result is not None
        assert result[0] == "/"


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

class TestInferenceEngine:
    @pytest.mark.asyncio
    async def test_initialize_sets_root_baseline(self):
        engine = InferenceEngine()
        calls: list[str] = []

        async def mock_send(method, path, headers=None, body=None):
            calls.append(method)
            return _sig(status_code=404, content_type="text/html")

        await engine.initialize(mock_send)
        # 2 probes per method x 5 methods = 10 total
        assert len(calls) == 10
        assert set(calls) == {"GET", "POST", "PUT", "DELETE", "PATCH"}
        assert engine.tree.lookup("/", "GET") is not None
        assert engine.tree.lookup("/", "POST") is not None

    @pytest.mark.asyncio
    async def test_baseline_match_returns_none(self):
        """A response matching baseline should be filtered."""
        engine = InferenceEngine()
        # Pre-set root baseline
        engine.tree.set("/", "GET", _baseline(_sig(status_code=404, content_type="text/html",
                                                content_length=50)))

        route = Route(template_path="/random/path", method="GET")
        sig = _sig(status_code=404, content_type="text/html", content_length=50)

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="text/html", content_length=50)

        result = await engine.process(route, sig, "/random/path", mock_send)
        assert result is None

    @pytest.mark.asyncio
    async def test_status_deviation_returns_finding(self):
        """A response with different status should be a finding."""
        engine = InferenceEngine()
        engine.tree.set("/", "GET", _baseline(_sig(status_code=404, content_type="text/html")))

        route = Route(template_path="/api/v1/users", method="GET")
        sig = _sig(status_code=200, content_type="application/json",
                  content_length=100, word_count=5, line_count=1)

        probe_calls = []

        async def mock_send(method, path, headers=None, body=None):
            probe_calls.append((method, path))
            # Sibling returns something different from candidate (not a handler boundary)
            if "sibling" not in path and method == "GET" and path != "/api/v1/users":
                return _sig(status_code=404, content_type="text/html")
            # Method change probe
            return _sig(status_code=405, content_type="application/json",
                       content_length=30, word_count=3, line_count=1)

        result = await engine.process(route, sig, "/api/v1/users", mock_send)
        assert result is not None
        assert isinstance(result, Finding)
        assert "status:" in result.reason

    @pytest.mark.asyncio
    async def test_handler_boundary_discovery(self):
        """When sibling matches candidate, a new handler boundary is registered."""
        engine = InferenceEngine()
        engine.tree.set("/", "GET", _baseline(_sig(status_code=404, content_type="text/html")))

        route = Route(template_path="/api/v1/users", method="GET")
        # Candidate: JSON 404 (different from root HTML 404)
        candidate_sig = _sig(status_code=404, content_type="application/json",
                            content_length=25, word_count=3, line_count=1)

        async def mock_send(method, path, headers=None, body=None):
            # Sibling under /api/v1 returns same JSON 404 -> handler boundary
            return _sig(status_code=404, content_type="application/json",
                       content_length=25, word_count=3, line_count=1)

        result = await engine.process(route, candidate_sig, "/api/v1/users", mock_send)
        # Candidate matches the new handler baseline -> filtered
        assert result is None
        # Handler boundary should be registered
        assert engine.tree.lookup("/api/v1", "GET") is not None

    @pytest.mark.asyncio
    async def test_method_sensitive_405(self):
        """405 on method change probe -> high confidence finding."""
        engine = InferenceEngine()
        engine.tree.set("/", "GET", _baseline(_sig(status_code=404, content_type="text/html")))

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
        """Content-type change from baseline -> high confidence."""
        engine = InferenceEngine()
        engine.tree.set("/", "GET", _baseline(_sig(content_type="text/html")))

        route = Route(template_path="/api/health", method="GET")
        sig = _sig(status_code=200, content_type="application/json",
                  content_length=20, word_count=2, line_count=1)

        async def mock_send(method, path, headers=None, body=None):
            # Sibling differs from candidate
            return _sig(status_code=404, content_type="text/html")

        result = await engine.process(route, sig, "/api/health", mock_send)
        assert result is not None
        assert "content-type:" in result.reason
        assert result.confidence == "high"

    @pytest.mark.asyncio
    async def test_status_blacklist(self):
        engine = InferenceEngine(status_blacklist={500, 502})
        engine.tree.set("/", "GET", _baseline(_sig()))

        route = Route(template_path="/error", method="GET")
        sig = _sig(status_code=500)

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(route, sig, "/error", mock_send)
        assert result is None

    @pytest.mark.asyncio
    async def test_status_whitelist(self):
        engine = InferenceEngine(status_whitelist={200, 301})
        engine.tree.set("/", "GET", _baseline(_sig()))

        route = Route(template_path="/auth", method="GET")
        sig = _sig(status_code=401)

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(route, sig, "/auth", mock_send)
        assert result is None

    @pytest.mark.asyncio
    async def test_known_bad_site_filtered(self):
        engine = InferenceEngine()
        engine.tree.set("/", "GET", _baseline(_sig()))

        route = Route(template_path="/api", method="GET")
        sig = _sig(status_code=400, content_length=1555, word_count=82, line_count=12)

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(route, sig, "/api", mock_send)
        assert result is None

    @pytest.mark.asyncio
    async def test_new_headers_in_reason(self):
        """New headers not in baseline should appear in reason."""
        engine = InferenceEngine()
        engine.tree.set("/", "GET", _baseline(_sig(header_names=frozenset({"content-type", "date"}))))

        route = Route(template_path="/admin/dashboard", method="GET")
        sig = _sig(status_code=401, content_type="application/json",
                  content_length=60, word_count=4, line_count=1,
                  header_names=frozenset({"content-type", "date", "x-request-id"}))

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="text/html")

        result = await engine.process(route, sig, "/admin/dashboard", mock_send)
        assert result is not None
        assert "x-request-id" in result.reason

    @pytest.mark.asyncio
    async def test_deep_path_walks_intermediates(self):
        """A deep path like /foo/bar/bin/baz should probe /foo, /foo/bar, /foo/bar/bin."""
        engine = InferenceEngine()
        # Root: html 404
        engine.tree.set("/", "GET", _baseline(_sig(status_code=404, content_type="text/html",
                                                    content_length=50)))

        route = Route(template_path="/foo/bar/bin/baz", method="GET")
        # Candidate returns json 200 (real route behind two handler boundaries)
        candidate_sig = _sig(status_code=200, content_type="application/json",
                            content_length=80, word_count=5, line_count=1)

        probed_paths: list[str] = []

        async def mock_send(method, path, headers=None, body=None):
            probed_paths.append(path)
            # /foo/* returns html 404 (same as root — not a boundary)
            if path.startswith("/foo/") and not path.startswith("/foo/bar"):
                return _sig(status_code=404, content_type="text/html", content_length=50)
            # /foo/bar/* returns json 404 (new boundary at /foo/bar)
            if path.startswith("/foo/bar/") and not path.startswith("/foo/bar/bin/baz"):
                return _sig(status_code=404, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            # method change probe or anything else
            return _sig(status_code=405)

        result = await engine.process(route, candidate_sig, "/foo/bar/bin/baz", mock_send)

        # /foo/bar should be registered as a handler boundary
        assert engine.tree.lookup("/foo/bar/anything", "GET") is not None
        bar_node = engine.tree.lookup("/foo/bar/anything", "GET")
        assert bar_node[0] == "/foo/bar"

        # /foo should NOT be a boundary (same as root)
        foo_node = engine.tree.lookup("/foo/something", "GET")
        assert foo_node[0] == "/"  # falls back to root

        # Candidate should be a finding (200 json != 404 json baseline at /foo/bar)
        assert result is not None

    @pytest.mark.asyncio
    async def test_deep_path_filtered_at_intermediate(self):
        """If a deep candidate matches an intermediate baseline, it should be filtered."""
        engine = InferenceEngine()
        engine.tree.set("/", "GET", _baseline(_sig(status_code=404, content_type="text/html",
                                                    content_length=50)))

        route = Route(template_path="/api/v2/anything", method="GET")
        # Candidate returns json 404 — same as what /api/v2 handler will return
        candidate_sig = _sig(status_code=404, content_type="application/json",
                            content_length=25, word_count=3, line_count=1)

        async def mock_send(method, path, headers=None, body=None):
            # /api/* returns html 404 (same as root)
            if path.startswith("/api/") and not path.startswith("/api/v2"):
                return _sig(status_code=404, content_type="text/html", content_length=50)
            # /api/v2/* returns json 404 (handler boundary)
            return _sig(status_code=404, content_type="application/json",
                       content_length=25, word_count=3, line_count=1)

        result = await engine.process(route, candidate_sig, "/api/v2/anything", mock_send)
        # Candidate matches the /api/v2 baseline → filtered
        assert result is None
        # /api/v2 should be in the tree
        assert engine.tree.lookup("/api/v2/test", "GET")[0] == "/api/v2"
