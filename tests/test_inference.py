"""Unit tests for the inference engine (no HTTP, mock send_fn)."""

from __future__ import annotations

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
from apiscan.scantree import BoundaryProbe, ScanTree


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
        status_code=status_code, content_type=content_type,
        content_length=content_length, adjusted_content_length=adjusted_content_length,
        adjustment_scale=adjustment_scale, word_count=word_count,
        line_count=line_count, header_names=header_names or frozenset(),
    )


def _baseline(*sigs: ResponseSignature) -> Baseline:
    return build_baseline(list(sigs))


def _make_engine(**kw) -> tuple[ScanTree, InferenceEngine]:
    tree = ScanTree()
    engine = InferenceEngine(tree=tree, **kw)
    return tree, engine


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

    def test_content_type_parsing(self):
        sig = compute_signature(200, {"content-type": "application/json; charset=utf-8"}, b"{}", "/")
        assert sig.content_type == "application/json"

    def test_path_adjustment(self):
        body = b"error: testpath not found at testpath"
        sig = compute_signature(404, {}, body, "/testpath")
        assert sig.adjustment_scale == 2

    def test_header_names_lowercase(self):
        sig = compute_signature(200, {"Content-Type": "text/html", "X-Request-Id": "abc"}, b"", "/")
        assert "content-type" in sig.header_names
        assert "x-request-id" in sig.header_names

    def test_empty_body(self):
        sig = compute_signature(204, {}, b"", "/")
        assert sig.content_length == 0
        assert sig.word_count == 0


# ---------------------------------------------------------------------------
# build_baseline
# ---------------------------------------------------------------------------

class TestBuildBaseline:
    def test_single_signature(self):
        bl = _baseline(_sig())
        assert "status_code" in bl.stable_fields
        assert "content_type" in bl.stable_fields

    def test_stable_detection(self):
        bl = _baseline(_sig(content_length=50), _sig(content_length=50))
        assert "content_length" in bl.stable_fields

    def test_unstable_detection(self):
        bl = _baseline(_sig(content_length=50), _sig(content_length=75))
        assert "content_length" not in bl.stable_fields
        assert "status_code" in bl.stable_fields

    def test_empty(self):
        bl = build_baseline([])
        assert len(bl.signatures) == 0


# ---------------------------------------------------------------------------
# matches_baseline
# ---------------------------------------------------------------------------

class TestMatchesBaseline:
    def test_exact_length_match(self):
        bl = _baseline(_sig())
        assert matches_baseline(_sig(), bl, 10) is not None

    def test_scaled_length_match(self):
        ref = _sig(adjusted_content_length=40, adjustment_scale=2)
        bl = _baseline(ref)
        candidate = _sig(content_length=40 + 2 * 8)
        assert matches_baseline(candidate, bl, 8) is not None

    def test_word_line_match(self):
        bl = _baseline(_sig(word_count=10, line_count=2))
        candidate = _sig(content_length=999, word_count=10, line_count=2)
        assert matches_baseline(candidate, bl, 5) is not None

    def test_no_match(self):
        bl = _baseline(_sig())
        candidate = _sig(status_code=200, content_type="application/json",
                        content_length=100, word_count=5, line_count=1)
        assert matches_baseline(candidate, bl, 5) is None

    def test_different_status_no_match(self):
        bl = _baseline(_sig(status_code=404))
        assert matches_baseline(_sig(status_code=200, content_length=50), bl, 5) is None

    def test_403_vs_404_no_match(self):
        bl = _baseline(_sig(status_code=404, content_length=50))
        assert matches_baseline(_sig(status_code=403, content_length=50), bl, 5) is None

    def test_content_type_change_breaks_match(self):
        bl = _baseline(_sig(content_type="text/html"))
        assert matches_baseline(_sig(content_type="application/json", content_length=50), bl, 5) is None

    def test_unstable_field_ignored(self):
        bl = _baseline(_sig(content_length=50), _sig(content_length=75))
        candidate = _sig(content_length=50, word_count=10, line_count=2)
        assert matches_baseline(candidate, bl, 5) is not None

    def test_empty_baseline(self):
        assert matches_baseline(_sig(), Baseline(), 5) is None


# ---------------------------------------------------------------------------
# is_known_bad_site
# ---------------------------------------------------------------------------

class TestKnownBadSites:
    def test_google_bad_request(self):
        assert is_known_bad_site(_sig(status_code=400, content_length=1555, word_count=82, line_count=12))

    def test_aws_gateway(self):
        assert is_known_bad_site(_sig(status_code=403, content_length=54, word_count=6, line_count=1,
                                     header_names=frozenset({"x-amzn-requestid"})))

    def test_normal_response(self):
        assert not is_known_bad_site(_sig(status_code=200, content_length=100, word_count=10, line_count=5))


# ---------------------------------------------------------------------------
# InferenceEngine.classify_boundary
# ---------------------------------------------------------------------------

class TestClassifyBoundary:
    def test_boundary_creates_finding(self):
        tree, engine = _make_engine()
        probe = BoundaryProbe(
            prefix="/admin", method="GET",
            signature=_sig(status_code=403, content_type="application/json"),
            ancestor_signature=_sig(status_code=404, content_type="text/html"),
        )
        finding = engine.classify_boundary(probe)
        assert finding is not None
        assert finding.route.method == "GET"
        assert finding.route.template_path == "/admin"
        assert "probe:" in finding.reason

    def test_boundary_filtered_by_blacklist(self):
        tree, engine = _make_engine(status_blacklist={403})
        probe = BoundaryProbe(
            prefix="/admin", method="GET",
            signature=_sig(status_code=403),
            ancestor_signature=_sig(status_code=404),
        )
        assert engine.classify_boundary(probe) is None

    def test_boundary_with_status_deviation(self):
        tree, engine = _make_engine()
        probe = BoundaryProbe(
            prefix="/users", method="DELETE",
            signature=_sig(status_code=500, content_type="application/json"),
            ancestor_signature=_sig(status_code=404, content_type="application/json"),
        )
        finding = engine.classify_boundary(probe)
        assert finding is not None
        assert "500" in finding.reason


# ---------------------------------------------------------------------------
# InferenceEngine.process
# ---------------------------------------------------------------------------

class TestInferenceProcess:
    @pytest.mark.asyncio
    async def test_baseline_match_filtered(self):
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(_sig(status_code=404, content_type="text/html",
                                                      content_length=50)))
        route = Route(template_path="/random/path", method="GET")

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="text/html", content_length=50)

        result = await engine.process(route, _sig(status_code=404, content_type="text/html",
                                                   content_length=50), "/random/path", mock_send)
        assert result == []

    @pytest.mark.asyncio
    async def test_status_deviation_returns_finding(self):
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(_sig(status_code=404, content_type="text/html")))

        route = Route(template_path="/api/v1/users", method="GET")
        sig = _sig(status_code=200, content_type="application/json",
                  content_length=100, word_count=5, line_count=1)

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=405)

        result = await engine.process(route, sig, "/api/v1/users", mock_send)
        assert len(result) == 1
        assert "status:" in result[0].reason

    @pytest.mark.asyncio
    async def test_handler_boundary_filters_children(self):
        tree, engine = _make_engine()
        tree.insert(Route(template_path="/api/v1/users", method="GET"))
        tree.set_baseline("/", "GET", _baseline(_sig(status_code=404, content_type="text/html")))
        tree.set_baseline("/api/v1", "GET", _baseline(
            _sig(status_code=404, content_type="application/json",
                 content_length=25, word_count=3, line_count=1)))

        route = Route(template_path="/api/v1/users", method="GET")
        candidate = _sig(status_code=404, content_type="application/json",
                        content_length=25, word_count=3, line_count=1)

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(route, candidate, "/api/v1/users", mock_send)
        assert result == []

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
        assert len(result) == 1
        assert "405" in result[0].reason
        assert result[0].confidence == "high"

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
        assert len(result) == 1
        assert "content-type:" in result[0].reason
        assert result[0].confidence == "high"

    @pytest.mark.asyncio
    async def test_status_blacklist(self):
        tree, engine = _make_engine(status_blacklist={500})
        tree.set_baseline("/", "GET", _baseline(_sig()))

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(
            Route(template_path="/error", method="GET"),
            _sig(status_code=500), "/error", mock_send)
        assert result == []

    @pytest.mark.asyncio
    async def test_status_whitelist(self):
        tree, engine = _make_engine(status_whitelist={200, 301})
        tree.set_baseline("/", "GET", _baseline(_sig()))

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(
            Route(template_path="/auth", method="GET"),
            _sig(status_code=401), "/auth", mock_send)
        assert result == []

    @pytest.mark.asyncio
    async def test_known_bad_site_filtered(self):
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(_sig()))

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        result = await engine.process(
            Route(template_path="/api", method="GET"),
            _sig(status_code=400, content_length=1555, word_count=82, line_count=12),
            "/api", mock_send)
        assert result == []

    @pytest.mark.asyncio
    async def test_new_headers_in_reason(self):
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(_sig(header_names=frozenset({"content-type", "date"}))))

        sig = _sig(status_code=401, content_type="application/json",
                  content_length=60, word_count=4, line_count=1,
                  header_names=frozenset({"content-type", "date", "x-request-id"}))

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="text/html")

        result = await engine.process(
            Route(template_path="/admin/dashboard", method="GET"),
            sig, "/admin/dashboard", mock_send)
        assert len(result) == 1
        assert "x-request-id" in result[0].reason

    @pytest.mark.asyncio
    async def test_alternate_methods_grouped(self):
        """Alternate method findings should be grouped by response fingerprint."""
        tree, engine = _make_engine(methods=["GET", "POST", "PUT"])
        tree.set_baseline("/", "GET", _baseline(_sig(status_code=404, content_type="text/html",
                                                      content_length=50)))
        tree.set_baseline("/", "POST", _baseline(_sig(status_code=404, content_type="text/html",
                                                       content_length=50)))
        tree.set_baseline("/", "PUT", _baseline(_sig(status_code=404, content_type="text/html",
                                                      content_length=50)))

        route = Route(template_path="/files/import", method="GET")
        candidate = _sig(status_code=404, content_type="text/html", content_length=50)

        async def mock_send(method, path, headers=None, body=None):
            if method in ("POST", "PUT"):
                return _sig(status_code=400, content_type="application/json",
                           content_length=86, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html", content_length=50)

        result = await engine.process(route, candidate, "/files/import", mock_send)
        assert len(result) == 1  # POST and PUT grouped
        assert "POST" in result[0].reason
        assert "PUT" in result[0].reason

    @pytest.mark.asyncio
    async def test_skip_alternate_methods_when_boundary_covers_path(self):
        """If a boundary probe already established per-method baselines at the
        route's prefix, alternate method probing on a baseline-matched route
        should not re-report what the boundary already discovered.

        Example: boundary probe finds GET /users -> 403, POST /users -> 404.
        Route GET /users/add matches GET baseline (403). Alternate method probe
        sends POST /users/add -> 404, which matches POST baseline at /users.
        Should NOT report POST /users/add as a finding since it just matches
        the POST baseline.
        """
        tree, engine = _make_engine()
        tree.insert(Route(template_path="/users/add", method="GET"))
        # Root baselines
        tree.set_baseline("/", "GET", _baseline(_sig(status_code=404, content_type="text/html")))
        tree.set_baseline("/", "POST", _baseline(_sig(status_code=404, content_type="text/html")))
        # Boundary baselines at /users (as if tree probing discovered them)
        tree.set_baseline("/users", "GET", _baseline(
            _sig(status_code=403, content_type="application/json", content_length=131)))
        tree.set_baseline("/users", "POST", _baseline(
            _sig(status_code=404, content_type="application/json", content_length=111)))

        route = Route(template_path="/users/add", method="GET")
        candidate = _sig(status_code=403, content_type="application/json", content_length=131)

        async def mock_send(method, path, headers=None, body=None):
            if method == "POST":
                # Matches POST baseline at /users — should NOT be a finding
                return _sig(status_code=404, content_type="application/json", content_length=111)
            return _sig(status_code=403, content_type="application/json", content_length=131)

        result = await engine.process(route, candidate, "/users/add", mock_send)
        assert result == []

    @pytest.mark.asyncio
    async def test_ancestor_baseline_match_filters_fallthrough(self):
        """A response that deviates from its nearest baseline but matches an
        ancestor baseline is falling through to the default handler — not a
        real endpoint.

        Example: /books/v1/ baseline is 401/119B (auth gate).  A route like
        /books/v1/.terraform returns 404/205B — deviates from /books/v1/ but
        matches the root 404 baseline exactly.  Should be filtered.
        """
        tree, engine = _make_engine()
        # Insert route to create tree nodes for /books/v1/*
        tree.insert(Route(template_path="/books/v1/.terraform", method="GET"))
        # Root baseline: 404, text/html, 205 bytes
        root_sig = _sig(status_code=404, content_type="text/html",
                        content_length=205, word_count=35, line_count=7)
        tree.set_baseline("/", "GET", _baseline(root_sig))
        tree.set_baseline("/", "POST", _baseline(root_sig))
        # Boundary at /books/v1: 401, application/json, 119 bytes
        tree.set_baseline("/books/v1", "GET", _baseline(
            _sig(status_code=401, content_type="application/json",
                 content_length=119, word_count=16, line_count=7)))

        route = Route(template_path="/books/v1/.terraform", method="GET")
        # Response matches root baseline exactly
        candidate = _sig(status_code=404, content_type="text/html",
                         content_length=205, word_count=35, line_count=7)

        async def mock_send(method, path, headers=None, body=None):
            return root_sig

        result = await engine.process(route, candidate, "/books/v1/.terraform", mock_send)
        assert result == []

    @pytest.mark.asyncio
    async def test_ancestor_match_does_not_suppress_real_endpoints(self):
        """A response that deviates from both nearest AND ancestor baselines
        should still be reported as a finding.

        Example: root is 404/text/html, /api/ is 200/json.  /api/users returns
        401/json — deviates from /api/ baseline, does NOT match root (different
        content-type).  Should be a finding.
        """
        tree, engine = _make_engine()
        tree.set_baseline("/", "GET", _baseline(
            _sig(status_code=404, content_type="text/html",
                 content_length=205, word_count=35, line_count=7)))
        tree.set_baseline("/", "POST", _baseline(
            _sig(status_code=404, content_type="text/html",
                 content_length=205, word_count=35, line_count=7)))
        tree.set_baseline("/api", "GET", _baseline(
            _sig(status_code=200, content_type="application/json",
                 content_length=12, word_count=2, line_count=1)))

        route = Route(template_path="/api/users", method="GET")
        candidate = _sig(status_code=401, content_type="application/json",
                         content_length=60, word_count=4, line_count=1)

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=405)

        result = await engine.process(route, candidate, "/api/users", mock_send)
        assert len(result) == 1
        assert "405" in result[0].reason
