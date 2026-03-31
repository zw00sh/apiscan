"""Tests for the unified scan tree: route ordering, baseline probing, and walk."""

from __future__ import annotations

import pytest

from apiscan.inference import ResponseSignature, build_baseline
from apiscan.kite import Route
from apiscan.scantree import BoundaryProbe, ScanTree


def _route(path: str, method: str = "GET") -> Route:
    return Route(template_path=path, method=method)


def _sig(
    status_code: int = 404,
    content_type: str = "text/html",
    content_length: int = 50,
    **kw,
) -> ResponseSignature:
    defaults = dict(
        adjusted_content_length=40, adjustment_scale=1,
        word_count=10, line_count=2, header_names=frozenset(),
    )
    defaults.update(kw)
    return ResponseSignature(
        status_code=status_code, content_type=content_type,
        content_length=content_length, **defaults,
    )


# ---------------------------------------------------------------------------
# Route ordering
# ---------------------------------------------------------------------------

class TestRouteOrdering:
    @pytest.mark.asyncio
    async def test_flat_preserves_order(self):
        tree = ScanTree([_route("/b"), _route("/a"), _route("/c")])
        items = [i async for i in tree.walk(None)]
        paths = [r.template_path for r in items if isinstance(r, Route)]
        assert paths == ["/b", "/a", "/c"]

    @pytest.mark.asyncio
    async def test_parent_before_children(self):
        tree = ScanTree([
            _route("/api/v1/users"),
            _route("/api"),
            _route("/api/v1"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        items = [i async for i in tree.walk(mock_send)]
        routes = [r for r in items if isinstance(r, Route)]
        paths = [r.template_path for r in routes]
        assert paths.index("/api") < paths.index("/api/v1")
        assert paths.index("/api/v1") < paths.index("/api/v1/users")

    @pytest.mark.asyncio
    async def test_siblings_preserve_insertion_order(self):
        tree = ScanTree([_route("/api/users"), _route("/api/health"), _route("/api/orders")])

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        items = [i async for i in tree.walk(mock_send)]
        paths = [r.template_path for r in items if isinstance(r, Route)]
        assert paths == ["/api/users", "/api/health", "/api/orders"]

    @pytest.mark.asyncio
    async def test_extensions_are_siblings(self):
        tree = ScanTree([_route("/files"), _route("/files.html"), _route("/files.zip")])
        items = [i async for i in tree.walk(None)]
        paths = [r.template_path for r in items if isinstance(r, Route)]
        assert paths == ["/files", "/files.html", "/files.zip"]

    @pytest.mark.asyncio
    async def test_children_after_parent(self):
        tree = ScanTree([_route("/files/cache/"), _route("/files"), _route("/files/tmp/")])

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        items = [i async for i in tree.walk(mock_send)]
        paths = [r.template_path for r in items if isinstance(r, Route)]
        assert paths.index("/files") < paths.index("/files/cache/")
        assert paths.index("/files") < paths.index("/files/tmp/")

    def test_count(self):
        assert len(ScanTree([_route("/a"), _route("/b")])) == 2

    def test_empty(self):
        assert len(ScanTree()) == 0

    @pytest.mark.asyncio
    async def test_multiple_methods_same_path(self):
        tree = ScanTree([_route("/api/users", "GET"), _route("/api/users", "POST")])
        items = [i async for i in tree.walk(None)]
        pairs = [(r.template_path, r.method) for r in items if isinstance(r, Route)]
        assert pairs == [("/api/users", "GET"), ("/api/users", "POST")]


# ---------------------------------------------------------------------------
# Baseline lookup
# ---------------------------------------------------------------------------

class TestBaselineLookup:
    def test_root_baseline(self):
        tree = ScanTree()
        tree.set_baseline("/", "GET", build_baseline([_sig()]))
        assert tree.lookup_baseline("/api/users", "GET") is not None
        assert tree.lookup_baseline("/api/users", "GET")[0] == "/"

    def test_deeper_prefix_wins(self):
        tree = ScanTree([_route("/api/v1/users")])
        tree.set_baseline("/", "GET", build_baseline([_sig(content_type="text/html")]))
        tree.set_baseline("/api/v1", "GET", build_baseline([_sig(content_type="application/json")]))
        result = tree.lookup_baseline("/api/v1/users", "GET")
        assert result[0] == "/api/v1"

    def test_method_specific(self):
        tree = ScanTree()
        tree.set_baseline("/", "GET", build_baseline([_sig(content_type="text/html")]))
        tree.set_baseline("/", "POST", build_baseline([_sig(content_type="application/json")]))
        assert tree.lookup_baseline("/x", "GET")[1].signatures[0].content_type == "text/html"
        assert tree.lookup_baseline("/x", "POST")[1].signatures[0].content_type == "application/json"

    def test_method_fallback_to_get_at_root(self):
        tree = ScanTree()
        tree.set_baseline("/", "GET", build_baseline([_sig()]))
        assert tree.lookup_baseline("/x", "PUT") is not None

    def test_no_baseline(self):
        assert ScanTree().lookup_baseline("/x", "GET") is None


# ---------------------------------------------------------------------------
# Prefix probing during walk
# ---------------------------------------------------------------------------

class TestPrefixProbing:
    @pytest.mark.asyncio
    async def test_empty_intermediate_probed(self):
        tree = ScanTree([_route("/api/v1/users")])
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/v1/"):
                return _sig(status_code=404, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        items = [i async for i in tree.walk(mock_send)]

        # Should have BoundaryProbe events for /api/v1
        boundaries = [i for i in items if isinstance(i, BoundaryProbe)]
        assert any(bp.prefix == "/api/v1" for bp in boundaries)

        # Baseline should be registered
        result = tree.lookup_baseline("/api/v1/users", "GET")
        assert result[0] == "/api/v1"

    @pytest.mark.asyncio
    async def test_same_handler_not_registered(self):
        tree = ScanTree([_route("/foo/bar")])
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html", content_length=50),
        ])

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="text/html", content_length=50)

        items = [i async for i in tree.walk(mock_send)]

        # No boundary probes — same handler as root
        boundaries = [i for i in items if isinstance(i, BoundaryProbe)]
        assert len(boundaries) == 0
        assert tree.lookup_baseline("/foo/bar", "GET")[0] == "/"

    @pytest.mark.asyncio
    async def test_boundary_probes_before_routes(self):
        """BoundaryProbe events should come before routes at the same node."""
        tree = ScanTree([_route("/api/v1/users")])
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/v1/"):
                return _sig(status_code=404, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        items = [i async for i in tree.walk(mock_send)]
        # Find first BoundaryProbe and first Route
        first_bp = next((i, idx) for idx, i in enumerate(items) if isinstance(i, BoundaryProbe))
        first_route = next((i, idx) for idx, i in enumerate(items) if isinstance(i, Route))
        assert first_bp[1] < first_route[1]
