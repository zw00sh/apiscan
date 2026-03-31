"""Tests for the unified scan tree: route ordering, baseline probing, and lookup."""

from __future__ import annotations

import pytest

from apiscan.inference import ResponseSignature, build_baseline
from apiscan.kite import Route
from apiscan.scantree import ScanTree


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
# Route ordering (depth-first, insertion order preserved)
# ---------------------------------------------------------------------------

class TestRouteOrdering:
    @pytest.mark.asyncio
    async def test_flat_preserves_order(self):
        tree = ScanTree([_route("/b"), _route("/a"), _route("/c")])
        paths = [r.template_path async for r in tree.walk(None)]
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

        paths = [r.template_path async for r in tree.walk(mock_send)]
        assert paths.index("/api") < paths.index("/api/v1")
        assert paths.index("/api/v1") < paths.index("/api/v1/users")

    @pytest.mark.asyncio
    async def test_siblings_preserve_insertion_order(self):
        tree = ScanTree([
            _route("/api/users"),
            _route("/api/health"),
            _route("/api/orders"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        paths = [r.template_path async for r in tree.walk(mock_send)]
        assert paths == ["/api/users", "/api/health", "/api/orders"]

    @pytest.mark.asyncio
    async def test_extensions_are_siblings(self):
        tree = ScanTree([_route("/files"), _route("/files.html"), _route("/files.zip")])
        paths = [r.template_path async for r in tree.walk(None)]
        assert paths == ["/files", "/files.html", "/files.zip"]

    @pytest.mark.asyncio
    async def test_children_after_parent(self):
        tree = ScanTree([
            _route("/files/cache/"),
            _route("/files"),
            _route("/files/tmp/"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        paths = [r.template_path async for r in tree.walk(mock_send)]
        assert paths.index("/files") < paths.index("/files/cache/")
        assert paths.index("/files") < paths.index("/files/tmp/")

    def test_count(self):
        tree = ScanTree([_route("/a"), _route("/b"), _route("/c")])
        assert len(tree) == 3

    def test_empty(self):
        tree = ScanTree()
        assert len(tree) == 0

    @pytest.mark.asyncio
    async def test_multiple_methods_same_path(self):
        tree = ScanTree([_route("/api/users", "GET"), _route("/api/users", "POST")])
        paths = [(r.template_path, r.method) async for r in tree.walk(None)]
        assert paths == [("/api/users", "GET"), ("/api/users", "POST")]


# ---------------------------------------------------------------------------
# Baseline storage and lookup
# ---------------------------------------------------------------------------

class TestBaselineLookup:
    def test_root_baseline(self):
        tree = ScanTree()
        bl = build_baseline([_sig()])
        tree.set_baseline("/", "GET", bl)
        result = tree.lookup_baseline("/api/users", "GET")
        assert result is not None
        assert result[0] == "/"

    def test_deeper_prefix_wins(self):
        tree = ScanTree([_route("/api/v1/users")])
        root_bl = build_baseline([_sig(content_type="text/html")])
        api_bl = build_baseline([_sig(content_type="application/json")])
        tree.set_baseline("/", "GET", root_bl)
        tree.set_baseline("/api/v1", "GET", api_bl)
        result = tree.lookup_baseline("/api/v1/users", "GET")
        assert result[0] == "/api/v1"
        assert result[1].signatures[0].content_type == "application/json"

    def test_method_specific(self):
        tree = ScanTree()
        get_bl = build_baseline([_sig(content_type="text/html")])
        post_bl = build_baseline([_sig(content_type="application/json")])
        tree.set_baseline("/", "GET", get_bl)
        tree.set_baseline("/", "POST", post_bl)
        assert tree.lookup_baseline("/x", "GET")[1].signatures[0].content_type == "text/html"
        assert tree.lookup_baseline("/x", "POST")[1].signatures[0].content_type == "application/json"

    def test_method_fallback_to_get(self):
        tree = ScanTree()
        tree.set_baseline("/", "GET", build_baseline([_sig()]))
        result = tree.lookup_baseline("/x", "PUT")
        assert result is not None

    def test_no_baseline(self):
        tree = ScanTree()
        assert tree.lookup_baseline("/x", "GET") is None


# ---------------------------------------------------------------------------
# Prefix probing during walk
# ---------------------------------------------------------------------------

class TestPrefixProbing:
    @pytest.mark.asyncio
    async def test_empty_intermediate_probed(self):
        """An intermediate node with no routes should be probed for a baseline."""
        # Wordlist has /api/v1/users but not /api or /api/v1
        tree = ScanTree([_route("/api/v1/users")])
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        probe_prefixes: list[str] = []

        async def mock_send(method, path, headers=None, body=None):
            probe_prefixes.append(path)
            if path.startswith("/api/v1/"):
                return _sig(status_code=404, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        routes = [r async for r in tree.walk(mock_send)]
        assert len(routes) == 1

        # /api/v1 should have a baseline (json, different from root html)
        result = tree.lookup_baseline("/api/v1/users", "GET")
        assert result is not None
        assert result[0] == "/api/v1"

    @pytest.mark.asyncio
    async def test_same_handler_not_registered(self):
        """If intermediate probe matches ancestor baseline, no new baseline is set."""
        tree = ScanTree([_route("/foo/bar")])
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html", content_length=50),
        ])

        async def mock_send(method, path, headers=None, body=None):
            # /foo/* returns same as root
            return _sig(status_code=404, content_type="text/html", content_length=50)

        _ = [r async for r in tree.walk(mock_send)]
        # /foo should not have its own baseline
        result = tree.lookup_baseline("/foo/bar", "GET")
        assert result[0] == "/"
