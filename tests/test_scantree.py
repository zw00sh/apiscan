"""Tests for the scan tree: baseline storage and prefix probing."""

from __future__ import annotations

import pytest

from apiscan.inference import ResponseSignature, build_baseline
from apiscan.kite import Route
from apiscan.scantree import BoundaryGroup, ScanTree


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
# Tree structure
# ---------------------------------------------------------------------------

class TestTreeStructure:
    def test_count(self):
        assert len(ScanTree([_route("/a"), _route("/b")])) == 2

    def test_empty(self):
        assert len(ScanTree()) == 0

    def test_insert_creates_nodes(self):
        tree = ScanTree([_route("/api/v1/users")])
        assert tree._resolve("/api") is not None
        assert tree._resolve("/api/v1") is not None
        assert tree._resolve("/api/v1/users") is not None

    def test_resolve_or_create(self):
        tree = ScanTree()
        node = tree._resolve_or_create("/new/path")
        assert node is not None
        assert tree._resolve("/new/path") is not None

    def test_insert_tracks_seen(self):
        tree = ScanTree([_route("/a"), _route("/b", "POST")])
        assert ("/a", "GET") in tree._seen
        assert ("/b", "POST") in tree._seen
        assert ("/c", "GET") not in tree._seen


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

    def test_ancestor_baselines(self):
        tree = ScanTree([_route("/api/v1/users")])
        root_bl = build_baseline([_sig(content_type="text/html")])
        api_bl = build_baseline([_sig(content_type="application/json")])
        tree.set_baseline("/", "GET", root_bl)
        tree.set_baseline("/api", "GET", api_bl)

        baselines = tree.ancestor_baselines("/api/v1", "GET")
        assert api_bl in baselines
        assert root_bl in baselines


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInitialization:
    @pytest.mark.asyncio
    async def test_initialize_only_random_probes(self):
        tree = ScanTree()
        probed_paths: list[str] = []

        async def mock_send(method, path, headers=None, body=None):
            probed_paths.append(path)
            return _sig(status_code=404, content_type="application/json", content_length=48)

        await tree.initialize(mock_send)

        for path in probed_paths:
            assert "%2e" not in path
            assert ".php" not in path
            segments = [s for s in path.split("/") if s]
            assert len(segments) == 1

    @pytest.mark.asyncio
    async def test_initialize_baseline_stable(self):
        tree = ScanTree()

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="application/json", content_length=48)

        await tree.initialize(mock_send)

        bl = tree._root.baselines.get("GET")
        assert bl is not None
        assert "status_code" in bl.stable_fields
        assert "content_type" in bl.stable_fields
        assert "content_length" in bl.stable_fields


# ---------------------------------------------------------------------------
# Prefix probing
# ---------------------------------------------------------------------------

class TestPrefixProbing:
    @pytest.mark.asyncio
    async def test_boundary_detection(self):
        """probe_prefix should detect handler boundaries."""
        tree = ScanTree([_route("/api/v1/users")])
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/v1/"):
                return _sig(status_code=404, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        group = await tree.probe_prefix("/api/v1", mock_send)
        assert group is not None
        assert group.prefix == "/api/v1"
        assert len(group.probes) >= 1
        assert tree.lookup_baseline("/api/v1/users", "GET")[0] == "/api/v1"

    @pytest.mark.asyncio
    async def test_same_handler_no_boundary(self):
        tree = ScanTree([_route("/foo/bar")])
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html", content_length=50),
        ])

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="text/html", content_length=50)

        group = await tree.probe_prefix("/foo", mock_send)
        assert group is None
        assert tree.lookup_baseline("/foo/bar", "GET")[0] == "/"

    @pytest.mark.asyncio
    async def test_probe_prefix_standalone(self):
        """probe_prefix works on paths not in the tree."""
        tree = ScanTree()
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        group = await tree.probe_prefix("/api", mock_send)
        assert group is not None
        assert tree.lookup_baseline("/api/anything", "GET")[0] == "/api"

    @pytest.mark.asyncio
    async def test_probe_prefix_idempotent(self):
        tree = ScanTree()
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])
        probe_count = 0

        async def mock_send(method, path, headers=None, body=None):
            nonlocal probe_count
            probe_count += 1
            if path.startswith("/api/"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        group1 = await tree.probe_prefix("/api", mock_send)
        assert group1 is not None
        probes_after_first = probe_count

        group2 = await tree.probe_prefix("/api", mock_send)
        assert group2 is None
        assert probe_count == probes_after_first
