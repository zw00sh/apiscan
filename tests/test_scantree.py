"""Tests for the scan tree: baseline storage, prefix probing, recursion."""

from __future__ import annotations

import pytest

from apiscan.inference import ResponseSignature, build_baseline
from apiscan.kite import Route
from apiscan.scantree import BoundaryGroup, BoundaryProbe, ScanTree


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
# Initialization
# ---------------------------------------------------------------------------

class TestInitialization:
    @pytest.mark.asyncio
    async def test_initialize_only_random_probes(self):
        """Initialization should only send random-path probes."""
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
        """Root baseline should have stable fields when target returns consistent responses."""
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

        group, injected = await tree.probe_prefix("/api/v1", mock_send)
        assert group is not None
        assert group.prefix == "/api/v1"
        assert len(group.probes) >= 1
        assert tree.lookup_baseline("/api/v1/users", "GET")[0] == "/api/v1"

    @pytest.mark.asyncio
    async def test_same_handler_no_boundary(self):
        """When probe matches ancestor baseline, no boundary registered."""
        tree = ScanTree([_route("/foo/bar")])
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html", content_length=50),
        ])

        async def mock_send(method, path, headers=None, body=None):
            return _sig(status_code=404, content_type="text/html", content_length=50)

        group, injected = await tree.probe_prefix("/foo", mock_send)
        assert group is None
        assert tree.lookup_baseline("/foo/bar", "GET")[0] == "/"

    @pytest.mark.asyncio
    async def test_probe_prefix_standalone(self):
        """probe_prefix works on paths with no children in the tree."""
        tree = ScanTree()
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        group, injected = await tree.probe_prefix("/api", mock_send)
        assert group is not None
        assert group.prefix == "/api"
        assert tree.lookup_baseline("/api/anything", "GET")[0] == "/api"

    @pytest.mark.asyncio
    async def test_probe_prefix_idempotent(self):
        """Calling probe_prefix twice should not re-probe."""
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

        group1, _ = await tree.probe_prefix("/api", mock_send)
        assert group1 is not None
        probes_after_first = probe_count

        group2, _ = await tree.probe_prefix("/api", mock_send)
        assert group2 is None
        assert probe_count == probes_after_first


# ---------------------------------------------------------------------------
# Recursion
# ---------------------------------------------------------------------------

class TestRecursion:
    def test_infer_depth(self):
        tree = ScanTree()
        tree._prefix_depth["/api"] = 0
        tree._prefix_depth["/api/v1"] = 1

        assert tree._infer_depth("/api/v1/users") == 2
        assert tree._infer_depth("/api/health") == 1
        assert tree._infer_depth("/unknown/path") == 0

    @pytest.mark.asyncio
    async def test_probe_prefix_with_recursion(self):
        """probe_prefix with recurse=True should inject and return routes."""
        wordlist = [_route("/users"), _route("/health")]
        tree = ScanTree(recurse=True, max_depth=2, wordlist=wordlist)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        group, injected = await tree.probe_prefix("/api", mock_send, depth=0)
        assert group is not None
        assert len(injected) == 2
        assert any(r.template_path == "/api/users" for r in injected)
        assert any(r.template_path == "/api/health" for r in injected)

        # Routes also inserted into tree
        node = tree._resolve("/api/users")
        assert node is not None
        assert len(node.routes) == 1

    @pytest.mark.asyncio
    async def test_recursion_respects_max_depth(self):
        """probe_prefix should not inject routes beyond max_depth."""
        wordlist = [_route("/child")]
        tree = ScanTree(recurse=True, max_depth=1, wordlist=wordlist)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/a/"):
                return _sig(status_code=403, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        # Depth 0: boundary at /a → injects /a/child
        group, injected = await tree.probe_prefix("/a", mock_send, depth=0)
        assert group is not None
        assert len(injected) == 1
        assert injected[0].template_path == "/a/child"

        # Depth 1: boundary at /a/child → max_depth reached, no injection
        group2, injected2 = await tree.probe_prefix("/a/child", mock_send, depth=1)
        assert len(injected2) == 0  # max_depth prevents recursion

    @pytest.mark.asyncio
    async def test_dedup_prevents_duplicate_injection(self):
        """Recursive injection should not create routes already seen."""
        wordlist = [_route("/users")]
        tree = ScanTree(recurse=True, max_depth=2, wordlist=wordlist)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])
        # Pre-insert /api/users
        tree.insert(_route("/api/users"))

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        group, injected = await tree.probe_prefix("/api", mock_send, depth=0)
        # /api/users already exists — should not be in injected
        assert len(injected) == 0

    @pytest.mark.asyncio
    async def test_no_recursion_by_default(self):
        """Without recurse=True, probe_prefix should not inject routes."""
        wordlist = [_route("/users")]
        tree = ScanTree(wordlist=wordlist)  # recurse defaults to False
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        group, injected = await tree.probe_prefix("/api", mock_send, depth=0)
        assert group is not None
        assert len(injected) == 0

    def test_skip_prefix(self):
        """skip_prefix should add to the skip set."""
        tree = ScanTree()
        tree.skip_prefix("/skip")
        assert "/skip" in tree._skip
