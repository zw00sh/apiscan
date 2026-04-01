"""Tests for the unified scan tree: route ordering, baseline probing, and walk."""

from __future__ import annotations

import asyncio

import pytest

from apiscan.inference import ResponseSignature, build_baseline
from apiscan.kite import Route
from apiscan.scantree import BoundaryGroup, BoundaryProbe, ScanTree


async def _collect_walk(tree, send_fn=None):
    """Helper: run tree.walk() and collect all items from the queue."""
    queue: asyncio.Queue = asyncio.Queue()
    await tree.walk(send_fn, queue)
    items = []
    while not queue.empty():
        items.append(queue.get_nowait())
    return items


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
    async def test_flat_all_present(self):
        tree = ScanTree([_route("/b"), _route("/a"), _route("/c")])
        items = await _collect_walk(tree)
        paths = [r.template_path for r in items if isinstance(r, Route)]
        # Siblings walked concurrently — order is nondeterministic
        assert set(paths) == {"/b", "/a", "/c"}

    @pytest.mark.asyncio
    async def test_parent_before_children(self):
        tree = ScanTree([
            _route("/api/v1/users"),
            _route("/api"),
            _route("/api/v1"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        items = await _collect_walk(tree, mock_send)
        routes = [r for r in items if isinstance(r, Route)]
        paths = [r.template_path for r in routes]
        assert paths.index("/api") < paths.index("/api/v1")
        assert paths.index("/api/v1") < paths.index("/api/v1/users")

    @pytest.mark.asyncio
    async def test_siblings_all_present(self):
        tree = ScanTree([_route("/api/users"), _route("/api/health"), _route("/api/orders")])

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        items = await _collect_walk(tree, mock_send)
        paths = [r.template_path for r in items if isinstance(r, Route)]
        # Siblings walked concurrently — order is nondeterministic
        assert set(paths) == {"/api/users", "/api/health", "/api/orders"}

    @pytest.mark.asyncio
    async def test_extensions_are_siblings(self):
        tree = ScanTree([_route("/files"), _route("/files.html"), _route("/files.zip")])
        items = await _collect_walk(tree)
        paths = [r.template_path for r in items if isinstance(r, Route)]
        # Siblings walked concurrently — order is nondeterministic
        assert set(paths) == {"/files", "/files.html", "/files.zip"}

    @pytest.mark.asyncio
    async def test_children_after_parent(self):
        tree = ScanTree([_route("/files/cache/"), _route("/files"), _route("/files/tmp/")])

        async def mock_send(method, path, headers=None, body=None):
            return _sig()

        items = await _collect_walk(tree, mock_send)
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
        items = await _collect_walk(tree)
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

        items = await _collect_walk(tree, mock_send)

        # Should have a BoundaryGroup for /api/v1
        groups = [i for i in items if isinstance(i, BoundaryGroup)]
        assert any(g.prefix == "/api/v1" for g in groups)

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

        items = await _collect_walk(tree, mock_send)

        # No boundary groups — same handler as root
        groups = [i for i in items if isinstance(i, BoundaryGroup)]
        assert len(groups) == 0
        assert tree.lookup_baseline("/foo/bar", "GET")[0] == "/"

    @pytest.mark.asyncio
    async def test_initialize_only_random_probes(self):
        """Initialization should only send random-path probes, not error shape probes.

        Error shape probes (/%2e%2e, .php, trailing slash) can return different
        responses that poison the baseline, making content_length and status_code
        unstable and causing false positives.
        """
        tree = ScanTree()
        probed_paths: list[str] = []

        async def mock_send(method, path, headers=None, body=None):
            probed_paths.append(path)
            return _sig(status_code=404, content_type="application/json", content_length=48)

        await tree.initialize(mock_send)

        # All probes should be random hex paths — no %2e%2e, .php, or trailing slash
        for path in probed_paths:
            assert "%2e" not in path, f"Error shape probe found: {path}"
            assert ".php" not in path, f"Error shape probe found: {path}"
            # Trailing slash check: only root-level random paths, not /{random}/
            segments = [s for s in path.split("/") if s]
            assert len(segments) == 1, f"Multi-segment probe found: {path}"

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

    @pytest.mark.asyncio
    async def test_boundary_probes_before_routes(self):
        """BoundaryGroup events should come before routes at the same node."""
        tree = ScanTree([_route("/api/v1/users")])
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/v1/"):
                return _sig(status_code=404, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        items = await _collect_walk(tree, mock_send)
        # Find first BoundaryGroup and first Route
        first_bg = next((i, idx) for idx, i in enumerate(items) if isinstance(i, BoundaryGroup))
        first_route = next((i, idx) for idx, i in enumerate(items) if isinstance(i, Route))
        assert first_bg[1] < first_route[1]


# ---------------------------------------------------------------------------
# Recursion
# ---------------------------------------------------------------------------

class TestRecursion:
    @pytest.mark.asyncio
    async def test_boundary_triggers_recursive_insertion(self):
        """When recursion is enabled and a boundary is found, the wordlist
        should be re-applied under the boundary prefix."""
        wordlist = [_route("/users"), _route("/health")]
        tree = ScanTree(wordlist, recurse=True, max_depth=2, wordlist=wordlist)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            # /api responds differently → boundary
            if path.startswith("/api/") and not path.startswith("/api/users") and not path.startswith("/api/health"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        # Insert a route under /api to trigger probing
        tree.insert(_route("/api/endpoint"))

        items = await _collect_walk(tree, mock_send)
        paths = [r.template_path for r in items if isinstance(r, Route)]

        # Should have original routes plus recursive routes under /api
        assert "/api/endpoint" in paths
        assert "/api/users" in paths
        assert "/api/health" in paths

    @pytest.mark.asyncio
    async def test_max_depth_limits_recursion(self):
        """Recursion should stop at max_depth."""
        wordlist = [_route("/sub")]
        tree = ScanTree(wordlist, recurse=True, max_depth=1, wordlist=wordlist)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        boundaries_seen: list[str] = []

        async def mock_send(method, path, headers=None, body=None):
            # Every prefix is a boundary (returns json instead of html)
            for seg in path.split("/"):
                if seg and len(seg) == 8:  # skip random probe segments
                    return _sig(status_code=200, content_type="application/json",
                               content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        # /a/sub — /a is probed, becomes boundary, recurses to /a/sub
        tree.insert(_route("/a/sub"))
        items = await _collect_walk(tree, mock_send)
        paths = [r.template_path for r in items if isinstance(r, Route)]

        # /a/sub exists in original, /a/sub/sub would be depth-1 recursion
        assert "/a/sub" in paths
        # depth-1 recursion from /a: adds /a/sub (already exists, deduped)
        # depth-2 recursion from /a/sub would add /a/sub/sub — should NOT exist
        assert "/a/sub/sub" not in paths

    @pytest.mark.asyncio
    async def test_no_recursion_by_default(self):
        """Without recurse=True, no recursive routes should be added."""
        wordlist = [_route("/users")]
        tree = ScanTree(wordlist)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        tree.insert(_route("/api/endpoint"))
        items = await _collect_walk(tree, mock_send)
        paths = [r.template_path for r in items if isinstance(r, Route)]

        assert "/api/endpoint" in paths
        assert "/users" in paths
        # /api/users should NOT exist — no recursion
        assert "/api/users" not in paths

    @pytest.mark.asyncio
    async def test_dedup_prevents_duplicate_routes(self):
        """Recursive insertion should not create routes that already exist."""
        wordlist = [_route("/users"), _route("/health")]
        tree = ScanTree(wordlist, recurse=True, max_depth=2, wordlist=wordlist)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/") and len(path.split("/")) <= 3:
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        # Manually insert /api/users — it should not be duplicated by recursion from /api
        tree.insert(_route("/api/users"))
        tree.insert(_route("/api/endpoint"))

        items = await _collect_walk(tree, mock_send)
        paths = [r.template_path for r in items if isinstance(r, Route)]

        # /api/users should appear exactly once
        assert paths.count("/api/users") == 1

    @pytest.mark.asyncio
    async def test_skip_prefix(self):
        """Skipped prefixes should not be walked."""
        wordlist = [_route("/users")]
        tree = ScanTree(wordlist, recurse=True, max_depth=2, wordlist=wordlist)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        tree.insert(_route("/api/endpoint"))
        tree.insert(_route("/skip/endpoint"))
        tree.skip_prefix("/skip")

        items = await _collect_walk(tree, mock_send)
        paths = [r.template_path for r in items if isinstance(r, Route)]

        assert "/api/endpoint" in paths
        assert "/skip/endpoint" not in paths

    @pytest.mark.asyncio
    async def test_probe_prefix_standalone(self):
        """probe_prefix can be called directly (as workers do) to discover
        boundaries at paths that have no children in the tree."""
        tree = ScanTree()
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        # /api has no children in the tree — would never be probed by _walk
        group = await tree.probe_prefix("/api", mock_send)
        assert group is not None
        assert group.prefix == "/api"
        assert len(group.probes) >= 1

        # Baseline should be registered
        result = tree.lookup_baseline("/api/anything", "GET")
        assert result is not None
        assert result[0] == "/api"

    @pytest.mark.asyncio
    async def test_probe_prefix_idempotent(self):
        """Calling probe_prefix twice on the same prefix should not re-probe."""
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
        assert group2 is None  # already probed — nothing new
        assert probe_count == probes_after_first  # no new HTTP requests

    def test_infer_depth(self):
        """_infer_depth should return parent depth + 1, or 0 if no parent known."""
        tree = ScanTree()
        tree._prefix_depth["/api"] = 0
        tree._prefix_depth["/api/v1"] = 1

        assert tree._infer_depth("/api/v1/users") == 2
        assert tree._infer_depth("/api/health") == 1
        assert tree._infer_depth("/unknown/path") == 0

    @pytest.mark.asyncio
    async def test_probe_prefix_with_recursion(self):
        """probe_prefix with recurse=True should inject wordlist routes."""
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

        group = await tree.probe_prefix("/api", mock_send, depth=0)
        assert group is not None

        # Recursive routes should be inserted into the tree
        node = tree._resolve("/api/users")
        assert node is not None
        assert len(node.routes) == 1
        assert node.routes[0].template_path == "/api/users"

        node2 = tree._resolve("/api/health")
        assert node2 is not None

    @pytest.mark.asyncio
    async def test_recursive_routes_are_walkable(self):
        """Routes injected by probe_prefix should appear in walk output."""
        wordlist = [_route("/users"), _route("/health")]
        tree = ScanTree([_route("/api/endpoint")], recurse=True, max_depth=2, wordlist=wordlist)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/api/") and "/endpoint" not in path:
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        items = await _collect_walk(tree, mock_send)
        paths = [r.template_path for r in items if isinstance(r, Route)]

        # Original route present
        assert "/api/endpoint" in paths
        # Recursive routes walked and present in output
        assert "/api/users" in paths
        assert "/api/health" in paths

    @pytest.mark.asyncio
    async def test_max_depth_strict(self):
        """Recursion should respect max_depth with distinct per-level responses."""
        wordlist = [_route("/child")]
        tree = ScanTree([_route("/a/original")], recurse=True, max_depth=1, wordlist=wordlist)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        # /a/* returns 403 json (boundary), /a/child/* returns 401 json (sub-boundary)
        async def mock_send(method, path, headers=None, body=None):
            if path.startswith("/a/child/"):
                return _sig(status_code=401, content_type="application/json",
                           content_length=30, word_count=4, line_count=1)
            if path.startswith("/a/"):
                return _sig(status_code=403, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        items = await _collect_walk(tree, mock_send)
        paths = [r.template_path for r in items if isinstance(r, Route)]

        # Depth 0: /a is boundary → injects /a/child
        assert "/a/child" in paths
        # Depth 1: /a/child could be boundary → but max_depth=1 prevents recursion
        # /a/child/child should NOT exist
        assert "/a/child/child" not in paths


# ---------------------------------------------------------------------------
# Lookahead
# ---------------------------------------------------------------------------

class TestLookahead:
    @pytest.mark.asyncio
    async def test_lookahead_discovers_hidden_boundary(self):
        """Lookahead should discover boundaries one level deeper than the tree."""
        # Flat wordlist — /users is a leaf, no children
        tree = ScanTree([_route("/users"), _route("/login")], lookahead=True)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])

        async def mock_send(method, path, headers=None, body=None):
            # /users/v1/* is a different handler
            if "/users/v1/" in path:
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        items = await _collect_walk(tree, mock_send)

        # Lookahead should have discovered /users/v1 as a boundary
        groups = [i for i in items if isinstance(i, BoundaryGroup)]
        assert any(g.prefix == "/users/v1" for g in groups)

        # Baseline should be registered
        result = tree.lookup_baseline("/users/v1/anything", "GET")
        assert result is not None
        assert result[0] == "/users/v1"

    @pytest.mark.asyncio
    async def test_lookahead_skips_when_boundary_found(self):
        """When standard probe finds a boundary at a prefix, lookahead
        should not fire at THAT prefix (it may fire at child nodes)."""
        tree = ScanTree([_route("/api/endpoint")], lookahead=True)
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])
        lookahead_prefixes: list[str] = []
        original_lookahead = tree._lookahead_prefix

        async def tracking_lookahead(prefix, send_fn, tracker=None, depth=0):
            lookahead_prefixes.append(prefix)
            return await original_lookahead(prefix, send_fn, tracker, depth)

        tree._lookahead_prefix = tracking_lookahead

        async def mock_send(method, path, headers=None, body=None):
            # /api/* is a boundary
            if path.startswith("/api/"):
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        items = await _collect_walk(tree, mock_send)

        # /api should be found as a boundary by standard probe
        groups = [i for i in items if isinstance(i, BoundaryGroup)]
        assert any(g.prefix == "/api" for g in groups)
        # Lookahead should NOT have been called for /api (boundary found there)
        assert "/api" not in lookahead_prefixes

    @pytest.mark.asyncio
    async def test_lookahead_disabled_by_default(self):
        """Without lookahead=True, no lookahead probes should fire."""
        tree = ScanTree([_route("/users"), _route("/login")])
        tree._root.baselines["GET"] = build_baseline([
            _sig(status_code=404, content_type="text/html"),
        ])
        probe_count = 0

        async def mock_send(method, path, headers=None, body=None):
            nonlocal probe_count
            probe_count += 1
            if "/users/v1/" in path:
                return _sig(status_code=200, content_type="application/json",
                           content_length=25, word_count=3, line_count=1)
            return _sig(status_code=404, content_type="text/html")

        items = await _collect_walk(tree, mock_send)

        # No boundary groups for /users/v1 — lookahead disabled
        groups = [i for i in items if isinstance(i, BoundaryGroup)]
        assert not any(g.prefix == "/users/v1" for g in groups)
