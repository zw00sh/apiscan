"""Tests for kite.py: protobuf decoding, crumb generation, route rendering, safety filter."""

from __future__ import annotations

import base64
import json
import os
import re
from uuid import UUID

import pytest

from apiscan.kite import (
    DANGEROUS_KEYWORDS,
    VALID_METHODS,
    Crumb,
    FilterStats,
    Route,
    apply_safety_filter,
    generate_value,
    route_from_dict,
    route_to_dict,
    load_kite,
    render_body,
    render_headers,
    render_path,
    render_query,
)

KITES_DIR = os.path.join(os.path.dirname(__file__), "..", "kites")
SMALL_KITE = os.path.join(KITES_DIR, "routes-small.kite")
LARGE_KITE = os.path.join(KITES_DIR, "routes-large.kite")


# ---------------------------------------------------------------------------
# .kite file loading
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists(SMALL_KITE), reason="routes-small.kite not found")
class TestLoadSmallKite:
    def test_route_count(self):
        routes = load_kite(SMALL_KITE)
        assert 30_000 <= len(routes) <= 37_000

    def test_valid_methods_only(self):
        routes = load_kite(SMALL_KITE)
        methods = {r.method for r in routes}
        assert methods <= VALID_METHODS

    def test_no_empty_paths(self):
        routes = load_kite(SMALL_KITE)
        for r in routes[:1000]:
            assert r.template_path

    def test_all_paths_renderable(self):
        """Every rendered path must start with / and produce a valid URL suffix."""
        routes = load_kite(SMALL_KITE)
        for r in routes:
            path = render_path(r)
            assert path.startswith("/"), f"bad path: {path!r} from {r.template_path!r}"
            assert ":" not in path.split("/")[0], f"port-like path: {path!r}"


@pytest.mark.skipif(not os.path.exists(LARGE_KITE), reason="routes-large.kite not found")
class TestLoadLargeKite:
    def test_route_count(self):
        routes = load_kite(LARGE_KITE)
        assert 900_000 <= len(routes) <= 965_000

    def test_junk_methods_filtered(self):
        routes = load_kite(LARGE_KITE)
        methods = {r.method for r in routes}
        for junk in ("GETT", "POSY", "VENDOREXTENSIONS", "/HEALTH", "CREATE"):
            assert junk not in methods

    def test_all_paths_renderable(self):
        """Every rendered path must start with / and produce a valid URL suffix."""
        routes = load_kite(LARGE_KITE)
        for r in routes:
            path = render_path(r)
            assert path.startswith("/"), f"bad path: {path!r} from {r.template_path!r}"


# ---------------------------------------------------------------------------
# Crumb value generation
# ---------------------------------------------------------------------------

class TestCrumbGeneration:
    def test_uuid(self):
        c = Crumb("uuid", name="id")
        val = generate_value(c)
        UUID(val)  # raises if invalid

    def test_static(self):
        c = Crumb("static", name="key", fields={"v": "hello"})
        assert generate_value(c) == "hello"

    def test_int_fixed(self):
        c = Crumb("int", name="n", fields={"min": 0, "max": 100, "val": 42, "fixed": True})
        assert generate_value(c) == "42"

    def test_int_random(self):
        c = Crumb("int", name="n", fields={"min": 10, "max": 20, "val": 0, "fixed": False})
        for _ in range(50):
            val = int(generate_value(c))
            assert 10 <= val < 20

    def test_int_bad_bounds_defaults(self):
        c = Crumb("int", name="n", fields={"min": 100, "max": 50, "val": 0, "fixed": False})
        val = int(generate_value(c))
        assert 0 <= val < 1_000_000

    def test_bool_fixed(self):
        c = Crumb("bool", name="flag", fields={"fixed": True, "val": True})
        assert generate_value(c) == "true"

    def test_bool_random(self):
        c = Crumb("bool", name="flag", fields={"fixed": False, "val": False})
        vals = {generate_value(c) for _ in range(50)}
        assert vals == {"true", "false"}

    def test_float_fixed(self):
        c = Crumb("float", name="x", fields={"fixed": True, "val": 3.14})
        assert generate_value(c) == "3.14"

    def test_float_random(self):
        c = Crumb("float", name="x", fields={"fixed": False, "val": 0.0})
        val = float(generate_value(c))
        assert 0.0 <= val < 1.0

    def test_random_string(self):
        c = Crumb("random_string", name="s", fields={"charset": "abc", "length": 10})
        val = generate_value(c)
        assert len(val) == 10
        assert all(ch in "abc" for ch in val)

    def test_random_string_defaults(self):
        c = Crumb("random_string", name="s", fields={"charset": "", "length": 0})
        val = generate_value(c)
        assert len(val) == 8
        assert val.isalnum()

    def test_regex_string(self):
        c = Crumb("regex_string", name="r", fields={"regex": r"[a-z]{5}"})
        val = generate_value(c)
        assert re.match(r"^[a-z]{5}$", val)

    def test_regex_string_fallback(self):
        c = Crumb("regex_string", name="r", fields={"regex": r"(?P<invalid"})
        assert generate_value(c) == "1"

    def test_basic_auth(self):
        c = Crumb("basic_auth", name="Authorization", fields={
            "user": "admin", "password": "secret", "random": False,
        })
        val = generate_value(c)
        assert val.startswith("Basic ")
        decoded = base64.b64decode(val[6:]).decode()
        assert decoded == "admin:secret"

    def test_basic_auth_random(self):
        c = Crumb("basic_auth", name="Authorization", fields={
            "user": "", "password": "", "random": True,
        })
        val = generate_value(c)
        assert val.startswith("Basic ")
        decoded = base64.b64decode(val[6:]).decode()
        assert ":" in decoded
        user, pwd = decoded.split(":", 1)
        assert len(user) == 16
        assert len(pwd) == 16

    def test_object_json(self):
        c = Crumb("object", name="body", children=[
            Crumb("static", name="name", fields={"v": "alice"}),
            Crumb("int", name="age", fields={"min": 0, "max": 100, "val": 30, "fixed": True}),
        ])
        val = generate_value(c)
        parsed = json.loads(val)
        assert parsed["name"] == "alice"
        assert parsed["age"] == 30

    def test_array_json(self):
        c = Crumb("array", name="items", children=[
            Crumb("static", name="item", fields={"v": "foo"}),
        ])
        val = generate_value(c)
        parsed = json.loads(val)
        assert parsed == ["foo"]

    def test_string_crumb(self):
        c = Crumb("string_crumb", name="wrapped", children=[
            Crumb("int", name="n", fields={"min": 0, "max": 10, "val": 5, "fixed": True}),
        ])
        val = generate_value(c)
        assert val == '"5"'


# ---------------------------------------------------------------------------
# Route rendering
# ---------------------------------------------------------------------------

class TestRouteRendering:
    def test_render_path_with_crumbs(self):
        route = Route(
            template_path="/users/{userId}/posts/{postId}",
            method="GET",
            path_crumbs=[
                Crumb("uuid", name="userId"),
                Crumb("int", name="postId", fields={"min": 1, "max": 100, "val": 42, "fixed": True}),
            ],
        )
        path = render_path(route)
        parts = path.split("/")
        assert parts[0] == ""
        assert parts[1] == "users"
        UUID(parts[2])  # valid uuid
        assert parts[3] == "posts"
        assert parts[4] == "42"

    def test_render_path_default_value(self):
        route = Route(template_path="/items/{id}", method="GET")
        assert render_path(route) == "/items/42"

    def test_render_path_no_template(self):
        route = Route(template_path="/static/path", method="GET")
        assert render_path(route) == "/static/path"

    def test_render_query(self):
        route = Route(
            template_path="/search",
            method="GET",
            query_crumbs=[
                Crumb("static", name="q", fields={"v": "hello world"}),
                Crumb("int", name="page", fields={"min": 1, "max": 10, "val": 1, "fixed": True}),
            ],
        )
        qs = render_query(route)
        assert "q=hello+world" in qs or "q=hello%20world" in qs
        assert "page=1" in qs

    def test_render_body(self):
        route = Route(
            template_path="/create",
            method="POST",
            body_crumbs=[
                Crumb("static", name="title", fields={"v": "test"}),
            ],
        )
        body = render_body(route)
        assert body is not None
        parsed = json.loads(body)
        assert parsed["title"] == "test"

    def test_render_body_empty(self):
        route = Route(template_path="/get", method="GET")
        assert render_body(route) is None

    def test_render_headers(self):
        route = Route(
            template_path="/auth",
            method="GET",
            header_crumbs=[
                Crumb("basic_auth", name="Authorization", fields={
                    "user": "u", "password": "p", "random": False,
                }),
            ],
        )
        headers = render_headers(route)
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")


# ---------------------------------------------------------------------------
# Safety filter
# ---------------------------------------------------------------------------

class TestSafetyFilter:
    def _make_routes(self):
        return [
            Route(template_path="/api/users", method="GET"),
            Route(template_path="/api/users", method="POST"),
            Route(template_path="/api/users/{id}", method="DELETE"),
            Route(template_path="/api/users/{id}", method="PUT"),
            Route(template_path="/admin/shutdown", method="GET"),
            Route(template_path="/api/cache/clear", method="GET"),
            Route(template_path="/api/items/{id}/remove", method="GET"),
            Route(template_path="/api/health", method="GET"),
        ]

    def test_safe_mode_methods(self):
        routes = self._make_routes()
        filtered, stats = apply_safety_filter(routes)
        methods = {r.method for r in filtered}
        assert methods == {"GET"}

    def test_safe_mode_keywords(self):
        routes = self._make_routes()
        filtered, stats = apply_safety_filter(routes)
        paths = {r.template_path for r in filtered}
        assert "/admin/shutdown" not in paths
        assert "/api/cache/clear" not in paths
        assert "/api/items/{id}/remove" not in paths
        assert "/api/users" in paths
        assert "/api/health" in paths

    def test_safe_mode_stats(self):
        routes = self._make_routes()
        _, stats = apply_safety_filter(routes)
        assert stats.total == 8
        assert stats.method_filtered == 3  # POST, DELETE, PUT
        assert stats.keyword_filtered == 3  # shutdown, clear, remove
        assert stats.kept == 2  # /api/users GET, /api/health GET

    def test_unsafe_mode_all_preserved(self):
        routes = self._make_routes()
        filtered, stats = apply_safety_filter(routes, unsafe_methods=True, unsafe_keywords=True)
        assert len(filtered) == len(routes)
        assert stats.method_filtered == 0
        assert stats.keyword_filtered == 0


# ---------------------------------------------------------------------------
# Route serialization roundtrip
# ---------------------------------------------------------------------------

class TestRouteSerialization:
    def test_crumb_roundtrip(self):
        crumbs = [
            Crumb("uuid"),
            Crumb("static", name="q", fields={"v": "test"}),
            Crumb("int", name="id", fields={"min": 1, "max": 100}),
            Crumb("bool", name="active"),
            Crumb("regex_string", name="pat", fields={"r": "[a-z]+"}),
        ]
        route = Route(
            template_path="/api/{id}",
            method="GET",
            path_crumbs=[crumbs[2]],
            query_crumbs=[crumbs[1], crumbs[3]],
            header_crumbs=[crumbs[4]],
        )
        d = route_to_dict(route)
        restored = route_from_dict(d)
        assert restored.template_path == route.template_path
        assert restored.method == route.method
        assert len(restored.path_crumbs) == 1
        assert restored.path_crumbs[0].kind == "int"
        assert restored.path_crumbs[0].name == "id"
        assert restored.path_crumbs[0].fields == {"min": 1, "max": 100}
        assert len(restored.query_crumbs) == 2
        assert len(restored.header_crumbs) == 1

    def test_nested_crumb_roundtrip(self):
        child = Crumb("int", name="age", fields={"min": 0, "max": 150})
        parent = Crumb("object", name="user", children=[child])
        route = Route(
            template_path="/api/users",
            method="POST",
            body_crumbs=[parent],
        )
        d = route_to_dict(route)
        restored = route_from_dict(d)
        assert len(restored.body_crumbs) == 1
        obj = restored.body_crumbs[0]
        assert obj.kind == "object"
        assert len(obj.children) == 1
        assert obj.children[0].kind == "int"
        assert obj.children[0].name == "age"

    def test_empty_crumbs_omitted(self):
        route = Route(template_path="/health", method="GET")
        d = route_to_dict(route)
        assert "pc" not in d
        assert "qc" not in d
        assert "bc" not in d
        assert "hc" not in d
        assert d == {"p": "/health", "m": "GET"}
        restored = route_from_dict(d)
        assert restored.path_crumbs == []
        assert restored.query_crumbs == []

    def test_source_api_url_omitted(self):
        route = Route(template_path="/api", method="GET", source_api_url="http://example.com/swagger.json")
        d = route_to_dict(route)
        assert "source_api_url" not in d
        restored = route_from_dict(d)
        assert restored.source_api_url == ""

    def test_content_types_roundtrip(self):
        route = Route(template_path="/api", method="POST", content_types=["application/json", "text/xml"])
        d = route_to_dict(route)
        assert d["ct"] == ["application/json", "text/xml"]
        restored = route_from_dict(d)
        assert restored.content_types == ["application/json", "text/xml"]
