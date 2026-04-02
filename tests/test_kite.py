"""Tests for kite.py: Route model."""

from __future__ import annotations

from apiscan.kite import Route


class TestRoute:
    def test_route_creation(self):
        r = Route(template_path="/api/users", method="GET")
        assert r.template_path == "/api/users"
        assert r.method == "GET"

    def test_route_equality(self):
        r1 = Route(template_path="/api/users", method="GET")
        r2 = Route(template_path="/api/users", method="GET")
        assert r1 == r2

    def test_route_different_methods(self):
        r1 = Route(template_path="/api/users", method="GET")
        r2 = Route(template_path="/api/users", method="POST")
        assert r1 != r2
