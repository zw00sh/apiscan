"""Tests for wordlist.py: flat wordlist loading."""

from __future__ import annotations

import tempfile
import os

from apiscan.wordlist import load_wordlist


class TestLoadWordlist:
    def test_basic(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/api/v1/users\n/api/v1/health\n/admin/dashboard\n")
            path = f.name
        try:
            routes = load_wordlist(path)
            assert len(routes) == 3
            assert routes[0].template_path == "/api/v1/users"
            assert routes[0].method == "GET"
            assert routes[0].path_crumbs == []
        finally:
            os.unlink(path)

    def test_deduplication(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("/api/users\n/api/users\n/api/health\n")
            path = f.name
        try:
            routes = load_wordlist(path)
            assert len(routes) == 2
        finally:
            os.unlink(path)

    def test_comments_and_blanks(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# this is a comment\n\n/api/users\n  \n/api/health\n")
            path = f.name
        try:
            routes = load_wordlist(path)
            assert len(routes) == 2
        finally:
            os.unlink(path)

    def test_missing_leading_slash(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("api/users\nadmin/dashboard\n")
            path = f.name
        try:
            routes = load_wordlist(path)
            assert routes[0].template_path == "/api/users"
            assert routes[1].template_path == "/admin/dashboard"
        finally:
            os.unlink(path)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("")
            path = f.name
        try:
            routes = load_wordlist(path)
            assert routes == []
        finally:
            os.unlink(path)
