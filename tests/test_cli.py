"""Tests for CLI argument parsing and output modes."""

from __future__ import annotations

import pytest

from apiscan.__main__ import _build_parser


class TestShortFlags:
    """Short flags should map to the same dest as their long counterparts."""

    def _parse(self, *args: str):
        parser = _build_parser()
        return parser.parse_args([*args])

    def test_url(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt")
        assert ns.url == "http://x"

    def test_wordlist(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt")
        assert ns.wordlist == "/tmp/wl.txt"

    def test_methods(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt", "-m", "GET,PUT")
        assert ns.methods == "GET,PUT"

    def test_concurrency(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt", "-c", "20")
        assert ns.concurrency == 20

    def test_rate(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt", "-r", "50")
        assert ns.rate == 50.0

    def test_timeout(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt", "-t", "5")
        assert ns.timeout == 5.0

    def test_header(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt", "-H", "Auth:Bearer tok")
        assert ns.header == ["Auth:Bearer tok"]

    def test_output(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt", "-o", "/tmp/out.csv")
        assert ns.output == "/tmp/out.csv"

    def test_verbose(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt", "-v")
        assert ns.verbose is True

    def test_quiet(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt", "-q")
        assert ns.quiet is True

    def test_combined(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/wl.txt", "-c", "5", "-r", "10", "-t", "3", "-q")
        assert ns.url == "http://x"
        assert ns.concurrency == 5
        assert ns.rate == 10.0
        assert ns.timeout == 3.0
        assert ns.quiet is True

    def test_include_exclude(self):
        ns = self._parse("-u", "http://x", "-i", "200,301", "-e", "500")
        assert ns.include == "200,301"
        assert ns.exclude == "500"


class TestWordlistSelection:
    """--short, --long, and -w are mutually exclusive; default is 10k."""

    def _parse(self, *args: str):
        parser = _build_parser()
        return parser.parse_args([*args])

    def test_default_no_wordlist(self):
        ns = self._parse("-u", "http://x")
        assert ns.wordlist is None
        assert ns.short is False
        assert getattr(ns, "long") is False

    def test_short_flag(self):
        ns = self._parse("-u", "http://x", "--short")
        assert ns.short is True
        assert ns.wordlist is None

    def test_long_flag(self):
        ns = self._parse("-u", "http://x", "--long")
        assert getattr(ns, "long") is True
        assert ns.wordlist is None

    def test_custom_wordlist(self):
        ns = self._parse("-u", "http://x", "-w", "/tmp/custom.txt")
        assert ns.wordlist == "/tmp/custom.txt"
        assert ns.short is False

    def test_short_and_wordlist_mutex(self):
        with pytest.raises(SystemExit):
            self._parse("-u", "http://x", "--short", "-w", "/tmp/wl.txt")

    def test_short_and_long_mutex(self):
        with pytest.raises(SystemExit):
            self._parse("-u", "http://x", "--short", "--long")


class TestJsonOutput:
    def _parse(self, *args: str):
        parser = _build_parser()
        return parser.parse_args([*args])

    def test_json_flag(self):
        ns = self._parse("-u", "http://x", "-j")
        assert ns.json is True

    def test_json_long_flag(self):
        ns = self._parse("-u", "http://x", "--json")
        assert ns.json is True

    def test_json_and_quiet_mutex(self):
        with pytest.raises(SystemExit):
            self._parse("-u", "http://x", "-j", "-q")


class TestRecursionFlags:
    def _parse(self, *args: str):
        parser = _build_parser()
        return parser.parse_args([*args])

    def test_recurse_flag(self):
        ns = self._parse("-u", "http://x", "--recurse")
        assert ns.recurse is True
        assert ns.recurse_all is False

    def test_recurse_all_flag(self):
        ns = self._parse("-u", "http://x", "--recurse-all")
        assert ns.recurse_all is True
        assert ns.recurse is False

    def test_recurse_and_recurse_all_mutex(self):
        with pytest.raises(SystemExit):
            self._parse("-u", "http://x", "--recurse", "--recurse-all")

    def test_neither_recurse(self):
        ns = self._parse("-u", "http://x")
        assert ns.recurse is False
        assert ns.recurse_all is False


class TestLookaheadFlags:
    def _parse(self, *args: str):
        parser = _build_parser()
        return parser.parse_args([*args])

    def test_lookahead_default_enabled(self):
        ns = self._parse("-u", "http://x")
        assert ns.no_lookahead is False

    def test_no_lookahead_disables(self):
        ns = self._parse("-u", "http://x", "--no-lookahead")
        assert ns.no_lookahead is True
