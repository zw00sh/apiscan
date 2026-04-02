"""Tests for CLI argument parsing and output modes."""

from __future__ import annotations

from apiscan.__main__ import _build_parser


class TestShortFlags:
    """Short flags should map to the same dest as their long counterparts."""

    def _parse(self, *args: str):
        parser = _build_parser()
        return parser.parse_args(["scan", *args])

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
